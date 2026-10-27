package ha

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/gorilla/websocket"
)

// SupervisorWebsocket is the Home Assistant websocket API behind the Supervisor proxy, open to
// add-ons that declare homeassistant_api.
const SupervisorWebsocket = "ws://supervisor/core/websocket"

// Entity is what Home Assistant made of a tag announced over MQTT discovery.
type Entity struct {
	EntityID string
	DeviceID string
}

// Registry reads the entity registry of Home Assistant.
type Registry struct {
	URL   string
	Token string
}

type message struct {
	ID      int    `json:"id"`
	Type    string `json:"type"`
	Success bool   `json:"success"`
	Result  []struct {
		EntityID string `json:"entity_id"`
		DeviceID string `json:"device_id"`
		UniqueID string `json:"unique_id"`
	} `json:"result"`
}

// Trackers returns the entities of the announced tags, by tag ID.
func (r Registry) Trackers(ctx context.Context) (map[string]Entity, error) {
	conn, _, err := websocket.DefaultDialer.DialContext(ctx, r.URL, nil)
	if err != nil {
		return nil, fmt.Errorf("home assistant: %w", err)
	}
	defer conn.Close()
	if deadline, ok := ctx.Deadline(); ok {
		conn.SetReadDeadline(deadline)
		conn.SetWriteDeadline(deadline)
	}

	var msg message
	if err := conn.ReadJSON(&msg); err != nil {
		return nil, fmt.Errorf("home assistant: %w", err)
	}
	if msg.Type != "auth_required" {
		return nil, fmt.Errorf("home assistant: unexpected %q message instead of auth_required", msg.Type)
	}
	if err := conn.WriteJSON(map[string]any{"type": "auth", "access_token": r.Token}); err != nil {
		return nil, fmt.Errorf("home assistant: %w", err)
	}
	msg = message{}
	if err := conn.ReadJSON(&msg); err != nil {
		return nil, fmt.Errorf("home assistant: %w", err)
	}
	if msg.Type != "auth_ok" {
		return nil, errors.New("home assistant: the token was refused")
	}

	if err := conn.WriteJSON(map[string]any{"id": 1, "type": "config/entity_registry/list"}); err != nil {
		return nil, fmt.Errorf("home assistant: %w", err)
	}
	for {
		msg = message{}
		if err := conn.ReadJSON(&msg); err != nil {
			return nil, fmt.Errorf("home assistant: %w", err)
		}
		if msg.Type != "result" || msg.ID != 1 {
			continue
		}
		if !msg.Success {
			return nil, errors.New("home assistant: the entity registry request failed")
		}
		out := map[string]Entity{}
		for _, e := range msg.Result {
			if id, ok := strings.CutPrefix(e.UniqueID, base+"_"); ok && strings.HasPrefix(e.EntityID, "device_tracker.") {
				out[id] = Entity{EntityID: e.EntityID, DeviceID: e.DeviceID}
			}
		}
		return out, nil
	}
}
