package ha

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/gorilla/websocket"
)

// fakeHA speaks the part of the Home Assistant websocket API that Registry uses.
func fakeHA(t *testing.T, token string) string {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		conn, err := (&websocket.Upgrader{}).Upgrade(w, r, nil)
		if err != nil {
			return
		}
		defer conn.Close()
		conn.WriteJSON(map[string]any{"type": "auth_required"})
		var auth struct {
			Type        string `json:"type"`
			AccessToken string `json:"access_token"`
		}
		if err := conn.ReadJSON(&auth); err != nil {
			return
		}
		if auth.Type != "auth" || auth.AccessToken != token {
			conn.WriteJSON(map[string]any{"type": "auth_invalid"})
			return
		}
		conn.WriteJSON(map[string]any{"type": "auth_ok"})
		var req struct {
			ID   int
			Type string
		}
		if err := conn.ReadJSON(&req); err != nil || req.Type != "config/entity_registry/list" {
			return
		}
		conn.WriteJSON(map[string]any{"id": req.ID, "type": "result", "success": true, "result": []map[string]any{
			{"entity_id": "device_tracker.keys", "unique_id": "findmy_abc", "device_id": "dev1"},
			{"entity_id": "binary_sensor.find_my_login_required", "unique_id": "findmy_login_required", "device_id": "dev2"},
			{"entity_id": "device_tracker.phone", "unique_id": "other_xyz", "device_id": "dev3"},
		}})
	}))
	t.Cleanup(srv.Close)
	return "ws" + strings.TrimPrefix(srv.URL, "http")
}

func TestTrackersReturnsOnlyTheEntitiesOfAnnouncedTags(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	got, err := Registry{URL: fakeHA(t, "secret"), Token: "secret"}.Trackers(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 || got["abc"] != (Entity{EntityID: "device_tracker.keys", DeviceID: "dev1"}) {
		t.Errorf("got %v, want only abc -> device_tracker.keys on dev1", got)
	}
}

func TestTrackersFailsOnARefusedToken(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if _, err := (Registry{URL: fakeHA(t, "secret"), Token: "wrong"}).Trackers(ctx); err == nil {
		t.Error("a refused token gave no error")
	}
}
