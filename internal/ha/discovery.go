package ha

import (
	"encoding/json"
	"errors"
	"strings"
	"time"

	"github.com/ad/go-findmy/internal/findmy"
)

const (
	discovery          = "homeassistant"
	base               = "findmy"
	AvailabilityTopic  = base + "/availability"
	loginRequiredTopic = base + "/login_required"
)

type Publisher interface {
	Publish(topic string, payload []byte) error
}

type Tag struct {
	ID    string
	Name  string
	Model string
}

func ID(s string) string {
	return strings.Map(func(r rune) rune {
		if r == '-' || r == '_' || r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' {
			return r
		}
		return '_'
	}, s)
}

func AnnounceTag(p Publisher, t Tag) error {
	return publishJSON(p, discovery+"/device_tracker/"+base+"/"+t.ID+"/config", map[string]any{
		"name":                  nil,
		"unique_id":             base + "_" + t.ID,
		"json_attributes_topic": base + "/" + t.ID + "/attributes",
		"availability_topic":    AvailabilityTopic,
		"source_type":           "gps",
		"device": map[string]any{
			"identifiers":  []string{base + "_" + t.ID},
			"name":         t.Name,
			"manufacturer": "Apple",
			"model":        t.Model,
		},
	})
}

// RemoveTag clears the retained messages of a tag, which makes Home Assistant drop its device.
func RemoveTag(p Publisher, id string) error {
	return errors.Join(
		p.Publish(discovery+"/device_tracker/"+base+"/"+id+"/config", nil),
		p.Publish(base+"/"+id+"/attributes", nil),
	)
}

func PublishLocation(p Publisher, id string, r findmy.Report) error {
	return publishJSON(p, base+"/"+id+"/attributes", map[string]any{
		"latitude":     r.Latitude,
		"longitude":    r.Longitude,
		"gps_accuracy": r.Accuracy,
		"last_seen":    r.Time.UTC().Format(time.RFC3339),
	})
}

func AnnounceLoginSensor(p Publisher) error {
	return publishJSON(p, discovery+"/binary_sensor/"+base+"/login_required/config", map[string]any{
		"name":               "Login required",
		"unique_id":          base + "_login_required",
		"state_topic":        loginRequiredTopic,
		"device_class":       "problem",
		"availability_topic": AvailabilityTopic,
		"device": map[string]any{
			"identifiers": []string{base + "_addon"},
			"name":        "Find My",
		},
	})
}

func PublishLoginRequired(p Publisher, required bool) error {
	state := "OFF"
	if required {
		state = "ON"
	}
	return p.Publish(loginRequiredTopic, []byte(state))
}

func publishJSON(p Publisher, topic string, v any) error {
	data, err := json.Marshal(v)
	if err != nil {
		return err
	}
	return p.Publish(topic, data)
}
