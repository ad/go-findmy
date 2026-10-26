package ha

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/ad/go-findmy/internal/findmy"
)

type published map[string]map[string]any

func (p published) Publish(topic string, payload []byte) error {
	var v map[string]any
	if err := json.Unmarshal(payload, &v); err != nil {
		v = map[string]any{"raw": string(payload)}
	}
	p[topic] = v
	return nil
}

func TestIDKeepsOnlyTopicSafeCharacters(t *testing.T) {
	for in, want := range map[string]string{
		"00000000-0000-0000-0000-000000000001": "00000000-0000-0000-0000-000000000001",
		"ab+/cd==":                             "ab__cd__",
		"../x y#":                              "___x_y_",
	} {
		if got := ID(in); got != want {
			t.Errorf("ID(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestAnnounceTagIsLocationOnlyTrackerWithAvailability(t *testing.T) {
	p := published{}
	if err := AnnounceTag(p, Tag{ID: "abc", Name: "Keys", Model: "AirTag1,1"}); err != nil {
		t.Fatal(err)
	}
	cfg, ok := p["homeassistant/device_tracker/findmy/abc/config"]
	if !ok {
		t.Fatalf("no discovery config, got topics %v", p)
	}
	for k, want := range map[string]any{
		"unique_id":             "findmy_abc",
		"json_attributes_topic": "findmy/abc/attributes",
		"availability_topic":    "findmy/availability",
		"source_type":           "gps",
	} {
		if cfg[k] != want {
			t.Errorf("%s = %v, want %v", k, cfg[k], want)
		}
	}
	if _, ok := cfg["state_topic"]; ok {
		t.Error("state_topic set: HA would take the state from it instead of the coordinates")
	}
	dev, _ := cfg["device"].(map[string]any)
	if dev["name"] != "Keys" || dev["model"] != "AirTag1,1" {
		t.Errorf("device %v", dev)
	}
}

func TestPublishLocationSetsHACoordinateAttributes(t *testing.T) {
	p := published{}
	r := findmy.Report{Time: time.Date(2026, 10, 26, 11, 0, 0, 0, time.UTC), Latitude: 52.5, Longitude: 13.4, Accuracy: 25}
	if err := PublishLocation(p, "abc", r); err != nil {
		t.Fatal(err)
	}
	got := p["findmy/abc/attributes"]
	want := map[string]any{"latitude": 52.5, "longitude": 13.4, "gps_accuracy": 25.0, "last_seen": "2026-10-26T11:00:00Z"}
	for k, v := range want {
		if got[k] != v {
			t.Errorf("%s = %v, want %v", k, got[k], v)
		}
	}
}

func TestLoginRequiredIsAProblemSensor(t *testing.T) {
	p := published{}
	if err := AnnounceLoginSensor(p); err != nil {
		t.Fatal(err)
	}
	if err := PublishLoginRequired(p, true); err != nil {
		t.Fatal(err)
	}
	cfg := p["homeassistant/binary_sensor/findmy/login_required/config"]
	if cfg["device_class"] != "problem" || cfg["state_topic"] != "findmy/login_required" {
		t.Errorf("config %v", cfg)
	}
	if p["findmy/login_required"]["raw"] != "ON" {
		t.Errorf("state %v, want ON", p["findmy/login_required"])
	}
}
