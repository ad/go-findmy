package main

import (
	"context"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/ad/go-findmy/internal/findmy"
	"github.com/ad/go-findmy/internal/ha"
)

type recorder map[string]string

func (r recorder) Publish(topic string, payload []byte) error {
	r[topic] = string(payload)
	return nil
}

type staticAnisette struct{}

func (staticAnisette) Headers() (map[string]string, error) {
	return map[string]string{"X-Apple-I-MD": "otp", "X-Apple-I-MD-M": "machine"}, nil
}

type pollFixture struct {
	s        *service
	pub      recorder
	keysDir  string
	id       string
	requests int
	status   int
}

func newPollFixture(t *testing.T) *pollFixture {
	t.Helper()
	var vec struct {
		Private string
		ID      string
		Reports []struct {
			Payload  string
			Latitude float64
		}
	}
	raw, err := os.ReadFile("../../internal/findmy/testdata/findmypy-22e4879-reports.json")
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(raw, &vec); err != nil {
		t.Fatal(err)
	}
	priv, _ := hex.DecodeString(vec.Private)

	fx := &pollFixture{pub: recorder{}, keysDir: t.TempDir(), id: vec.ID, status: http.StatusOK}
	writeJSON(t, filepath.Join(fx.keysDir, "tag.keys"), findmy.KeyFile{PrivateKey: base64.StdEncoding.EncodeToString(priv)})
	writeJSON(t, filepath.Join(fx.keysDir, authFile), auth{DSID: "1", SearchPartyToken: "old"})

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fx.requests++
		if fx.status != http.StatusOK {
			w.WriteHeader(fx.status)
			return
		}
		body, _ := json.Marshal(map[string]any{"acsnLocations": map[string]any{
			"statusCode":      "200",
			"locationPayload": []map[string]any{{"id": vec.ID, "locationInfo": []string{vec.Reports[0].Payload}}},
		}})
		w.Write(body)
	}))
	t.Cleanup(srv.Close)

	f := findmy.NewFetcher(staticAnisette{}, nil, func(context.Context) error { return io.EOF })
	f.URL, f.HTTP = srv.URL, srv.Client()
	fx.s = newService(fx.keysDir, t.TempDir(), f, fx.pub)
	return fx
}

func writeJSON(t *testing.T, path string, v any) {
	t.Helper()
	data, _ := json.Marshal(v)
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}
}

func TestPollPublishesTrackerAndLocation(t *testing.T) {
	fx := newPollFixture(t)
	fx.s.poll(context.Background(), time.Date(2026, 10, 26, 12, 0, 0, 0, time.UTC))

	id := ha.ID(fx.id)
	if _, ok := fx.pub["homeassistant/device_tracker/findmy/"+id+"/config"]; !ok {
		t.Errorf("tracker not announced; topics %v", fx.pub)
	}
	var attrs map[string]any
	json.Unmarshal([]byte(fx.pub["findmy/"+id+"/attributes"]), &attrs)
	if attrs["latitude"] != 55.7512345 {
		t.Errorf("attributes %v, want latitude 55.7512345", attrs)
	}
	if fx.pub["findmy/login_required"] != "OFF" {
		t.Errorf("login_required %q, want OFF", fx.pub["findmy/login_required"])
	}
	st := fx.s.Status()
	if len(st.Tags) != 1 || st.Tags[0].Report == nil || st.LastPoll.IsZero() {
		t.Errorf("status %+v", st)
	}
}

func TestPollStopsFetchingAfterRejectedTokenUntilItChanges(t *testing.T) {
	fx := newPollFixture(t)
	fx.status = http.StatusUnauthorized
	ctx, now := context.Background(), time.Now()

	fx.s.poll(ctx, now)
	if fx.pub["findmy/login_required"] != "ON" || !fx.s.Status().LoginRequired {
		t.Fatalf("login_required %q, status %+v", fx.pub["findmy/login_required"], fx.s.Status())
	}
	sent := fx.requests

	fx.s.poll(ctx, now)
	if fx.requests != sent {
		t.Errorf("%d more requests with the rejected token", fx.requests-sent)
	}

	fx.status = http.StatusOK
	writeJSON(t, filepath.Join(fx.keysDir, authFile), auth{DSID: "1", SearchPartyToken: "new"})
	fx.s.poll(ctx, now)
	if fx.requests == sent || fx.pub["findmy/login_required"] != "OFF" {
		t.Errorf("new token: %d requests, login_required %q", fx.requests-sent, fx.pub["findmy/login_required"])
	}
}

func TestWaitHonoursLastPollAcrossRestarts(t *testing.T) {
	fx := newPollFixture(t)
	now := time.Date(2026, 10, 26, 12, 0, 0, 0, time.UTC)
	if d := fx.s.wait(15*time.Minute, now); d != 0 {
		t.Errorf("first start waits %v, want 0", d)
	}
	fx.s.poll(context.Background(), now.Add(-5*time.Minute))

	restarted := newService(fx.keysDir, fx.s.dataDir, fx.s.fetcher, fx.pub)
	if d := restarted.wait(15*time.Minute, now); d != 10*time.Minute {
		t.Errorf("wait %v after restart, want 10m", d)
	}
}

func TestPollIntervalHasA15MinuteFloor(t *testing.T) {
	for minutes, want := range map[int]time.Duration{0: 15 * time.Minute, 5: 15 * time.Minute, 30: 30 * time.Minute} {
		if got := pollInterval(minutes); got != want {
			t.Errorf("pollInterval(%d) = %v, want %v", minutes, got, want)
		}
	}
}
