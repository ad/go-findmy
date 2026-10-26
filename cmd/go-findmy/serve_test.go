package main

import (
	"context"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/ad/go-findmy/internal/findmy"
	"github.com/ad/go-findmy/internal/ha"
	"github.com/ad/go-findmy/internal/icloud"
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

func (staticAnisette) Resync() error { return nil }

func openAccount(t *testing.T, state map[string]any) *icloud.Account {
	t.Helper()
	dir := t.TempDir()
	writeJSON(t, filepath.Join(dir, "account.json"), state)
	acct, err := icloud.Open(dir, staticAnisette{})
	if err != nil {
		t.Fatal(err)
	}
	return acct
}

type pollFixture struct {
	s        *service
	pub      recorder
	keysDir  string
	id       string
	requests int
	status   int
}

func newPollFixture(t *testing.T, account map[string]any) *pollFixture {
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

	acct := openAccount(t, account)
	f := findmy.NewFetcher(staticAnisette{}, acct, acct.Relogin)
	f.URL, f.HTTP = srv.URL, srv.Client()
	fx.s = newService(fx.keysDir, t.TempDir(), f, acct, fx.pub)
	return fx
}

func writeJSON(t *testing.T, path string, v any) {
	t.Helper()
	data, _ := json.Marshal(v)
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}
}

var signedIn = map[string]any{"dsid": "1", "tokens": map[string]string{"searchPartyToken": "tok"}}

func TestPollPublishesTrackerAndLocation(t *testing.T) {
	fx := newPollFixture(t, signedIn)
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

func TestPollStopsFetchingAfterRejectedToken(t *testing.T) {
	fx := newPollFixture(t, signedIn)
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
}

func TestPollSendsNothingWhileAccountNeedsLogin(t *testing.T) {
	fx := newPollFixture(t, map[string]any{"needLogin": "Apple refused the relogin"})
	fx.s.poll(context.Background(), time.Now())
	if fx.requests != 0 || fx.pub["findmy/login_required"] != "ON" {
		t.Errorf("%d requests, login_required %q; want 0 and ON", fx.requests, fx.pub["findmy/login_required"])
	}
}

func TestIngressLoginDoesNotProvisionDuringCooldown(t *testing.T) {
	until := time.Now().Add(time.Hour).UTC()
	acct := openAccount(t, map[string]any{"cooldownUntil": until, "needLogin": "the Apple ID is locked, unlock it at iforgot.apple.com"})
	provisioned := 0
	l := &ingressLogin{acct: acct, provision: func() (bool, error) { provisioned++; return true, nil }}

	_, err := l.SignIn(context.Background(), "me@example.com", "pw")
	if !errors.Is(err, icloud.ErrCooldown) || provisioned != 0 {
		t.Errorf("err %v, %d provisions; want ErrCooldown and none", err, provisioned)
	}
	if !strings.Contains(err.Error(), until.Format(time.RFC3339)) {
		t.Errorf("error %q lacks the cooldown end", err)
	}
}

func TestWaitHonoursLastPollAcrossRestarts(t *testing.T) {
	fx := newPollFixture(t, signedIn)
	now := time.Date(2026, 10, 26, 12, 0, 0, 0, time.UTC)
	if d := fx.s.wait(15*time.Minute, now); d != 0 {
		t.Errorf("first start waits %v, want 0", d)
	}
	fx.s.poll(context.Background(), now.Add(-5*time.Minute))

	restarted := newService(fx.keysDir, fx.s.dataDir, fx.s.fetcher, fx.s.acct, fx.pub)
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
