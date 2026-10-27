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
	if !strings.Contains(fx.s.Status().NeedLogin, "Apple refused the relogin") {
		t.Errorf("status does not say why: %+v", fx.s.Status())
	}
}

func TestPollSendsNothingDuringCooldown(t *testing.T) {
	fx := newPollFixture(t, map[string]any{"dsid": "1", "tokens": map[string]string{"searchPartyToken": "tok"}, "cooldownUntil": time.Now().Add(time.Hour)})
	fx.s.poll(context.Background(), time.Now())
	if fx.requests != 0 || !strings.Contains(fx.s.Status().LastError, "cooldown") {
		t.Errorf("%d requests, last error %q; want 0 and the cooldown", fx.requests, fx.s.Status().LastError)
	}
}

func TestCooldownAloneDoesNotAskForLogin(t *testing.T) {
	until := time.Now().Add(time.Hour)
	fx := newPollFixture(t, map[string]any{"dsid": "1", "tokens": map[string]string{"searchPartyToken": "tok"}, "cooldownUntil": until})
	fx.s.poll(context.Background(), time.Now())
	if fx.pub["findmy/login_required"] != "OFF" {
		t.Errorf("login_required %q during a cooldown with a usable token, want OFF", fx.pub["findmy/login_required"])
	}

	fx = newPollFixture(t, map[string]any{"cooldownUntil": until, "needLogin": "Apple rejected the Apple ID or password"})
	fx.s.poll(context.Background(), time.Now())
	if fx.pub["findmy/login_required"] != "ON" {
		t.Errorf("login_required %q during a cooldown after a refusal, want ON", fx.pub["findmy/login_required"])
	}
}

func TestSignInClearsLoginRequiredAtOnce(t *testing.T) {
	fx := newPollFixture(t, signedIn)
	fx.s.setLoginRequired(true)
	fx.s.signedIn()
	if fx.s.Status().LoginRequired || fx.pub["findmy/login_required"] != "OFF" {
		t.Errorf("status %+v, login_required %q", fx.s.Status(), fx.pub["findmy/login_required"])
	}
}

func TestIngressLoginDoesNotProvisionDuringCooldown(t *testing.T) {
	until := time.Now().Add(time.Hour).UTC()
	acct := openAccount(t, map[string]any{"cooldownUntil": until, "needLogin": "the Apple ID is locked, unlock it at iforgot.apple.com"})
	provisioned := 0
	l := &ingressLogin{acct: acct, provision: func() (bool, error) { provisioned++; return true, nil }}

	_, err := l.SignIn(context.Background(), "me@example.com", "pw", false)
	if !errors.Is(err, icloud.ErrCooldown) || provisioned != 0 {
		t.Errorf("err %v, %d provisions; want ErrCooldown and none", err, provisioned)
	}
	if !strings.Contains(err.Error(), until.Format(time.RFC3339)) {
		t.Errorf("error %q lacks the cooldown end", err)
	}
}

func TestFailedProvisionCoolsDownTheNextSignIn(t *testing.T) {
	acct := openAccount(t, map[string]any{})
	provisioned := 0
	l := &ingressLogin{acct: acct, provision: func() (bool, error) { provisioned++; return false, errors.New("anisette: POST /provision: 500") }}

	if _, err := l.SignIn(context.Background(), "me@example.com", "pw", false); err == nil {
		t.Fatal("sign-in with a failed provision succeeded")
	}
	if _, err := l.SignIn(context.Background(), "me@example.com", "pw", false); !errors.Is(err, icloud.ErrCooldown) || provisioned != 1 {
		t.Errorf("second sign-in err %v, %d provisions; want ErrCooldown and 1", err, provisioned)
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

func TestDeleteRemovesKeysAndClearsTheDevice(t *testing.T) {
	fx := newPollFixture(t, signedIn)
	fx.s.poll(context.Background(), time.Date(2026, 10, 26, 12, 0, 0, 0, time.UTC))
	id := ha.ID(fx.id)

	name, err := fx.s.Delete("tag.keys")
	if err != nil || name == "" {
		t.Fatalf("Delete = %q, %v", name, err)
	}
	if _, err := os.Stat(filepath.Join(fx.keysDir, "tag.keys")); !os.IsNotExist(err) {
		t.Errorf("key file is still there: %v", err)
	}
	for _, topic := range []string{"homeassistant/device_tracker/findmy/" + id + "/config", "findmy/" + id + "/attributes"} {
		if payload, ok := fx.pub[topic]; !ok || payload != "" {
			t.Errorf("%s = %q (published %v), want an empty retained message", topic, payload, ok)
		}
	}
	if st := fx.s.Status(); len(st.Tags) != 0 {
		t.Errorf("status still lists %+v", st.Tags)
	}
}

func TestDeleteTouchesOnlyListedTags(t *testing.T) {
	fx := newPollFixture(t, signedIn)
	writeJSON(t, filepath.Join(fx.keysDir, "auth.json"), map[string]string{"password": "x"})
	for _, file := range []string{"auth.json", "../tag.keys", "missing.keys"} {
		if _, err := fx.s.Delete(file); err == nil {
			t.Errorf("Delete(%q) succeeded", file)
		}
	}
	for _, file := range []string{"auth.json", "tag.keys"} {
		if _, err := os.Stat(filepath.Join(fx.keysDir, file)); err != nil {
			t.Errorf("%s: %v", file, err)
		}
	}
}

func TestPollDoesNotBringBackADeletedTag(t *testing.T) {
	fx := newPollFixture(t, signedIn)
	fx.s.poll(context.Background(), time.Date(2026, 10, 26, 12, 0, 0, 0, time.UTC))
	fx.s.Delete("tag.keys")
	fx.s.poll(context.Background(), time.Date(2026, 10, 26, 12, 15, 0, 0, time.UTC))
	if payload := fx.pub["homeassistant/device_tracker/findmy/"+ha.ID(fx.id)+"/config"]; payload != "" {
		t.Errorf("the next poll announced the tag again: %s", payload)
	}
	if st := fx.s.Status(); len(st.Tags) != 0 {
		t.Errorf("status lists %+v", st.Tags)
	}
}

func TestLocationPrefersTheOptionThenTZ(t *testing.T) {
	for _, c := range []struct{ option, env, want string }{
		{"Europe/Moscow", "Asia/Tokyo", "Europe/Moscow"},
		{"", "Asia/Tokyo", "Asia/Tokyo"},
		{"", "nonsense", "UTC"},
		{"", "", "UTC"},
	} {
		if got := location(c.option, c.env).String(); got != c.want {
			t.Errorf("location(%q, %q) = %s, want %s", c.option, c.env, got, c.want)
		}
	}
}

func deviceName(t *testing.T, fx *pollFixture) string {
	t.Helper()
	var cfg struct{ Device struct{ Name string } }
	if err := json.Unmarshal([]byte(fx.pub["homeassistant/device_tracker/findmy/"+ha.ID(fx.id)+"/config"]), &cfg); err != nil {
		t.Fatal(err)
	}
	return cfg.Device.Name
}

func TestRenameChangesTheDeviceAndSurvivesRestartsAndPolls(t *testing.T) {
	fx := newPollFixture(t, signedIn)
	fx.s.poll(context.Background(), time.Date(2026, 10, 26, 12, 0, 0, 0, time.UTC))
	if got := deviceName(t, fx); got != "tag" {
		t.Fatalf("default device name %q, want tag", got)
	}

	if err := fx.s.Rename("tag.keys", "  My keys "); err != nil {
		t.Fatal(err)
	}
	if got := deviceName(t, fx); got != "My keys" {
		t.Errorf("device name %q, want My keys", got)
	}
	if st := fx.s.Status(); len(st.Tags) != 1 || st.Tags[0].Name != "My keys" {
		t.Errorf("status %+v", st.Tags)
	}

	fx.s.poll(context.Background(), time.Date(2026, 10, 26, 12, 15, 0, 0, time.UTC))
	if got := deviceName(t, fx); got != "My keys" {
		t.Errorf("a poll reset the name to %q", got)
	}

	restarted := newService(fx.keysDir, fx.s.dataDir, fx.s.fetcher, fx.s.acct, fx.pub)
	restarted.poll(context.Background(), time.Date(2026, 10, 26, 13, 0, 0, 0, time.UTC))
	if got := deviceName(t, fx); got != "My keys" {
		t.Errorf("after a restart the name is %q", got)
	}

	if err := fx.s.Rename("tag.keys", ""); err != nil {
		t.Fatal(err)
	}
	if got := deviceName(t, fx); got != "tag" {
		t.Errorf("empty name gave %q, want the default tag", got)
	}
}

func TestRenameRejectsUnknownTagsAndLongNames(t *testing.T) {
	fx := newPollFixture(t, signedIn)
	if err := fx.s.Rename("missing.keys", "x"); err == nil {
		t.Error("renamed a tag that does not exist")
	}
	if err := fx.s.Rename("tag.keys", strings.Repeat("я", maxNameLen+1)); err == nil {
		t.Error("accepted a name over the limit")
	}
	if err := fx.s.Rename("tag.keys", strings.Repeat("я", maxNameLen)); err != nil {
		t.Errorf("rejected a name at the limit: %v", err)
	}
}

func TestDeleteForgetsTheName(t *testing.T) {
	fx := newPollFixture(t, signedIn)
	fx.s.Rename("tag.keys", "My keys")
	fx.s.Delete("tag.keys")
	if len(fx.s.names) != 0 {
		t.Errorf("names left: %v", fx.s.names)
	}
}

type fakeRegistry struct {
	calls    int
	entities map[string]ha.Entity
	err      error
}

func (r *fakeRegistry) Trackers(context.Context) (map[string]ha.Entity, error) {
	r.calls++
	return r.entities, r.err
}

func TestStatusLinksTagsToTheirHomeAssistantDevices(t *testing.T) {
	fx := newPollFixture(t, signedIn)
	reg := &fakeRegistry{entities: map[string]ha.Entity{ha.ID(fx.id): {EntityID: "device_tracker.tag", DeviceID: "dev1"}}}
	fx.s.links.Registry = reg
	fx.s.poll(context.Background(), time.Date(2026, 10, 26, 12, 0, 0, 0, time.UTC))

	tags := fx.s.Status().Tags
	if len(tags) != 1 || tags[0].Entity != "device_tracker.tag" || tags[0].DeviceID != "dev1" {
		t.Fatalf("tags %+v", tags)
	}
	fx.s.Status()
	if reg.calls != 1 {
		t.Errorf("the registry was asked %d times, want once within the TTL", reg.calls)
	}
}

func TestStatusWorksWhileHomeAssistantDoesNotAnswer(t *testing.T) {
	fx := newPollFixture(t, signedIn)
	fx.s.links.Registry = &fakeRegistry{err: errors.New("down")}
	fx.s.poll(context.Background(), time.Date(2026, 10, 26, 12, 0, 0, 0, time.UTC))
	tags := fx.s.Status().Tags
	if len(tags) != 1 || tags[0].DeviceID != "" {
		t.Errorf("tags %+v, want one without a link", tags)
	}
}
