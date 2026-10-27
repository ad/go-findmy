package web

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/ad/go-findmy/internal/findmy"
)

type fakeLogin struct {
	appleID, password, code string
	needCode, sms           bool
	waiting, cancelled      bool
}

func (l *fakeLogin) Pending() (bool, bool) { return l.sms, l.waiting }
func (l *fakeLogin) Cancel()               { l.cancelled, l.waiting = true, false }

func (l *fakeLogin) SignIn(_ context.Context, appleID, password string, sms bool) (bool, error) {
	l.appleID, l.password, l.sms = appleID, password, sms
	l.waiting = l.needCode
	return l.needCode, nil
}

func (l *fakeLogin) SubmitCode(_ context.Context, code string) error {
	l.code = code
	if code != "123456" {
		return errors.New("wrong code")
	}
	l.waiting = false
	return nil
}

var tags = []TagStatus{
	{Name: "Keys", Report: &findmy.Report{Latitude: 52.5, Longitude: 13.4, Accuracy: 25}},
	{Name: "Bag"},
}

func newServer(t *testing.T) (*Server, *fakeLogin) {
	t.Helper()
	l := &fakeLogin{}
	return &Server{
		Login:   l,
		KeysDir: t.TempDir(),
		Status: func() Status {
			return Status{
				LoginRequired: true,
				Cooldown:      "icloud: cooldown until 2026-10-26T12:45:00Z: the Apple ID is locked, unlock it at iforgot.apple.com",
				LastPoll:      time.Date(2026, 10, 26, 11, 0, 0, 0, time.UTC),
				Tags:          tags,
			}
		},
	}, l
}

func signedIn(s *Server, tags []TagStatus) {
	s.Status = func() Status {
		return Status{LastPoll: time.Date(2026, 10, 26, 11, 0, 0, 0, time.UTC), Tags: tags}
	}
}

func shows(t *testing.T, body string, want, absent []string) {
	t.Helper()
	for _, w := range want {
		if !strings.Contains(body, w) {
			t.Errorf("page lacks %q", w)
		}
	}
	for _, a := range absent {
		if strings.Contains(body, a) {
			t.Errorf("page has %q", a)
		}
	}
}

func do(s *Server, method, path string, form url.Values) *httptest.ResponseRecorder {
	r := httptest.NewRequest(method, path, strings.NewReader(form.Encode()))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	r.RemoteAddr = ingressProxy + ":51234"
	w := httptest.NewRecorder()
	s.ServeHTTP(w, r)
	return w
}

func accessoryJSON(t *testing.T, identifier string) string {
	t.Helper()
	raw, err := os.ReadFile("../findmy/testdata/findmypy-22e4879.json")
	if err != nil {
		t.Fatal(err)
	}
	var v struct{ Accessory map[string]any }
	if err := json.Unmarshal(raw, &v); err != nil {
		t.Fatal(err)
	}
	v.Accessory["identifier"] = identifier
	data, _ := json.Marshal(v.Accessory)
	return string(data)
}

func TestOnlyIngressProxyIsServed(t *testing.T) {
	s, _ := newServer(t)
	r := httptest.NewRequest(http.MethodGet, "/", nil)
	r.RemoteAddr = "192.168.1.20:40000"
	w := httptest.NewRecorder()
	s.ServeHTTP(w, r)
	if w.Code != http.StatusForbidden {
		t.Errorf("status %d, want 403", w.Code)
	}
}

func TestSignedOutPageOffersOnlyTheLoginForm(t *testing.T) {
	s, _ := newServer(t)
	body := do(s, http.MethodGet, "/", nil).Body.String()
	shows(t, body,
		[]string{"Sign-in required", `action="login"`, `name="sms"`, "until 2026-10-26T12:45:00Z", "iforgot.apple.com", " disabled"},
		[]string{`action="code"`, `action="import"`, `action="cancel"`, "Keys"})
}

func TestPageAsksForTheCodeOnlyWhileSignInWaits(t *testing.T) {
	s, l := newServer(t)
	l.waiting = true
	body := do(s, http.MethodGet, "/", nil).Body.String()
	shows(t, body,
		[]string{"Waiting for the code", `action="code"`, `action="cancel"`, "trusted device"},
		[]string{`action="login"`, `action="import"`})

	l.sms = true
	if body := do(s, http.MethodGet, "/", nil).Body.String(); !strings.Contains(body, "by SMS") {
		t.Error("the page does not say the code went out by SMS")
	}

	w := do(s, http.MethodPost, "/cancel", nil)
	if !l.cancelled || strings.Contains(w.Body.String(), `action="code"`) || !strings.Contains(w.Body.String(), `action="login"`) {
		t.Errorf("cancelled %v; the page must go back to the login form", l.cancelled)
	}
}

func TestSignedInPageShowsTagsAndImport(t *testing.T) {
	s, _ := newServer(t)
	signedIn(s, tags)
	body := do(s, http.MethodGet, "/", nil).Body.String()
	shows(t, body,
		[]string{"Signed in", "Keys", "52.5", "no report yet", `action="import"`, "<summary>Add a tag</summary>", "<summary>Account</summary>"},
		[]string{`action="code"`, `class="steps"`})
}

func TestSignedInPageWithoutTagsLeadsToImport(t *testing.T) {
	s, _ := newServer(t)
	signedIn(s, nil)
	body := do(s, http.MethodGet, "/", nil).Body.String()
	shows(t, body, []string{"Add your first tag", `class="steps"`, `action="import"`}, []string{"<summary>Add a tag</summary>"})
}

func TestPageKeepsTheHomeAssistantTheme(t *testing.T) {
	s, _ := newServer(t)
	body := do(s, http.MethodGet, "/", nil).Body.String()
	shows(t, body, []string{"prefers-color-scheme:dark", "--primary-background-color", "--primary-text-color"}, nil)
}

func TestImportWritesValidatedAccessoryInsideKeysDir(t *testing.T) {
	s, _ := newServer(t)
	w := do(s, http.MethodPost, "/import", url.Values{"accessory": {accessoryJSON(t, "../../evil")}})
	if w.Code != http.StatusOK {
		t.Fatalf("status %d: %s", w.Code, w.Body)
	}
	entries, _ := os.ReadDir(s.KeysDir)
	if len(entries) != 1 || entries[0].Name() != "______evil.json" {
		t.Fatalf("keys dir %v, want one ______evil.json", entries)
	}
	path := filepath.Join(s.KeysDir, entries[0].Name())
	info, _ := os.Stat(path)
	if info.Mode().Perm() != 0o600 {
		t.Errorf("mode %v, want 0600", info.Mode().Perm())
	}
	data, _ := os.ReadFile(path)
	if _, err := findmy.ParseAccessory(data); err != nil {
		t.Errorf("saved file does not parse: %v", err)
	}
}

func TestImportTakesAListOfTags(t *testing.T) {
	s, _ := newServer(t)
	list := "[" + accessoryJSON(t, "tag/a") + "," + accessoryJSON(t, "tag/b") + "]"
	w := do(s, http.MethodPost, "/import", url.Values{"accessory": {list}})
	if w.Code != http.StatusOK || !strings.Contains(w.Body.String(), "Imported 2 tags") {
		t.Fatalf("status %d: %s", w.Code, w.Body)
	}
	for _, name := range []string{"tag_a.json", "tag_b.json"} {
		if _, err := os.Stat(filepath.Join(s.KeysDir, name)); err != nil {
			t.Errorf("%s not written: %v", name, err)
		}
	}
}

func TestImportOfAListWritesNothingWhenOneTagIsBad(t *testing.T) {
	s, _ := newServer(t)
	list := "[" + accessoryJSON(t, "tag-a") + `,{"type":"accessory"}]`
	w := do(s, http.MethodPost, "/import", url.Values{"accessory": {list}})
	if w.Code != http.StatusBadRequest || !strings.Contains(w.Body.String(), "tag 2:") {
		t.Errorf("status %d, body lacks the tag number", w.Code)
	}
	if entries, _ := os.ReadDir(s.KeysDir); len(entries) != 0 {
		t.Errorf("files written: %v", entries)
	}
}

func TestImportRejectsAnEmptyList(t *testing.T) {
	s, _ := newServer(t)
	if w := do(s, http.MethodPost, "/import", url.Values{"accessory": {" [] "}}); w.Code != http.StatusBadRequest {
		t.Errorf("status %d, want 400", w.Code)
	}
}

func TestImportRejectsInvalidAccessory(t *testing.T) {
	s, _ := newServer(t)
	w := do(s, http.MethodPost, "/import", url.Values{"accessory": {`{"type":"accessory"}`}})
	if w.Code != http.StatusBadRequest {
		t.Errorf("status %d, want 400", w.Code)
	}
	if entries, _ := os.ReadDir(s.KeysDir); len(entries) != 0 {
		t.Errorf("files written: %v", entries)
	}
}

func TestImportRefusesNamesTakenForCredentials(t *testing.T) {
	s, _ := newServer(t)
	w := do(s, http.MethodPost, "/import", url.Values{"accessory": {accessoryJSON(t, "auth")}})
	if w.Code != http.StatusBadRequest {
		t.Errorf("status %d, want 400", w.Code)
	}
	if entries, _ := os.ReadDir(s.KeysDir); len(entries) != 0 {
		t.Errorf("files written: %v", entries)
	}
}

func TestLoginThenCode(t *testing.T) {
	s, l := newServer(t)
	l.needCode = true
	w := do(s, http.MethodPost, "/login", url.Values{"apple_id": {"me@example.com"}, "password": {"pw"}})
	if l.appleID != "me@example.com" || l.password != "pw" {
		t.Errorf("SignIn got %q %q", l.appleID, l.password)
	}
	if !strings.Contains(w.Body.String(), `action="code"`) {
		t.Errorf("no prompt for the 2FA code")
	}

	w = do(s, http.MethodPost, "/code", url.Values{"code": {"000000"}})
	if w.Code != http.StatusBadRequest || !strings.Contains(w.Body.String(), "wrong code") {
		t.Errorf("bad code: status %d, body lacks the error", w.Code)
	}
	w = do(s, http.MethodPost, "/code", url.Values{"code": {"123456"}})
	if w.Code != http.StatusOK || l.code != "123456" {
		t.Errorf("good code: status %d, code %q", w.Code, l.code)
	}
}

func TestLoginCanAskForSMS(t *testing.T) {
	s, l := newServer(t)
	do(s, http.MethodPost, "/login", url.Values{"apple_id": {"me@example.com"}, "password": {"pw"}})
	if l.sms {
		t.Error("SMS asked without the box ticked")
	}
	do(s, http.MethodPost, "/login", url.Values{"apple_id": {"me@example.com"}, "password": {"pw"}, "sms": {"on"}})
	if !l.sms {
		t.Error("SMS not asked with the box ticked")
	}
}
