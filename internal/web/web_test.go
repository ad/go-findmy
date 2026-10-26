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
	needCode                bool
}

func (l *fakeLogin) SignIn(_ context.Context, appleID, password string) (bool, error) {
	l.appleID, l.password = appleID, password
	return l.needCode, nil
}

func (l *fakeLogin) SubmitCode(_ context.Context, code string) error {
	l.code = code
	if code != "123456" {
		return errors.New("wrong code")
	}
	return nil
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
				LastPoll:      time.Date(2026, 10, 26, 11, 0, 0, 0, time.UTC),
				Tags: []TagStatus{
					{Name: "Keys", Report: &findmy.Report{Latitude: 52.5, Longitude: 13.4, Accuracy: 25}},
					{Name: "Bag"},
				},
			}
		},
	}, l
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

func TestStatusPageShowsLoginNeededAndTags(t *testing.T) {
	s, _ := newServer(t)
	w := do(s, http.MethodGet, "/", nil)
	body := w.Body.String()
	for _, want := range []string{"Login required", "Keys", "52.5", "Bag", `action="login"`, `action="code"`, `action="import"`} {
		if !strings.Contains(body, want) {
			t.Errorf("page lacks %q", want)
		}
	}
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
	if !strings.Contains(w.Body.String(), "Enter the code") {
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
