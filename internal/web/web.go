package web

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"html/template"
	"log"
	"net"
	"net/http"
	"path/filepath"
	"strings"
	"time"

	"github.com/ad/go-findmy/internal/findmy"
	"github.com/ad/go-findmy/internal/ha"
)

const ingressProxy = "172.30.32.2"

type Login interface {
	SignIn(ctx context.Context, appleID, password string, sms bool) (needCode bool, err error)
	SubmitCode(ctx context.Context, code string) error
	// Pending reports whether a sign-in waits for its code, and how the code was sent.
	Pending() (sms, waiting bool)
	// Cancel drops the sign-in that waits for a code.
	Cancel()
}

type TagStatus struct {
	Name   string
	Report *findmy.Report
}

type Status struct {
	LoginRequired bool
	Cooldown      string
	NeedLogin     string
	Reason        string // why the session was lost; empty when there was no attempt yet
	LastPoll      time.Time
	LastError     string
	Tags          []TagStatus
}

type Server struct {
	Login   Login
	KeysDir string
	Status  func() Status
}

func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if host, _, _ := net.SplitHostPort(r.RemoteAddr); host != ingressProxy {
		http.Error(w, "only Home Assistant Ingress is served", http.StatusForbidden)
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, 1<<20)
	switch {
	case r.Method == http.MethodGet && r.URL.Path == "/":
		s.render(w, http.StatusOK, "")
	case r.Method == http.MethodPost && r.URL.Path == "/login":
		needCode, err := s.Login.SignIn(r.Context(), r.FormValue("apple_id"), r.FormValue("password"), r.FormValue("sms") != "")
		switch {
		case err != nil:
			s.render(w, http.StatusBadRequest, "Login failed: "+err.Error())
		case needCode:
			s.render(w, http.StatusOK, "")
		default:
			s.render(w, http.StatusOK, "Signed in.")
		}
	case r.Method == http.MethodPost && r.URL.Path == "/code":
		if err := s.Login.SubmitCode(r.Context(), r.FormValue("code")); err != nil {
			s.render(w, http.StatusBadRequest, "Code rejected: "+err.Error())
			return
		}
		s.render(w, http.StatusOK, "Signed in.")
	case r.Method == http.MethodPost && r.URL.Path == "/cancel":
		s.Login.Cancel()
		s.render(w, http.StatusOK, "")
	case r.Method == http.MethodPost && r.URL.Path == "/import":
		s.importAccessory(w, r)
	default:
		http.NotFound(w, r)
	}
}

// importAccessory takes one tag or a JSON array of them, the airtags.json that export_tags.sh
// gets from Apple. Everything is checked before the first file is written.
func (s *Server) importAccessory(w http.ResponseWriter, r *http.Request) {
	tags, err := s.parseTags([]byte(r.FormValue("accessory")))
	if err != nil {
		s.render(w, http.StatusBadRequest, "Import failed: "+err.Error())
		return
	}
	names := make([]string, len(tags))
	for i, a := range tags {
		file := ha.ID(a.Identifier()) + ".json"
		if err := a.Save(filepath.Join(s.KeysDir, file)); err != nil {
			log.Printf("import %s: %v", file, err)
			s.render(w, http.StatusInternalServerError, fmt.Sprintf("Import failed after %d of %d tags: %v", i, len(tags), err))
			return
		}
		names[i] = a.Name()
	}
	if len(tags) == 1 {
		s.render(w, http.StatusOK, "Imported "+names[0]+". It shows up after the next poll.")
		return
	}
	s.render(w, http.StatusOK, fmt.Sprintf("Imported %d tags: %s. They show up after the next poll.", len(tags), strings.Join(names, ", ")))
}

func (s *Server) parseTags(data []byte) ([]*findmy.Accessory, error) {
	items := []json.RawMessage{data}
	list := bytes.HasPrefix(bytes.TrimSpace(data), []byte("["))
	if list {
		items = nil
		if err := json.Unmarshal(data, &items); err != nil {
			return nil, err
		}
		if len(items) == 0 {
			return nil, errors.New("the list is empty")
		}
	}
	tags := make([]*findmy.Accessory, len(items))
	for i, item := range items {
		a, err := findmy.ParseAccessory(item)
		if err == nil && a.Identifier() == "" {
			err = errNoIdentifier
		}
		if err == nil && strings.HasSuffix(ha.ID(a.Identifier())+".json", "auth.json") {
			err = errors.New("identifier " + a.Identifier() + " collides with the credentials file")
		}
		if err != nil {
			if list {
				err = fmt.Errorf("tag %d: %w", i+1, err)
			}
			return nil, err
		}
		tags[i] = a
	}
	return tags, nil
}

var errNoIdentifier = errors.New("accessory: identifier is empty")

func (s *Server) render(w http.ResponseWriter, status int, message string) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(status)
	sms, waiting := s.Login.Pending()
	v := view{Status: s.Status(), Message: message, Failed: status >= 400, SMS: sms, Waiting: waiting}
	if err := page.Execute(w, v); err != nil {
		log.Printf("ingress page: %v", err)
	}
}

// view is what the page needs: the status plus the outcome of the last action.
type view struct {
	Status
	Message string
	Failed  bool
	Waiting bool // a sign-in waits for its code
	SMS     bool // the code went out by SMS
}

// Step is the one thing the user has to do now: sign in, enter the code, or nothing.
func (v view) Step() string {
	switch {
	case v.Waiting:
		return "code"
	case v.LoginRequired || v.NeedLogin != "":
		return "login"
	}
	return "ready"
}

type step struct {
	Name  string
	State string // done, current or todo
}

// Steps is the progress shown until the first tag is on the page; later it is noise.
func (v view) Steps() []step {
	names := []string{"Apple ID", "Code", "Tags"}
	cur := map[string]int{"login": 0, "code": 1, "ready": 2}[v.Step()]
	if cur == 2 && len(v.Tags) > 0 {
		return nil
	}
	out := make([]step, len(names))
	for i, n := range names {
		out[i] = step{n, "todo"}
		switch {
		case i < cur:
			out[i].State = "done"
		case i == cur:
			out[i].State = "current"
		}
	}
	return out
}

// Forms post to relative URLs: Ingress serves the page under a per-session path prefix.
// The colours come from the Home Assistant theme of the parent page (same origin under
// Ingress); the prefers-color-scheme values apply when the parent cannot be read.
var page = template.Must(template.New("page").Parse(pageHTML))
