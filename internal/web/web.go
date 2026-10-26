package web

import (
	"context"
	"errors"
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
	SignIn(ctx context.Context, appleID, password string) (needCode bool, err error)
	SubmitCode(ctx context.Context, code string) error
}

type TagStatus struct {
	Name   string
	Report *findmy.Report
}

type Status struct {
	LoginRequired bool
	Cooldown      string
	NeedLogin     string
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
		needCode, err := s.Login.SignIn(r.Context(), r.FormValue("apple_id"), r.FormValue("password"))
		switch {
		case err != nil:
			s.render(w, http.StatusBadRequest, "Login failed: "+err.Error())
		case needCode:
			s.render(w, http.StatusOK, "Enter the code from your trusted device.")
		default:
			s.render(w, http.StatusOK, "Signed in.")
		}
	case r.Method == http.MethodPost && r.URL.Path == "/code":
		if err := s.Login.SubmitCode(r.Context(), r.FormValue("code")); err != nil {
			s.render(w, http.StatusBadRequest, "Code rejected: "+err.Error())
			return
		}
		s.render(w, http.StatusOK, "Signed in.")
	case r.Method == http.MethodPost && r.URL.Path == "/import":
		s.importAccessory(w, r)
	default:
		http.NotFound(w, r)
	}
}

func (s *Server) importAccessory(w http.ResponseWriter, r *http.Request) {
	a, err := findmy.ParseAccessory([]byte(r.FormValue("accessory")))
	if err == nil && a.Identifier() == "" {
		err = errNoIdentifier
	}
	if err != nil {
		s.render(w, http.StatusBadRequest, "Import failed: "+err.Error())
		return
	}
	name := ha.ID(a.Identifier()) + ".json"
	if strings.HasSuffix(name, "auth.json") {
		s.render(w, http.StatusBadRequest, "Import failed: identifier "+a.Identifier()+" collides with the credentials file")
		return
	}
	if err := a.Save(filepath.Join(s.KeysDir, name)); err != nil {
		log.Printf("import %s: %v", name, err)
		s.render(w, http.StatusInternalServerError, "Import failed: "+err.Error())
		return
	}
	s.render(w, http.StatusOK, "Imported "+a.Name()+". It shows up after the next poll.")
}

var errNoIdentifier = errors.New("accessory: identifier is empty")

func (s *Server) render(w http.ResponseWriter, status int, message string) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(status)
	if err := page.Execute(w, struct {
		Status
		Message string
	}{s.Status(), message}); err != nil {
		log.Printf("ingress page: %v", err)
	}
}

// Forms post to relative URLs: Ingress serves the page under a per-session path prefix.
var page = template.Must(template.New("page").Parse(`<!doctype html>
<html><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<title>Find My</title>
<style>body{font-family:sans-serif;max-width:40rem;margin:1rem auto;padding:0 1rem}
form{margin:1rem 0}input,textarea{display:block;width:100%;margin:.3rem 0;box-sizing:border-box}
.warn{color:#b00}td,th{padding:.2rem .5rem;text-align:left}</style></head><body>
<h1>Find My</h1>
{{with .Message}}<p><b>{{.}}</b></p>{{end}}
{{if .LoginRequired}}<p class="warn">Login required.</p>{{end}}
{{with .NeedLogin}}<p class="warn">{{.}}</p>{{end}}
{{with .Cooldown}}<p class="warn">Nothing is sent to Apple: {{.}}</p>{{end}}
<p>Last poll: {{if .LastPoll.IsZero}}not yet{{else}}{{.LastPoll.Format "2006-01-02 15:04:05 MST"}}{{end}}</p>
{{with .LastError}}<p class="warn">Last error: {{.}}</p>{{end}}
<h2>Tags</h2>
<table><tr><th>Name</th><th>Last seen</th><th>Location</th><th>Accuracy, m</th></tr>
{{range .Tags}}<tr><td>{{.Name}}</td>{{with .Report}}<td>{{.Time.Format "2006-01-02 15:04 MST"}}</td><td>{{.Latitude}}, {{.Longitude}}</td><td>{{.Accuracy}}</td>{{else}}<td colspan="3">no report</td>{{end}}</tr>
{{else}}<tr><td colspan="4">No tags yet.</td></tr>{{end}}</table>
<h2>Apple ID</h2>
<form method="post" action="login"><input name="apple_id" type="email" placeholder="Apple ID" autocomplete="username" required>
<input name="password" type="password" placeholder="Password" autocomplete="current-password" required><button>Sign in</button></form>
<form method="post" action="code"><input name="code" inputmode="numeric" placeholder="2FA code" autocomplete="one-time-code" required><button>Submit code</button></form>
<h2>Import AirTag JSON</h2>
<form method="post" action="import"><textarea name="accessory" rows="8" placeholder="FindMy.py / export-findmy accessory JSON" required></textarea><button>Import</button></form>
</body></html>
`))
