package main

import (
	"cmp"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"syscall"
	"time"
	_ "time/tzdata" // the add-on image has no zoneinfo
	"unicode/utf8"

	"github.com/ad/go-findmy/internal/anisette"
	"github.com/ad/go-findmy/internal/findmy"
	"github.com/ad/go-findmy/internal/ha"
	"github.com/ad/go-findmy/internal/icloud"
	"github.com/ad/go-findmy/internal/web"
)

const (
	addonDataDir = "/data"
	ingressAddr  = ":8099"
	lastPollFile = "last_poll"
	namesFile    = "names.json"
	maxNameLen   = 100
	minInterval  = 15 * time.Minute
)

func pollInterval(minutes int) time.Duration {
	return max(time.Duration(minutes)*time.Minute, minInterval)
}

type service struct {
	keysDir string
	dataDir string
	fetcher *findmy.Fetcher
	acct    *icloud.Account
	pub     ha.Publisher

	// pubMu is held while a tag is announced or deleted, so that a poll that started
	// before Delete cannot bring the tag back.
	pubMu sync.Mutex

	mu      sync.Mutex
	status  web.Status
	reports map[string]*findmy.Report
	links   links
	names   map[string]string // names the user gave, by tag ID; they win over the name in the key file
}

func newService(keysDir, dataDir string, f *findmy.Fetcher, acct *icloud.Account, pub ha.Publisher) *service {
	f.Credentials = acct
	s := &service{keysDir: keysDir, dataDir: dataDir, fetcher: f, acct: acct, pub: pub, reports: map[string]*findmy.Report{}, names: map[string]string{}}
	if data, err := os.ReadFile(filepath.Join(dataDir, namesFile)); err == nil {
		if err := json.Unmarshal(data, &s.names); err != nil {
			log.Printf("%s: %v", namesFile, err)
			s.names = map[string]string{}
		}
	}
	return s
}

// links finds the Home Assistant entity of each tag. The registry changes rarely and every page
// view asks, so the answer is kept for a while.
type links struct {
	Registry interface {
		Trackers(ctx context.Context) (map[string]ha.Entity, error)
	}

	mu       sync.Mutex
	entities map[string]ha.Entity
	at       time.Time
}

const linksTTL = 30 * time.Second

// get returns the entities by tag ID, nil when the registry is not available.
func (l *links) get() map[string]ha.Entity {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.Registry == nil || time.Since(l.at) < linksTTL {
		return l.entities
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	l.at = time.Now()
	entities, err := l.Registry.Trackers(ctx)
	if err != nil {
		log.Print(err)
		return l.entities
	}
	l.entities = entities
	return entities
}

// named is the tag as Home Assistant should show it. s.mu must be held.
func (s *service) named(t tag) ha.Tag {
	ht := t.haTag()
	if n := s.names[ht.ID]; n != "" {
		ht.Name = n
	}
	return ht
}

func (s *service) announce(t tag) error {
	s.mu.Lock()
	ht := s.named(t)
	s.mu.Unlock()
	return ha.AnnounceTag(s.pub, ht)
}

// saveNames writes names.json; s.mu must be held.
func (s *service) saveNames() error {
	data, err := json.Marshal(s.names)
	if err != nil {
		return err
	}
	path := filepath.Join(s.dataDir, namesFile)
	if err := os.WriteFile(path+".tmp", data, 0o600); err != nil {
		return err
	}
	return os.Rename(path+".tmp", path)
}

func (s *service) Status() web.Status {
	s.mu.Lock()
	st := s.status
	st.Tags = slices.Clone(st.Tags)
	s.mu.Unlock()
	if entities := s.links.get(); entities != nil {
		for i, t := range st.Tags {
			e := entities[t.ID]
			st.Tags[i].Entity, st.Tags[i].DeviceID = e.EntityID, e.DeviceID
		}
	}
	st.AppleID = s.acct.AppleID()
	if err := s.acct.Cooldown(); err != nil {
		st.Cooldown = err.Error()
	}
	if _, _, err := s.acct.SearchPartyAuth(); err != nil {
		st.NeedLogin = err.Error()
		st.Reason = strings.TrimPrefix(strings.TrimPrefix(st.NeedLogin, icloud.ErrNeedLogin.Error()), ": ")
	}
	return st
}

func (s *service) wait(interval time.Duration, now time.Time) time.Duration {
	data, err := os.ReadFile(filepath.Join(s.dataDir, lastPollFile))
	if err != nil {
		return 0
	}
	last, err := time.Parse(time.RFC3339, strings.TrimSpace(string(data)))
	if err != nil {
		return 0
	}
	return max(last.Add(interval).Sub(now), 0)
}

func (s *service) poll(ctx context.Context, now time.Time) {
	// Written first so that a crash mid-poll still holds back the next start.
	if err := os.WriteFile(filepath.Join(s.dataDir, lastPollFile), []byte(now.Format(time.RFC3339)), 0o600); err != nil {
		log.Print(err)
	}
	err := s.fetchAndPublish(ctx, now)
	if err != nil {
		log.Print(err)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.status.LastPoll = now
	s.status.LastError = ""
	if err != nil {
		s.status.LastError = err.Error()
	}
}

func (s *service) fetchAndPublish(ctx context.Context, now time.Time) error {
	tags, err := loadTags(s.keysDir)
	if err != nil {
		return err
	}
	var errs []error
	for _, t := range tags {
		errs = append(errs, s.whilePresent(t, func() error { return s.announce(t) }))
	}
	defer s.setTags(tags)

	if err := s.acct.Cooldown(); err != nil {
		return errors.Join(append(errs, err, s.setLoginRequired(s.credentials() == ""))...)
	}

	reports, err := latest(ctx, s.fetcher, tags, now)
	errs = append(errs, err, s.setLoginRequired(s.credentials() == ""))

	for _, t := range tags {
		if r := reports[t.name]; r != nil {
			errs = append(errs, s.whilePresent(t, func() error {
				s.mu.Lock()
				s.reports[t.name] = r
				s.mu.Unlock()
				return ha.PublishLocation(s.pub, t.haTag().ID, *r)
			}))
		}
	}
	return errors.Join(errs...)
}

func (s *service) credentials() string {
	dsid, token, err := s.acct.SearchPartyAuth()
	if err != nil {
		return ""
	}
	return dsid + ":" + token
}

func (s *service) signedIn() {
	if err := s.setLoginRequired(false); err != nil {
		log.Print(err)
	}
}

func (s *service) SignOut() error {
	if err := s.acct.Logout(); err != nil {
		return err
	}
	if err := s.setLoginRequired(true); err != nil {
		log.Print(err)
	}
	return nil
}

func (s *service) setLoginRequired(required bool) error {
	s.mu.Lock()
	s.status.LoginRequired = required
	s.mu.Unlock()
	return ha.PublishLoginRequired(s.pub, required)
}

func (s *service) setTags(tags []tag) {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]web.TagStatus, 0, len(tags))
	for _, t := range tags {
		if _, err := os.Stat(t.path); err == nil {
			out = append(out, web.TagStatus{File: t.name, ID: t.haTag().ID, Name: s.named(t).Name, Report: s.reports[t.name]})
		}
	}
	s.status.Tags = out
}

// whilePresent runs publish unless the tag was deleted since it was loaded.
func (s *service) whilePresent(t tag, publish func() error) error {
	s.pubMu.Lock()
	defer s.pubMu.Unlock()
	if _, err := os.Stat(t.path); err != nil {
		return nil
	}
	return publish()
}

// Delete removes the key file of a tag and its device from Home Assistant, and returns the tag's name.
// Only tags that loadTags lists can be deleted, not the credentials or any other file.
func (s *service) Delete(file string) (string, error) {
	tags, err := loadTags(s.keysDir)
	if err != nil {
		return "", err
	}
	i := slices.IndexFunc(tags, func(t tag) bool { return t.name == file })
	if i < 0 {
		return "", errors.New("no such tag")
	}
	t := tags[i]

	s.pubMu.Lock()
	defer s.pubMu.Unlock()
	if err := os.Remove(t.path); err != nil {
		return "", err
	}
	s.mu.Lock()
	ht := s.named(t)
	if _, ok := s.names[ht.ID]; ok {
		delete(s.names, ht.ID)
		if err := s.saveNames(); err != nil {
			log.Print(err)
		}
	}
	delete(s.reports, t.name)
	s.status.Tags = slices.DeleteFunc(slices.Clone(s.status.Tags), func(ts web.TagStatus) bool { return ts.File == t.name })
	s.mu.Unlock()
	if err := ha.RemoveTag(s.pub, ht.ID); err != nil {
		return "", fmt.Errorf("the keys are gone, but clearing the device in Home Assistant failed: %w", err)
	}
	return ht.Name, nil
}

// Rename gives the tag in the key file the name its device has in Home Assistant. An empty name
// goes back to the one from the key file. The name outlives a new import of the same tag.
func (s *service) Rename(file, name string) error {
	name = strings.TrimSpace(name)
	if utf8.RuneCountInString(name) > maxNameLen {
		return fmt.Errorf("the name is longer than %d characters", maxNameLen)
	}
	tags, err := loadTags(s.keysDir)
	if err != nil {
		return err
	}
	i := slices.IndexFunc(tags, func(t tag) bool { return t.name == file })
	if i < 0 {
		return errors.New("no such tag")
	}
	t := tags[i]

	s.pubMu.Lock()
	defer s.pubMu.Unlock()
	s.mu.Lock()
	id := t.haTag().ID
	if name == "" {
		delete(s.names, id)
	} else {
		s.names[id] = name
	}
	err = s.saveNames()
	for j := range s.status.Tags {
		if s.status.Tags[j].File == t.name {
			s.status.Tags[j].Name = s.named(t).Name
		}
	}
	s.mu.Unlock()
	if err != nil {
		return err
	}
	return s.announce(t)
}

// location is the time zone of the page: the add-on option, else the TZ Supervisor passes to the
// add-on from the Home Assistant settings, else UTC.
func location(option, env string) *time.Location {
	if option != "" {
		loc, err := time.LoadLocation(option)
		if err != nil {
			log.Fatalf("options.json: timezone: %v", err)
		}
		return loc
	}
	if env != "" {
		if loc, err := time.LoadLocation(env); err == nil {
			return loc
		}
		log.Printf("ignoring TZ=%q: unknown time zone", env)
	}
	return time.UTC
}

func (t tag) haTag() ha.Tag {
	if t.acc != nil {
		return ha.Tag{ID: ha.ID(cmp.Or(t.acc.Identifier(), t.name)), Name: cmp.Or(t.acc.Name(), t.name), Model: t.acc.Model()}
	}
	return ha.Tag{ID: ha.ID(t.key.ID), Name: strings.TrimSuffix(t.name, ".keys"), Model: "OpenHaystack"}
}

type ingressLogin struct {
	acct      *icloud.Account
	provision func() (fresh bool, err error)
	signedIn  func()

	mu      sync.Mutex
	pending *icloud.SecondFactor
	sms     bool
	phoneID int64
}

func (l *ingressLogin) SignIn(ctx context.Context, appleID, password string, sms bool) (bool, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.pending = nil
	// The sidecar provisions against Apple and cannot see the account cooldown.
	if err := l.acct.Cooldown(); err != nil {
		return false, err
	}
	if _, err := l.provision(); err != nil {
		return false, l.acct.Refused(err)
	}
	sf, err := l.acct.Login(ctx, appleID, password)
	if err != nil {
		return false, err
	}
	if sf == nil {
		l.signedIn()
		return false, nil
	}
	l.sms = sms || !sf.TrustedDevice
	if l.sms {
		err = l.requestSMS(ctx, sf)
	} else {
		err = sf.RequestTrustedDeviceCode(ctx)
	}
	if err != nil {
		return false, err
	}
	l.pending = sf
	return true, nil
}

func (l *ingressLogin) requestSMS(ctx context.Context, sf *icloud.SecondFactor) error {
	phones, err := sf.Phones(ctx)
	if err != nil {
		return err
	}
	if len(phones) == 0 {
		return errors.New("icloud: the account has no trusted phone numbers")
	}
	l.phoneID = phones[0].ID
	return sf.RequestSMSCode(ctx, l.phoneID)
}

func (l *ingressLogin) Pending() (sms, waiting bool) {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.sms, l.pending != nil
}

func (l *ingressLogin) Cancel() {
	l.mu.Lock()
	l.pending = nil
	l.mu.Unlock()
}

func (l *ingressLogin) SubmitCode(ctx context.Context, code string) error {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.pending == nil {
		return errors.New("no sign-in waits for a code, sign in first")
	}
	var err error
	if l.sms {
		err = l.pending.SubmitSMSCode(ctx, l.phoneID, code)
	} else {
		err = l.pending.SubmitTrustedDeviceCode(ctx, code)
	}
	if err == nil {
		l.pending = nil
		l.signedIn()
	}
	return err
}

func serve() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	var opts struct {
		PollInterval int    `json:"poll_interval"`
		Timezone     string `json:"timezone"`
	}
	data, err := os.ReadFile(filepath.Join(addonDataDir, "options.json"))
	if err != nil {
		log.Fatal(err)
	}
	if err := json.Unmarshal(data, &opts); err != nil {
		log.Fatalf("options.json: %v", err)
	}
	interval := pollInterval(opts.PollInterval)
	loc := location(opts.Timezone, os.Getenv("TZ"))

	broker := "tcp://" + net.JoinHostPort(os.Getenv("MQTT_HOST"), os.Getenv("MQTT_PORT"))
	client, err := ha.Dial(broker, os.Getenv("MQTT_USER"), os.Getenv("MQTT_PASSWORD"))
	if err != nil {
		log.Fatal(err)
	}
	defer client.Close()
	if err := ha.AnnounceLoginSensor(client); err != nil {
		log.Print(err)
	}

	sc := anisette.New(anisetteURL)
	acct, err := icloud.Open(filepath.Join(addonDataDir, accountDir), sc)
	if err != nil {
		log.Fatal(err)
	}
	s := newService(filepath.Join(addonDataDir, keysDir), addonDataDir, findmy.NewFetcher(sc, acct, acct.Relogin), acct, client)
	if token := os.Getenv("SUPERVISOR_TOKEN"); token != "" {
		s.links.Registry = ha.Registry{URL: ha.SupervisorWebsocket, Token: token}
	}
	login := &ingressLogin{acct: acct, provision: sc.Provision, signedIn: s.signedIn}
	go func() {
		log.Fatal(http.ListenAndServe(ingressAddr, &web.Server{Login: login, KeysDir: s.keysDir, Status: s.Status, Delete: s.Delete, Rename: s.Rename, SignOut: s.SignOut, Location: loc}))
	}()

	log.Printf("polling every %v", interval)
	for {
		select {
		case <-ctx.Done():
			return
		case <-time.After(s.wait(interval, time.Now())):
		}
		s.poll(ctx, time.Now())
	}
}
