package main

import (
	"cmp"
	"context"
	"encoding/json"
	"errors"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"time"

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

	mu      sync.Mutex
	status  web.Status
	reports map[string]*findmy.Report
}

func newService(keysDir, dataDir string, f *findmy.Fetcher, acct *icloud.Account, pub ha.Publisher) *service {
	f.Credentials = acct
	return &service{keysDir: keysDir, dataDir: dataDir, fetcher: f, acct: acct, pub: pub, reports: map[string]*findmy.Report{}}
}

func (s *service) Status() web.Status {
	s.mu.Lock()
	st := s.status
	s.mu.Unlock()
	if err := s.acct.Cooldown(); err != nil {
		st.Cooldown = err.Error()
	}
	if _, _, err := s.acct.SearchPartyAuth(); err != nil {
		st.NeedLogin = err.Error()
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
		errs = append(errs, ha.AnnounceTag(s.pub, t.haTag()))
	}
	defer s.setTags(tags)

	if err := s.acct.Cooldown(); err != nil {
		return errors.Join(append(errs, err)...)
	}

	reports, err := latest(ctx, s.fetcher, tags, now)
	needed := loginNeeded(err) || s.credentials() == ""
	errs = append(errs, err, s.setLoginRequired(needed))

	for _, t := range tags {
		if r := reports[t.name]; r != nil {
			s.reports[t.name] = r
			errs = append(errs, ha.PublishLocation(s.pub, t.haTag().ID, *r))
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

func (s *service) setLoginRequired(required bool) error {
	s.mu.Lock()
	s.status.LoginRequired = required
	s.mu.Unlock()
	return ha.PublishLoginRequired(s.pub, required)
}

func (s *service) setTags(tags []tag) {
	out := make([]web.TagStatus, len(tags))
	for i, t := range tags {
		out[i] = web.TagStatus{Name: t.haTag().Name, Report: s.reports[t.name]}
	}
	s.mu.Lock()
	s.status.Tags = out
	s.mu.Unlock()
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
		PollInterval int `json:"poll_interval"`
	}
	data, err := os.ReadFile(filepath.Join(addonDataDir, "options.json"))
	if err != nil {
		log.Fatal(err)
	}
	if err := json.Unmarshal(data, &opts); err != nil {
		log.Fatalf("options.json: %v", err)
	}
	interval := pollInterval(opts.PollInterval)

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
	login := &ingressLogin{acct: acct, provision: sc.Provision, signedIn: s.signedIn}
	go func() {
		log.Fatal(http.ListenAndServe(ingressAddr, &web.Server{Login: login, KeysDir: s.keysDir, Status: s.Status}))
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
