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
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/ad/go-findmy/internal/anisette"
	"github.com/ad/go-findmy/internal/findmy"
	"github.com/ad/go-findmy/internal/ha"
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
	pub     ha.Publisher

	mu       sync.Mutex
	status   web.Status
	reports  map[string]*findmy.Report
	rejected *auth
}

func newService(keysDir, dataDir string, f *findmy.Fetcher, pub ha.Publisher) *service {
	return &service{keysDir: keysDir, dataDir: dataDir, fetcher: f, pub: pub, reports: map[string]*findmy.Report{}}
}

func (s *service) Status() web.Status {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.status
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

	a, err := readAuth(s.keysDir)
	if err != nil {
		return errors.Join(append(errs, s.setLoginRequired(true), fmt.Errorf("no credentials, sign in: %w", err))...)
	}
	if s.rejected != nil && *s.rejected == a {
		return errors.Join(errs...)
	}

	s.fetcher.Credentials = a
	reports, err := latest(ctx, s.fetcher, tags, now)
	unauthorized := errors.Is(err, findmy.ErrUnauthorized)
	s.rejected = nil
	if unauthorized {
		s.rejected = &a
	}
	errs = append(errs, err, s.setLoginRequired(unauthorized))

	for _, t := range tags {
		if r := reports[t.name]; r != nil {
			s.reports[t.name] = r
			errs = append(errs, ha.PublishLocation(s.pub, t.haTag().ID, *r))
		}
	}
	return errors.Join(errs...)
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

type pendingLogin struct{}

var errLoginNotWired = fmt.Errorf("sign-in is not wired yet; put dsid and searchPartyToken into %s", filepath.Join(addonDataDir, keysDir, authFile))

func (pendingLogin) SignIn(context.Context, string, string) (bool, error) { return false, errLoginNotWired }

func (pendingLogin) SubmitCode(context.Context, string) error { return errLoginNotWired }

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

	f := findmy.NewFetcher(anisette.New(anisetteURL), nil, relogin)
	s := newService(filepath.Join(addonDataDir, keysDir), addonDataDir, f, client)
	go func() {
		log.Fatal(http.ListenAndServe(ingressAddr, &web.Server{Login: pendingLogin{}, KeysDir: s.keysDir, Status: s.Status}))
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
