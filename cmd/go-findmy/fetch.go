package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/ad/go-findmy/internal/anisette"
	"github.com/ad/go-findmy/internal/findmy"
)

const (
	keysDir     = "keys"
	authFile    = "auth.json"
	anisetteURL = "http://127.0.0.1:6969"
)

type auth struct {
	DSID             string `json:"dsid"`
	SearchPartyToken string `json:"searchPartyToken"`
}

func (a auth) SearchPartyAuth() (string, string, error) {
	return a.DSID, a.SearchPartyToken, nil
}

type tag struct {
	name string
	path string
	key  *findmy.Key
	acc  *findmy.Accessory
}

func loadTags(dir string) ([]tag, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, err
	}
	var tags []tag
	for _, e := range entries {
		name := e.Name()
		path := filepath.Join(dir, name)
		if e.IsDir() || strings.HasSuffix(name, authFile) {
			continue
		}
		switch filepath.Ext(name) {
		case ".keys":
			data, err := os.ReadFile(path)
			if err != nil {
				return nil, err
			}
			k, err := findmy.ReadKeyFile(data)
			if errors.Is(err, findmy.ErrLegacyKeyFile) {
				log.Printf("skipping %s: %v", name, err)
				continue
			}
			if err != nil {
				return nil, fmt.Errorf("%s: %w", name, err)
			}
			tags = append(tags, tag{name: name, path: path, key: &k})
		case ".json":
			data, err := os.ReadFile(path)
			if err != nil {
				return nil, err
			}
			a, err := findmy.ParseAccessory(data)
			if err != nil {
				return nil, fmt.Errorf("%s: %w", name, err)
			}
			tags = append(tags, tag{name: name, path: path, acc: a})
		}
	}
	return tags, nil
}

func fetch() {
	tags, err := loadTags(keysDir)
	if err != nil {
		log.Fatal(err)
	}
	a, err := readAuth(keysDir)
	if err != nil {
		log.Fatal(err)
	}

	f := findmy.NewFetcher(anisette.New(anisetteURL), a, relogin)
	out, err := latest(context.Background(), f, tags, time.Now())
	if errors.Is(err, findmy.ErrUnauthorized) {
		log.Fatal(err)
	}
	if err != nil {
		log.Print(err)
	}

	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	if err := enc.Encode(out); err != nil {
		log.Fatal(err)
	}
}

func readAuth(dir string) (auth, error) {
	var a auth
	data, err := os.ReadFile(filepath.Join(dir, authFile))
	if err != nil {
		return a, err
	}
	if err := json.Unmarshal(data, &a); err != nil {
		return a, fmt.Errorf("%s: %w", authFile, err)
	}
	return a, nil
}

func relogin(context.Context) error {
	return fmt.Errorf("token in %s rejected, refresh it", authFile)
}

func latest(ctx context.Context, f *findmy.Fetcher, tags []tag, now time.Time) (map[string]*findmy.Report, error) {
	out := map[string]*findmy.Report{}
	var errs []error

	var static []findmy.Key
	for _, t := range tags {
		if t.key != nil {
			static = append(static, *t.key)
		}
	}
	reports, err := f.LatestStatic(ctx, static, now)
	if errors.Is(err, findmy.ErrUnauthorized) {
		return out, err
	}
	errs = append(errs, err)
	for _, t := range tags {
		if t.key == nil {
			continue
		}
		out[t.name] = nil
		if r, ok := reports[t.key.ID]; ok {
			out[t.name] = &r
		}
	}

	for _, t := range tags {
		if t.acc == nil {
			continue
		}
		r, err := f.LatestAccessory(ctx, t.acc, now)
		if errors.Is(err, findmy.ErrUnauthorized) {
			return out, err
		}
		errs = append(errs, err)
		out[t.name] = r
		if r != nil {
			if err := t.acc.Save(t.path); err != nil {
				errs = append(errs, fmt.Errorf("%s: saving alignment: %w", t.name, err))
			}
		}
	}
	return out, errors.Join(errs...)
}
