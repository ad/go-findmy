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
	data, err := os.ReadFile(filepath.Join(keysDir, authFile))
	if err != nil {
		log.Fatal(err)
	}
	var a auth
	if err := json.Unmarshal(data, &a); err != nil {
		log.Fatalf("%s: %v", authFile, err)
	}

	f := findmy.NewFetcher(anisette.New(anisetteURL), a, func(context.Context) error {
		return fmt.Errorf("token in %s rejected, refresh it", authFile)
	})
	ctx := context.Background()
	now := time.Now()
	out := map[string]*findmy.Report{}

	var static []findmy.Key
	for _, t := range tags {
		if t.key != nil {
			static = append(static, *t.key)
		}
	}
	reports, err := f.LatestStatic(ctx, static, now)
	checkFetch(err)
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
		checkFetch(err)
		out[t.name] = r
		if r != nil {
			if err := t.acc.Save(t.path); err != nil {
				log.Printf("%s: saving alignment: %v", t.name, err)
			}
		}
	}

	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	if err := enc.Encode(out); err != nil {
		log.Fatal(err)
	}
}

func checkFetch(err error) {
	if errors.Is(err, findmy.ErrUnauthorized) {
		log.Fatal(err)
	}
	if err != nil {
		log.Print(err)
	}
}
