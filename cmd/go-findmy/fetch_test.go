package main

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"log"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/ad/go-findmy/internal/findmy"
)

func TestLoadTagsSkipsLegacyKeysWithWarning(t *testing.T) {
	dir := t.TempDir()
	write := func(name string, v any) {
		data, err := json.Marshal(v)
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(dir, name), data, 0o600); err != nil {
			t.Fatal(err)
		}
	}

	good, err := findmy.NewKeyFile()
	if err != nil {
		t.Fatal(err)
	}
	write("good.keys", good)
	write("old.keys", findmy.KeyFile{
		PrivateKey: good.PrivateKey,
		AdvKey:     base64.StdEncoding.EncodeToString(make([]byte, 57)),
	})
	write(authFile, map[string]string{"dsid": "1", "searchPartyToken": "t"})
	write("example."+authFile, map[string]string{})

	var vectors struct{ Accessory json.RawMessage }
	raw, err := os.ReadFile("../../internal/findmy/testdata/findmypy-22e4879.json")
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(raw, &vectors); err != nil {
		t.Fatal(err)
	}
	write("airtag.json", vectors.Accessory)

	var logged bytes.Buffer
	log.SetOutput(&logged)
	t.Cleanup(func() { log.SetOutput(os.Stderr) })

	tags, err := loadTags(dir)
	if err != nil {
		t.Fatal(err)
	}
	var names []string
	for _, tg := range tags {
		names = append(names, tg.name)
	}
	if strings.Join(names, ",") != "airtag.json,good.keys" {
		t.Errorf("tags %v, want airtag.json and good.keys", names)
	}
	if !strings.Contains(logged.String(), "old.keys") {
		t.Errorf("no warning about old.keys in log: %q", logged.String())
	}
}
