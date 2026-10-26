package findmy

import (
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"strings"
	"testing"
)

func TestKeyFileMatchesFindMyPy(t *testing.T) {
	want := loadVectors(t).OpenHaystack
	priv, _ := hex.DecodeString(want.Private)
	got, err := newKeyFile(priv)
	if err != nil {
		t.Fatal(err)
	}
	for _, c := range []struct{ name, got, want string }{
		{"private_key_hex", got.PrivateKeyHex, want.Private},
		{"adv_key_hex", got.AdvKeyHex, want.Adv},
		{"hashed_key", got.HashedKey, want.ID},
		{"mac", got.MAC, want.MAC},
		{"payload", got.Payload, want.Payload},
	} {
		if c.got != c.want {
			t.Errorf("%s = %s, want %s", c.name, c.got, c.want)
		}
	}
}

func TestNewKeyFileHasNoSlashInHashPrefix(t *testing.T) {
	for range 200 {
		k, err := NewKeyFile()
		if err != nil {
			t.Fatal(err)
		}
		if strings.Contains(k.HashedKey[:7], "/") {
			t.Fatalf("hashed_key %s has / in the first 7 chars", k.HashedKey)
		}
	}
}

func TestReadKeyFileUsesPrivateKey(t *testing.T) {
	want := loadVectors(t).OpenHaystack
	priv, _ := hex.DecodeString(want.Private)

	generated, err := NewKeyFile()
	if err != nil {
		t.Fatal(err)
	}
	genPriv, _ := base64.StdEncoding.DecodeString(generated.PrivateKey)
	stale := KeyFile{PrivateKey: base64.StdEncoding.EncodeToString(priv), HashedKey: generated.HashedKey}

	for _, c := range []struct {
		name   string
		file   KeyFile
		wantID string
		priv   []byte
	}{
		{"generated", generated, generated.HashedKey, genPriv},
		{"stale hashed_key", stale, want.ID, priv},
	} {
		t.Run(c.name, func(t *testing.T) {
			data, _ := json.Marshal(c.file)
			k, err := ReadKeyFile(data)
			if err != nil {
				t.Fatal(err)
			}
			if k.ID != c.wantID || hex.EncodeToString(k.Private) != hex.EncodeToString(c.priv) {
				t.Errorf("got id %s private %x, want %s %x", k.ID, k.Private, c.wantID, c.priv)
			}
		})
	}
}

func TestReadKeyFileRejectsLegacyAdvKey(t *testing.T) {
	kf, err := NewKeyFile()
	if err != nil {
		t.Fatal(err)
	}
	kf.AdvKey = base64.StdEncoding.EncodeToString(make([]byte, 57))
	data, _ := json.Marshal(kf)
	if _, err := ReadKeyFile(data); !errors.Is(err, ErrLegacyKeyFile) {
		t.Errorf("err = %v, want ErrLegacyKeyFile", err)
	}
}

func TestReadKeyFileRejectsBadPrivateKey(t *testing.T) {
	for name, data := range map[string]string{
		"not json":    `{`,
		"not base64":  `{"private_key":"!!"}`,
		"short key":   `{"private_key":"AQID"}`,
		"missing key": `{"hashed_key":"x"}`,
		"zero key":    `{"private_key":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=="}`,
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := ReadKeyFile([]byte(data)); err == nil {
				t.Error("ReadKeyFile accepted it")
			}
		})
	}
}
