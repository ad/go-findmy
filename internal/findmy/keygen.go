package findmy

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strings"
)

type KeyFile struct {
	PrivateKey    string `json:"private_key"`
	AdvKey        string `json:"adv_key"`
	HashedKey     string `json:"hashed_key"`
	PrivateKeyHex string `json:"private_key_hex"`
	AdvKeyHex     string `json:"adv_key_hex"`
	MAC           string `json:"mac"`
	Payload       string `json:"payload"`
}

func advertisementTemplate() []byte {
	adv := make([]byte, 31)
	adv[0] = 0x1e
	adv[1] = 0xff
	adv[2] = 0x4c
	adv[3] = 0x00
	adv[4] = 0x12
	adv[5] = 0x19
	adv[6] = 0x00
	for i := 7; i < 29; i++ {
		adv[i] = 0x00
	}
	adv[29] = 0x00
	adv[30] = 0x00
	return adv
}

func generateMACAndPayload(key []byte) (string, string) {
	addr := make([]byte, 6)
	copy(addr, key[:6])
	addr[0] |= 0b11000000

	adv := advertisementTemplate()
	copy(adv[7:29], key[6:28])
	adv[29] = key[0] >> 6

	return fmt.Sprintf("%x", addr), fmt.Sprintf("%x", adv)
}

func NewKeyFile() (KeyFile, error) {
	for {
		privateKey, err := ecdsa.GenerateKey(elliptic.P224(), rand.Reader)
		if err != nil {
			return KeyFile{}, err
		}
		priv, err := privateKey.Bytes()
		if err != nil {
			return KeyFile{}, err
		}
		kf, err := newKeyFile(priv)
		if err != nil {
			return KeyFile{}, err
		}
		if !strings.Contains(kf.HashedKey[:7], "/") {
			return kf, nil
		}
	}
}

func newKeyFile(priv []byte) (KeyFile, error) {
	k, err := ecdsa.ParseRawPrivateKey(elliptic.P224(), priv)
	if err != nil {
		return KeyFile{}, err
	}
	adv := advKey(k)
	mac, payload := generateMACAndPayload(adv)
	return KeyFile{
		PrivateKey:    base64.StdEncoding.EncodeToString(priv),
		AdvKey:        base64.StdEncoding.EncodeToString(adv),
		HashedKey:     hashedKey(adv),
		PrivateKeyHex: hex.EncodeToString(priv),
		AdvKeyHex:     hex.EncodeToString(adv),
		MAC:           mac,
		Payload:       payload,
	}, nil
}

func ReadKeyFile(data []byte) (Key, error) {
	var kf KeyFile
	if err := json.Unmarshal(data, &kf); err != nil {
		return Key{}, err
	}
	priv, err := base64.StdEncoding.DecodeString(kf.PrivateKey)
	if err != nil {
		return Key{}, fmt.Errorf("keys file: private_key: %w", err)
	}
	k, err := ecdsa.ParseRawPrivateKey(elliptic.P224(), priv)
	if err != nil {
		return Key{}, fmt.Errorf("keys file: private_key: %w", err)
	}
	return Key{ID: hashedKey(advKey(k)), Private: priv}, nil
}

func advKey(k *ecdsa.PrivateKey) []byte {
	pub, err := k.PublicKey.Bytes()
	if err != nil {
		panic(err)
	}
	return pub[1:29]
}

func hashedKey(adv []byte) string {
	h := sha256.Sum256(adv)
	return base64.StdEncoding.EncodeToString(h[:])
}
