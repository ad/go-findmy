package findmy

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
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

func convertKeyToHex(privateKey *ecdsa.PrivateKey, publicKey *ecdsa.PublicKey) (string, string) {
	privateKeyBytes := privateKey.D.Bytes()
	publicKeyBytes := elliptic.Marshal(publicKey.Curve, publicKey.X, publicKey.Y)
	privateKeyHex := fmt.Sprintf("%x", privateKeyBytes)
	publicKeyHex := fmt.Sprintf("%x", publicKeyBytes)
	return privateKeyHex, publicKeyHex
}

func generateMACAndPayload(publicKey *ecdsa.PublicKey) (string, string) {
	key := elliptic.Marshal(publicKey.Curve, publicKey.X, publicKey.Y)

	addr := make([]byte, 6)
	copy(addr, key[:6])
	addr[0] |= 0b11000000

	adv := advertisementTemplate()
	copy(adv[7:29], key[6:28])
	adv[29] = key[0] >> 6

	return fmt.Sprintf("%x", addr), fmt.Sprintf("%x", adv)
}

func NewKeyFile() (KeyFile, error) {
	privateKey, err := ecdsa.GenerateKey(elliptic.P224(), rand.Reader)
	if err != nil {
		return KeyFile{}, err
	}
	publicKey := &privateKey.PublicKey

	privateKeyBytes := privateKey.D.Bytes()
	publicKeyBytes := elliptic.Marshal(publicKey.Curve, publicKey.X, publicKey.Y)

	privateKeyHex, publicKeyHex := convertKeyToHex(privateKey, publicKey)
	mac, payload := generateMACAndPayload(publicKey)

	publicKeyHash := sha256.Sum256(publicKeyBytes)

	return KeyFile{
		PrivateKey:    base64.StdEncoding.EncodeToString(privateKeyBytes),
		AdvKey:        base64.StdEncoding.EncodeToString(publicKeyBytes),
		HashedKey:     base64.StdEncoding.EncodeToString(publicKeyHash[:]),
		PrivateKeyHex: privateKeyHex,
		AdvKeyHex:     publicKeyHex,
		MAC:           mac,
		Payload:       payload,
	}, nil
}
