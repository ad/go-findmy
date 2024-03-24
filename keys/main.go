package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
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
	adv[0] = 0x1e // length (30)
	adv[1] = 0xff // manufacturer specific data
	adv[2] = 0x4c // company ID (Apple)
	adv[3] = 0x00 // company ID (Apple)
	adv[4] = 0x12 // offline finding type and length
	adv[5] = 0x19 // offline finding type and length
	adv[6] = 0x00 // state
	for i := 7; i < 29; i++ {
		adv[i] = 0x00
	}
	adv[29] = 0x00 // first two bits of key[0]
	adv[30] = 0x00 // hint
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

func main() {
	var nkeys int
	fmt.Print("Enter the number of keys to generate [1 by default]: ")
	fmt.Scanln(&nkeys)

	if nkeys <= 0 {
		nkeys = 1
	}

	var prefix string
	fmt.Print("Enter a prefix for the keyfiles (optional, press enter to skip): ")
	fmt.Scanln(&prefix)

	if prefix == "" {
		prefix = ""
	}

	if _, err := os.Stat("keys"); os.IsNotExist(err) {
		os.Mkdir("keys", 0755)
	}

	for i := 0; i < nkeys; i++ {
		for {
			privateKey, err := ecdsa.GenerateKey(elliptic.P224(), rand.Reader)
			if err != nil {
				fmt.Println("Error generating private key:", err)
				return
			}
			publicKey := &privateKey.PublicKey

			privateKeyBytes := privateKey.D.Bytes()
			publicKeyBytes := elliptic.Marshal(publicKey.Curve, publicKey.X, publicKey.Y)

			privateKeyB64 := base64.StdEncoding.EncodeToString(privateKeyBytes)
			publicKeyB64 := base64.StdEncoding.EncodeToString(publicKeyBytes)

			privateKeyHex, publicKeyHex := convertKeyToHex(privateKey, publicKey)
			mac, payload := generateMACAndPayload(publicKey)

			publicKeyHash := sha256.Sum256(publicKeyBytes)
			s256B64 := base64.StdEncoding.EncodeToString(publicKeyHash[:])

			if s256B64[:7] != "/" {
				fname := fmt.Sprintf("%s_%s.keys", prefix, mac)
				if prefix == "" {
					fname = fmt.Sprintf("%s.keys", mac)
				}

				fmt.Println(i + 1)
				fmt.Println("Private key (Base64):", privateKeyB64)
				fmt.Println("Public key (Base64):", publicKeyB64)
				fmt.Println("Hashed adv key (Base64):", s256B64)
				fmt.Println("---------------------------------------------------------------------------------")
				fmt.Println("Private key (Hex):", privateKeyHex)
				fmt.Println("Public key (Hex):", publicKeyHex)
				fmt.Println("---------------------------------------------------------------------------------")
				fmt.Println("MAC:", mac)
				fmt.Println("Payload:", payload)
				fmt.Println()

				// keysContent := fmt.Sprintf("Private key: %s\nAdvertisement key: %s\nHashed adv key: %s\nPrivate key (Hex): %s\nAdvertisement key (Hex): %s\nMAC: %s\nPayload: %s\n",
				// 	privateKeyB64, publicKeyB64, s256B64, privateKeyHex, publicKeyHex, mac, payload)
				keyData := KeyFile{
					PrivateKey:    privateKeyB64,
					AdvKey:        publicKeyB64,
					HashedKey:     s256B64,
					PrivateKeyHex: privateKeyHex,
					AdvKeyHex:     publicKeyHex,
					MAC:           mac,
					Payload:       payload,
				}

				keyDataString, err := json.Marshal(keyData)
				if err != nil {
					fmt.Println("Error marshalling key data:", err)
					return
				}

				err = os.WriteFile(fmt.Sprintf("keys/%s", fname), []byte(keyDataString), 0644)
				if err != nil {
					fmt.Println("Error saving keys file:", err)
					return
				}
				fmt.Println("Keys file saved to:", fmt.Sprintf("keys/%s", fname))
				fmt.Println()
				break
			}
		}
	}
}
