package main

import (
	"encoding/json"
	"fmt"
	"os"

	"github.com/ad/go-findmy/internal/findmy"
)

func keygen() {
	var nkeys int
	fmt.Print("Enter the number of keys to generate [1 by default]: ")
	fmt.Scanln(&nkeys)

	if nkeys <= 0 {
		nkeys = 1
	}

	var prefix string
	fmt.Print("Enter a prefix for the keyfiles (optional, press enter to skip): ")
	fmt.Scanln(&prefix)

	if _, err := os.Stat("keys"); os.IsNotExist(err) {
		os.Mkdir("keys", 0755)
	}

	for i := 0; i < nkeys; i++ {
		for {
			keyData, err := findmy.NewKeyFile()
			if err != nil {
				fmt.Println("Error generating private key:", err)
				return
			}

			if keyData.HashedKey[:7] != "/" {
				fname := fmt.Sprintf("%s_%s.keys", prefix, keyData.MAC)
				if prefix == "" {
					fname = fmt.Sprintf("%s.keys", keyData.MAC)
				}

				fmt.Println(i + 1)
				fmt.Println("Private key (Base64):", keyData.PrivateKey)
				fmt.Println("Public key (Base64):", keyData.AdvKey)
				fmt.Println("Hashed adv key (Base64):", keyData.HashedKey)
				fmt.Println("---------------------------------------------------------------------------------")
				fmt.Println("Private key (Hex):", keyData.PrivateKeyHex)
				fmt.Println("Public key (Hex):", keyData.AdvKeyHex)
				fmt.Println("---------------------------------------------------------------------------------")
				fmt.Println("MAC:", keyData.MAC)
				fmt.Println("Payload:", keyData.Payload)
				fmt.Println()

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
