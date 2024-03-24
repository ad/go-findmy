package main

import (
	"bytes"
	"crypto/aes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"math/big"
	"net/http"
	"os"
	"path/filepath"
	"time"

	"github.com/AlanQuatermain/go-gcm"
	"github.com/google/uuid"
)

const (
	ANISETTE_URL = "http://localhost:6969"
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

type Auth struct {
	DSID             string `json:"dsid"`
	SearchPartyToken string `json:"searchPartyToken"`
	Username         string `json:"username"`
	Password         string `json:"password"`
}

type SearchRequest struct {
	Search []Search `json:"search"`
}

type Search struct {
	StartDate int64    `json:"startDate"`
	EndDate   int64    `json:"endDate"`
	Ids       []string `json:"ids"`
}

type Results struct {
	Results    []Result `json:"results"`
	StatusCode string   `json:"statusCode"`
}

type Result struct {
	DatePublished int64  `json:"datePublished"`
	Payload       string `json:"payload"`
	Description   string `json:"description"`
	ID            string `json:"id"`
	StatusCode    int    `json:"statusCode"`
}

type Tag struct {
	Lat         float64 `json:"lat"`
	Lon         float64 `json:"lon"`
	Confidence  int     `json:"conf"`
	Status      int     `json:"status"`
	Timestamp   int64   `json:"timestamp"`
	Isodatetime string  `json:"isodatetime"`
	Key         string  `json:"key"`
	Goog        string  `json:"goog"`
}

func main() {
	privkeys, err := loadKeysFromFiles()
	if err != nil {
		log.Fatal(err)
	}

	var auth Auth

	// configPath := filepath.Join(filepath.Dir(os.Args[0]), "keys", "auth.json")
	configPath := filepath.Join(".", "keys", "auth.json")
	// fmt.Printf("Config path: %s\n", configPath)
	if _, err := os.Stat(configPath); err == nil {
		file, err := ioutil.ReadFile(configPath)
		if err != nil {
			log.Fatal(err)
		}

		err = json.Unmarshal(file, &auth)
		if err != nil {
			log.Fatal(err)
		}

		// fmt.Printf("DSID: %s\n SearchPartyToken %s\n", auth.DSID, auth.SearchPartyToken)
	}

	authToken := base64.StdEncoding.EncodeToString([]byte(auth.DSID + ":" + auth.SearchPartyToken))

	endDate := time.Now().UnixMilli()
	startdate := endDate - (60 * 60 * 24 * 1000) // reports for the last hour

	keys := []string{}
	for k := range privkeys {
		keys = append(keys, k)
	}

	search := SearchRequest{
		Search: []Search{
			{
				StartDate: startdate,
				EndDate:   endDate,
				Ids:       keys,
			},
		},
	}

	jsonStr, err := json.Marshal(search)
	if err != nil {
		log.Fatal(err)
	}

	// fmt.Printf("Search: %s\n", jsonStr)

	url := "https://gateway.icloud.com/acsnservice/fetch"
	// fmt.Println("URL:>", url)

	headers := generateAnisetteHeaders()

	req, err := http.NewRequest("POST", url, bytes.NewBuffer(jsonStr))
	if err != nil {
		log.Fatal(err)
	}

	// req.Header.Set("X-Apple-ADSID", auth.DSID)
	req.Header.Set("Authorization", "Basic "+authToken)
	// req.Header.Set("Content-Type", "application/json")
	for key, value := range headers {
		req.Header.Set(key, value)
	}

	// fmt.Printf("Headers: %v\n", headers)
	// fmt.Printf("Headers: %v\n", req.Header)

	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		panic(err)
	}
	defer resp.Body.Close()
	// fmt.Println("response Status:", resp.Status)
	// fmt.Println("response Headers:", resp.Header)
	body, _ := io.ReadAll(resp.Body)
	// fmt.Println("response Body:", string(body))

	if resp.StatusCode == 200 {
		results := Results{}
		err = json.Unmarshal(body, &results)
		if err != nil {
			log.Fatal(err)
		}

		fmt.Printf("Results count before filter by timestamp: %v\n", len(results.Results))

		ordered := make([]Tag, 0)

		names := map[string]string{}

		for _, report := range results.Results {
			privBytes, _ := base64.StdEncoding.DecodeString(privkeys[report.ID])
			if err != nil {
				fmt.Println(err)

				continue
			}

			data, _ := base64.StdEncoding.DecodeString(report.Payload)

			timestamp := int64(binary.BigEndian.Uint32(data[0:4])) + 978307200

			if timestamp > (startdate / 1000) {
				encData := data[62:72]
				authTag := data[72:]
				curve := elliptic.P224()
				priv, err := ReadPrivateKeyFromHex(hex.EncodeToString(privBytes))
				if err != nil {
					fmt.Println(err)
					return
				}

				x, y := elliptic.Unmarshal(curve, data[5:62])
				ephKey := &ecdsa.PublicKey{Curve: curve, X: x, Y: y}

				b, _ := ephKey.Curve.ScalarMult(ephKey.X, ephKey.Y, priv.D.Bytes())

				dataToHash := append(b.Bytes(), append([]byte{0x00, 0x00, 0x00, 0x01}, data[5:62]...)...)
				hash := sha256.Sum256(dataToHash)

				decryptionKey := hash[:16]
				iv := hash[16:]

				decrypted, err := decryptAes(decryptionKey, iv, encData, authTag)
				if err != nil {
					fmt.Println(err)
					continue
				}

				tag := decodeTag([]byte(decrypted))
				tag.Timestamp = int64(binary.BigEndian.Uint32(data[0:4])) + 978307200
				tag.Isodatetime = time.Unix(tag.Timestamp, 0).Format(time.RFC3339)
				tag.Key = names[report.ID]
				tag.Goog = fmt.Sprintf("https://maps.google.com/maps?q=%f,%f", tag.Lat, tag.Lon)

				ordered = append(ordered, tag)
			}
		}

		result, err := json.Marshal(ordered)
		if err != nil {
			log.Fatal(err)
		}

		fmt.Printf("Result: %s\n", result)
	}
}

func generateAnisetteHeaders() map[string]string {
	resp, err := http.Get(ANISETTE_URL)
	if err != nil {
		log.Fatal(err)
	}
	defer resp.Body.Close()

	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		log.Fatal(err)
	}

	var h map[string]string
	err = json.Unmarshal(body, &h)
	if err != nil {
		log.Fatal(err)
	}

	userID := uuid.New().String()
	deviceID := uuid.New().String()

	metaHeaders := generateMetaHeaders(userID, deviceID)
	metaHeaders["X-Apple-I-MD"] = h["X-Apple-I-MD"]
	metaHeaders["X-Apple-I-MD-M"] = h["X-Apple-I-MD-M"]

	return metaHeaders
}

func generateMetaHeaders(userID string, deviceID string) map[string]string {
	return map[string]string{
		"X-Apple-I-Client-Time": time.Now().UTC().Format("2006-01-02T15:04:05Z"),
		"X-Apple-I-TimeZone":    "MSK", //time.Now().UTC().Format("MST"),
		"loc":                   "en_US",
		"X-Apple-Locale":        "en_US",
		"X-Apple-I-MD-RINFO":    "17106176",
		"X-Apple-I-MD-LU":       base64.StdEncoding.EncodeToString([]byte(userID)),
		"X-Mme-Device-Id":       deviceID,
		"X-Apple-I-SRL-NO":      "0",
	}
}

func decodeTag(data []byte) Tag {
	latitude := float64(int32(binary.BigEndian.Uint32(data[0:4]))) / 10000000.0
	longitude := float64(int32(binary.BigEndian.Uint32(data[4:8]))) / 10000000.0
	confidence := int(data[8])
	status := int(data[9])

	return Tag{
		Lat:        latitude,
		Lon:        longitude,
		Confidence: confidence,
		Status:     status,
	}
}

func decryptAes(decryptionKey, iv, encData, authTag []byte) (decrypted []byte, err error) {
	blockCipher, err := aes.NewCipher(decryptionKey)
	if err != nil {
		return nil, err
	}

	gcmD, err := gcm.NewGCM(blockCipher, 128, iv)
	if err != nil {
		return nil, err
	}

	decrypted, err = gcmD.Decrypt(encData, nil, authTag)
	if err != nil {
		return nil, err
	}

	return decrypted, nil
}

func ReadPrivateKeyFromHex(Dhex string) (*ecdsa.PrivateKey, error) {
	c := elliptic.P256()
	d, err := hex.DecodeString(Dhex)
	if err != nil {
		return nil, err
	}
	k := new(big.Int).SetBytes(d)
	params := c.Params()
	one := new(big.Int).SetInt64(1)
	n := new(big.Int).Sub(params.N, one)
	if k.Cmp(n) >= 0 {
		return nil, errors.New("privateKey's D is overflow")
	}
	priv := new(ecdsa.PrivateKey)
	priv.PublicKey.Curve = c
	priv.D = k
	priv.PublicKey.X, priv.PublicKey.Y = c.ScalarBaseMult(k.Bytes())
	return priv, nil
}

func loadKeysFromFiles() (map[string]string, error) {
	privkeys := make(map[string]string)

	files, err := ioutil.ReadDir("./keys")
	if err != nil {
		return privkeys, err
	}

	for _, file := range files {
		if file.IsDir() {
			continue
		}

		filename := file.Name()
		if filepath.Ext(filename) == ".keys" {
			key, err := ioutil.ReadFile(filepath.Join("keys", filename))
			if err != nil {
				return privkeys, err
			}

			var keyFile KeyFile

			json.Unmarshal(key, &keyFile)

			privkeys[keyFile.HashedKey] = keyFile.PrivateKey
		}
	}

	return privkeys, nil
}
