package gsa

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/pbkdf2"
	"crypto/sha256"
	"errors"
	"fmt"
	"math/big"
	"net/http/cookiejar"
	"strings"
	"time"

	nethttp "net/http"

	"github.com/Laky-64/http"

	"github.com/Laky-64/appleservices/internal/srp"
	"howett.net/plist"
)

const anisetteMaxAge = 60 * time.Second

type Client struct {
	anisette              AnisetteProvider
	transport             nethttp.RoundTripper
	cookieJar             *cookiejar.Jar
	cachedAnisetteHeaders map[string]string
	anisetteFetchedAt     time.Time
}

func (c *Client) anisetteHeaders() (map[string]string, error) {
	if c.cachedAnisetteHeaders != nil && time.Since(c.anisetteFetchedAt) < anisetteMaxAge {
		return c.cachedAnisetteHeaders, nil
	}
	return c.refreshAnisetteHeaders()
}

func (c *Client) refreshAnisetteHeaders() (map[string]string, error) {
	h, err := c.anisette.Headers()
	if err != nil {
		if c.cachedAnisetteHeaders != nil {
			return c.cachedAnisetteHeaders, nil
		}
		return nil, fmt.Errorf("gsa: anisette headers: %w", err)
	}
	c.cachedAnisetteHeaders = h
	c.anisetteFetchedAt = time.Now()
	return h, nil
}

func (c *Client) AnisetteHeaders() (map[string]string, error) {
	return c.anisetteHeaders()
}

const gsaBaseURL = "https://gsa.apple.com"

func NewClient(anisette AnisetteProvider) *Client {
	jar, _ := cookiejar.New(nil)
	return &Client{
		anisette:  anisette,
		transport: AppleRootTransport(),
		cookieJar: jar,
	}
}

type LoginResult struct {
	NeedsTwoFactor  bool
	TwoFactorMethod string
	SessionPayload  map[string]any
}

func caseInsensitiveLookup(headers map[string]string, name string) string {
	for k, v := range headers {
		if strings.EqualFold(k, name) {
			return v
		}
	}
	return ""
}

func (c *Client) doRequest(request map[string]any) (map[string]any, error) {
	body := map[string]any{
		"Header":  map[string]any{"Version": "1.0.1"},
		"Request": request,
	}
	var buf bytes.Buffer
	if err := plist.NewEncoder(&buf).Encode(body); err != nil {
		return nil, fmt.Errorf("gsa: encode request: %w", err)
	}

	anisetteHeaders, err := c.anisetteHeaders()
	if err != nil {
		return nil, err
	}
	headers := map[string]string{
		"Content-Type": "text/x-xml-plist",
		"Accept":       "*/*",
		"User-Agent":   "akd/1.0 CFNetwork/978.0.7 Darwin/18.7.0",
	}
	if ua := caseInsensitiveLookup(anisetteHeaders, "User-Agent"); ua != "" {
		headers["User-Agent"] = ua
	}
	if ci := caseInsensitiveLookup(anisetteHeaders, "X-Mme-Client-Info"); ci != "" {
		headers["X-Mme-Client-Info"] = ci
	}

	result, err := http.ExecuteRequest(gsaBaseURL+"/grandslam/GsService2",
		http.Method("POST"),
		http.Body(buf.Bytes()),
		http.Headers(headers),
		http.Transport(c.transport),
		http.CookieJar(c.cookieJar),
		http.Timeout(30*time.Second),
	)
	if err != nil {
		return nil, fmt.Errorf("gsa: request failed: %w", err)
	}
	if result.StatusCode != 200 {
		return nil, fmt.Errorf("gsa: request status %d", result.StatusCode)
	}

	var decoded map[string]any
	if _, err := plist.Unmarshal(result.Body, &decoded); err != nil {
		return nil, fmt.Errorf("gsa: decode response: %w", err)
	}
	respMap, ok := decoded["Response"].(map[string]any)
	if !ok {
		return nil, errors.New("gsa: response missing Response dict")
	}
	return respMap, nil
}

func asInt64(v any) (int64, bool) {
	switch n := v.(type) {
	case int64:
		return n, true
	case uint64:
		return int64(n), true
	default:
		return 0, false
	}
}

func (c *Client) buildCPD() (map[string]any, error) {
	h, err := c.anisetteHeaders()
	if err != nil {
		return nil, err
	}
	cpd := map[string]any{
		"bootstrap": true,
		"icscrec":   true,
		"pbe":       false,
		"prkgen":    true,
		"svct":      "iCloud",
	}
	for k, v := range h {
		cpd[k] = v
	}
	return cpd, nil
}

func derivePasswordKey(password string, protocol string, salt []byte, iterations int) ([]byte, error) {
	p1 := sha256.Sum256([]byte(password))
	var p2 []byte
	if protocol == "s2k_fo" {
		p2 = []byte(fmt.Sprintf("%x", p1))
	} else {
		p2 = p1[:]
	}
	return pbkdf2.Key(sha256.New, string(p2), salt, iterations, 32)
}

func hmacSHA256(key, msg []byte) []byte {
	h := hmac.New(sha256.New, key)
	h.Write(msg)
	return h.Sum(nil)
}

func pkcs7Unpad(data []byte, blockSize int) ([]byte, error) {
	if len(data) == 0 || len(data)%blockSize != 0 {
		return nil, errors.New("gsa: spd ciphertext length invalid for PKCS7")
	}
	padLen := int(data[len(data)-1])
	if padLen == 0 || padLen > blockSize || padLen > len(data) {
		return nil, errors.New("gsa: spd invalid PKCS7 padding length")
	}
	for _, b := range data[len(data)-padLen:] {
		if int(b) != padLen {
			return nil, errors.New("gsa: spd invalid PKCS7 padding bytes")
		}
	}
	return data[:len(data)-padLen], nil
}

func decryptSPD(sessionKey, spd []byte) (map[string]any, error) {
	key := hmacSHA256(sessionKey, []byte("extra data key:"))
	iv := hmacSHA256(sessionKey, []byte("extra data iv:"))[:aes.BlockSize]

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("gsa: spd aes cipher: %w", err)
	}
	if len(spd)%aes.BlockSize != 0 {
		return nil, errors.New("gsa: spd ciphertext not a multiple of the AES block size")
	}
	plain := make([]byte, len(spd))
	cipher.NewCBCDecrypter(block, iv).CryptBlocks(plain, spd)

	unpadded, err := pkcs7Unpad(plain, aes.BlockSize)
	if err != nil {
		return nil, err
	}

	var decoded map[string]any
	if _, err := plist.Unmarshal(unpadded, &decoded); err != nil {
		return nil, fmt.Errorf("gsa: spd plist decode: %w", err)
	}
	return decoded, nil
}

func (c *Client) Login(username, password string) (*LoginResult, error) {
	params := srp.NewParams()
	client := srp.NewClient(params, username)

	if _, err := c.refreshAnisetteHeaders(); err != nil {
		return nil, err
	}

	initCPD, err := c.buildCPD()
	if err != nil {
		return nil, err
	}
	initResp, err := c.doRequest(map[string]any{
		"cpd": initCPD,
		"A2k": client.PublicA().Bytes(),
		"ps":  []string{"s2k", "s2k_fo"},
		"u":   username,
		"o":   "init",
	})
	if err != nil {
		return nil, fmt.Errorf("gsa: init request: %w", err)
	}
	initStatus, _ := initResp["Status"].(map[string]any)
	if initStatus == nil {
		return nil, errors.New("gsa: init response missing Status")
	}
	ec, ok := asInt64(initStatus["ec"])
	if !ok {
		return nil, errors.New("gsa: could not parse ec/i as integer")
	}
	if ec != 0 {
		em, _ := initStatus["em"].(string)
		return nil, fmt.Errorf("gsa: init rejected, ec=%v em=%q", ec, em)
	}

	protocol, _ := initResp["sp"].(string)
	salt, _ := initResp["s"].([]byte)
	iterations, ok := asInt64(initResp["i"])
	if !ok {
		return nil, errors.New("gsa: could not parse ec/i as integer")
	}
	challengeID, _ := initResp["c"].(string)
	bBytes, _ := initResp["B"].([]byte)
	if salt == nil || bBytes == nil || challengeID == "" {
		return nil, errors.New("gsa: init response missing required fields")
	}
	B := new(big.Int).SetBytes(bBytes)

	passwordKey, err := derivePasswordKey(password, protocol, salt, int(iterations))
	if err != nil {
		return nil, fmt.Errorf("gsa: derive password key: %w", err)
	}
	x := params.DeriveX(salt, passwordKey)

	m1, sessionKey, err := client.ProcessChallenge(x, salt, B)
	if err != nil {
		return nil, fmt.Errorf("gsa: process challenge: %w", err)
	}

	completeCPD, err := c.buildCPD()
	if err != nil {
		return nil, err
	}
	completeResp, err := c.doRequest(map[string]any{
		"cpd": completeCPD,
		"c":   challengeID,
		"M1":  m1,
		"u":   username,
		"o":   "complete",
	})
	if err != nil {
		return nil, fmt.Errorf("gsa: complete request: %w", err)
	}
	status, _ := completeResp["Status"].(map[string]any)
	if status == nil {
		return nil, errors.New("gsa: complete response missing Status")
	}
	completeEC, ok := asInt64(status["ec"])
	if !ok {
		return nil, errors.New("gsa: could not parse ec/i as integer")
	}
	if completeEC != 0 {
		em, _ := status["em"].(string)
		return nil, fmt.Errorf("gsa: complete rejected, ec=%v em=%q (wrong password or account issue)", completeEC, em)
	}

	m2, _ := completeResp["M2"].([]byte)
	if m2 == nil {
		return nil, errors.New("gsa: complete response missing M2")
	}
	if err := client.VerifyServer(m2); err != nil {
		return nil, fmt.Errorf("gsa: server proof invalid: %w", err)
	}

	var sessionPayload map[string]any
	if spd, _ := completeResp["spd"].([]byte); len(spd) > 0 {
		sessionPayload, err = decryptSPD(sessionKey, spd)
		if err != nil {
			return nil, fmt.Errorf("gsa: decrypt spd: %w", err)
		}
	}

	au, _ := status["au"].(string)
	needsTwoFactor := au == "trustedDeviceSecondaryAuth" || au == "secondaryAuth"

	return &LoginResult{NeedsTwoFactor: needsTwoFactor, TwoFactorMethod: au, SessionPayload: sessionPayload}, nil
}
