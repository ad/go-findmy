package icloud

import (
	"bytes"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"regexp"
	"strconv"
	"strings"

	"howett.net/plist"
)

var (
	ErrThrottled   = errors.New("Apple answered HTTP 429, wait 45 minutes")
	ErrLocked      = errors.New("the Apple ID is locked, unlock it at iforgot.apple.com")
	ErrBadPassword = errors.New("Apple rejected the Apple ID or password")
)

type AppleError struct {
	Op   string
	HTTP int
	EC   int64
	HSC  int64
	AU   string
	EM   string
}

func (e *AppleError) Error() string {
	msg := fmt.Sprintf("icloud: %s refused: http %d ec %d hsc %d", e.Op, e.HTTP, e.EC, e.HSC)
	if e.AU != "" {
		msg += " au " + e.AU
	}
	if e.EM != "" {
		msg += fmt.Sprintf(" %q", e.EM)
	}
	if kind := e.Unwrap(); kind != nil {
		msg += ": " + kind.Error()
	}
	return msg
}

func (e *AppleError) Unwrap() error {
	switch {
	case e.HTTP == http.StatusTooManyRequests:
		return ErrThrottled
	case e.AU == "iForgotAppleIdLocked" || e.EC == -20209:
		return ErrLocked
	case e.EC == -22406:
		return ErrBadPassword
	}
	return nil
}

const (
	bundleAkd       = "com.apple.AuthKit/1 (com.apple.akd/1.0)"
	bundleAccountsd = "com.apple.AOSKit/282 (com.apple.accountsd/113)"
)

// CFNetwork and Darwin of each macOS release the sidecar may claim; a guess would contradict its client info.
var releases = map[string]string{
	"<macOS;13.1;22C65>": "CFNetwork/1404.0.5 Darwin/22.2.0",
}

type identity struct {
	platform string
	network  string
}

var angle = regexp.MustCompile(`<[^>]*>`)

func identityOf(anisette map[string]string) (identity, error) {
	groups := angle.FindAllString(anisette["X-Mme-Client-Info"], 2)
	if len(groups) < 2 {
		return identity{}, fmt.Errorf("icloud: anisette client info %q has no <model> <os;version;build>", anisette["X-Mme-Client-Info"])
	}
	network, ok := releases[groups[1]]
	if !ok {
		return identity{}, fmt.Errorf("icloud: unknown release %s in anisette client info", groups[1])
	}
	return identity{platform: groups[0] + " " + groups[1], network: network}, nil
}

func (id identity) clientInfo(bundle string) string { return id.platform + " <" + bundle + ">" }

func withoutClientInfo(anisette map[string]string) map[string]string {
	out := make(map[string]string, len(anisette))
	for k, v := range anisette {
		if !strings.EqualFold(k, "X-Mme-Client-Info") {
			out[k] = v
		}
	}
	return out
}

func asInt(v any) int64 {
	switch n := v.(type) {
	case int64:
		return n
	case uint64:
		return int64(n)
	}
	return 0
}

func (a *Account) send(req *http.Request) (int, []byte, error) {
	if err := a.cooling(); err != nil {
		return 0, nil, err
	}
	resp, err := a.http.Do(req)
	if err != nil {
		return 0, nil, err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if resp.StatusCode == http.StatusTooManyRequests {
		return 0, nil, &AppleError{Op: req.URL.Path, HTTP: resp.StatusCode}
	}
	return resp.StatusCode, body, err
}

var errResync = errors.New("icloud: anisette resync required")

func (a *Account) gsa(ctx context.Context, op string, params map[string]any) (map[string]any, map[string]any, error) {
	anisette, err := a.anisette.Headers()
	if err != nil {
		return nil, nil, fmt.Errorf("icloud: anisette: %w", err)
	}
	cpd := map[string]any{"bootstrap": true, "icscrec": true, "pbe": false, "prkgen": true, "svct": "iCloud"}
	for k, v := range withoutClientInfo(anisette) {
		cpd[k] = v
	}
	request := map[string]any{"cpd": cpd, "o": op}
	for k, v := range params {
		request[k] = v
	}
	body, err := plist.Marshal(map[string]any{"Header": map[string]any{"Version": "1.0.1"}, "Request": request}, plist.XMLFormat)
	if err != nil {
		return nil, nil, err
	}
	id, err := identityOf(anisette)
	if err != nil {
		return nil, nil, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, a.gsaURL+"/grandslam/GsService2", bytes.NewReader(body))
	if err != nil {
		return nil, nil, err
	}
	req.Close = true
	req.Header.Set("Content-Type", "text/x-xml-plist")
	req.Header.Set("Accept", "*/*")
	req.Header.Set("User-Agent", "akd/1.0 "+id.network)
	req.Header.Set("X-MMe-Client-Info", id.clientInfo(bundleAkd))

	code, data, err := a.send(req)
	if err != nil {
		return nil, nil, err
	}
	if code == 434 {
		return nil, nil, errResync
	}
	var decoded struct {
		Response map[string]any `plist:"Response"`
	}
	if _, err := plist.Unmarshal(data, &decoded); err != nil || decoded.Response == nil {
		return nil, nil, &AppleError{Op: op, HTTP: code, EM: "reply is not a GSA plist"}
	}
	status, _ := decoded.Response["Status"].(map[string]any)
	e := &AppleError{Op: op, HTTP: code, EC: asInt(status["ec"]), HSC: asInt(status["hsc"])}
	e.AU, _ = status["au"].(string)
	e.EM, _ = status["em"].(string)
	switch {
	case e.HSC == 434 || e.EC == -22421:
		return nil, nil, errResync
	case code != http.StatusOK || status == nil || e.EC != 0 || e.Unwrap() != nil:
		return nil, nil, e
	}
	return decoded.Response, status, nil
}

type gsaResult struct {
	adsid, idms, pet string
	secondFactor     bool
	trustedDevice    bool
}

func (a *Account) authenticate(ctx context.Context, user string, digest []byte) (gsaResult, error) {
	r, err := a.srpLogin(ctx, user, digest)
	if !errors.Is(err, errResync) {
		return r, err
	}
	if err := a.anisette.Resync(); err != nil {
		// The sidecar does not say whether Apple refused the resync, so count it as a refusal.
		a.st.CooldownUntil = a.now().Add(cooldown)
		return gsaResult{}, fmt.Errorf("icloud: anisette resync: %w", err)
	}
	r, err = a.srpLogin(ctx, user, digest)
	if errors.Is(err, errResync) {
		return gsaResult{}, &AppleError{Op: "init", HSC: 434, EC: -22421, EM: "machine refused again after resync"}
	}
	return r, err
}

func (a *Account) srpLogin(ctx context.Context, user string, digest []byte) (gsaResult, error) {
	srp, err := newSRP(user)
	if err != nil {
		return gsaResult{}, err
	}
	init, _, err := a.gsa(ctx, "init", map[string]any{"A2k": srp.A.Bytes(), "u": user, "ps": []string{"s2k", "s2k_fo"}})
	if err != nil {
		return gsaResult{}, err
	}
	salt, _ := init["s"].([]byte)
	b, _ := init["B"].([]byte)
	c, _ := init["c"].(string)
	sp, _ := init["sp"].(string)
	iterations := asInt(init["i"])
	if salt == nil || b == nil || c == "" || iterations <= 0 {
		return gsaResult{}, errors.New("icloud: init reply lacks s, B, c or i")
	}
	p, err := srpPassword(digest, salt, int(iterations), sp)
	if err != nil {
		return gsaResult{}, err
	}
	m1, err := srp.m1(salt, b, p)
	if err != nil {
		return gsaResult{}, err
	}
	complete, status, err := a.gsa(ctx, "complete", map[string]any{"c": c, "M1": m1, "u": user})
	if err != nil {
		return gsaResult{}, err
	}
	if m2, _ := complete["M2"].([]byte); !srp.verify(m2) {
		return gsaResult{}, errors.New("icloud: Apple's SRP proof M2 does not match")
	}
	spdData, _ := complete["spd"].([]byte)
	spd, err := decryptSPD(srp.key, spdData)
	if err != nil {
		return gsaResult{}, err
	}

	r := gsaResult{}
	r.adsid, _ = spd["adsid"].(string)
	r.idms, _ = spd["GsIdmsToken"].(string)
	au, _ := status["au"].(string)
	switch {
	case au == "" && asInt(status["hsc"]) == 409, au == "trustedDeviceSecondaryAuth":
		r.secondFactor, r.trustedDevice = true, true
	case au == "secondaryAuth":
		r.secondFactor = true
	case au != "":
		return gsaResult{}, &AppleError{Op: "complete", HTTP: 200, HSC: asInt(status["hsc"]), AU: au, EM: "unknown au"}
	default:
		t, _ := spd["t"].(map[string]any)
		pet, _ := t["com.apple.gs.idms.pet"].(map[string]any)
		r.pet, _ = pet["token"].(string)
		if r.pet == "" {
			return gsaResult{}, errors.New("icloud: session payload has no PET")
		}
	}
	if r.adsid == "" || r.secondFactor && r.idms == "" {
		return gsaResult{}, errors.New("icloud: session payload lacks adsid or GsIdmsToken")
	}
	return r, nil
}

func decryptSPD(key, spd []byte) (map[string]any, error) {
	mac := func(msg string) []byte {
		m := hmac.New(sha256.New, key)
		m.Write([]byte(msg))
		return m.Sum(nil)
	}
	if len(spd) == 0 || len(spd)%aes.BlockSize != 0 {
		return nil, errors.New("icloud: spd length is not a multiple of the AES block")
	}
	block, err := aes.NewCipher(mac("extra data key:"))
	if err != nil {
		return nil, err
	}
	plain := make([]byte, len(spd))
	cipher.NewCBCDecrypter(block, mac("extra data iv:")[:aes.BlockSize]).CryptBlocks(plain, spd)
	n := int(plain[len(plain)-1])
	if n == 0 || n > aes.BlockSize || !bytes.Equal(plain[len(plain)-n:], bytes.Repeat([]byte{byte(n)}, n)) {
		return nil, errors.New("icloud: spd has bad padding")
	}
	var out map[string]any
	if _, err := plist.Unmarshal(plain[:len(plain)-n], &out); err != nil {
		return nil, fmt.Errorf("icloud: spd: %w", err)
	}
	return out, nil
}

func (a *Account) loginDelegates(ctx context.Context, user, adsid, pet string) (dsid string, tokens map[string]string, err error) {
	anisette, err := a.anisette.Headers()
	if err != nil {
		return "", nil, fmt.Errorf("icloud: anisette: %w", err)
	}
	id, err := identityOf(anisette)
	if err != nil {
		return "", nil, err
	}
	clientID, err := base64.StdEncoding.DecodeString(anisette["X-Apple-I-MD-LU"])
	if err != nil || len(clientID) == 0 {
		return "", nil, errors.New("icloud: anisette has no X-Apple-I-MD-LU")
	}
	body, err := plist.Marshal(map[string]any{
		"apple-id":  user,
		"delegates": map[string]any{"com.apple.mobileme": map[string]any{}},
		"password":  pet,
		"client-id": string(clientID),
	}, plist.XMLFormat)
	if err != nil {
		return "", nil, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, a.setupURL+"/setup/iosbuddy/loginDelegates", bytes.NewReader(body))
	if err != nil {
		return "", nil, err
	}
	for k, v := range withoutClientInfo(anisette) {
		req.Header.Set(k, v)
	}
	req.Header.Set("Content-Type", "application/octet-stream")
	req.Header.Set("X-Apple-ADSID", adsid)
	req.Header.Set("User-Agent", "com.apple.iCloudHelper/282 "+id.network)
	req.Header.Set("X-Mme-Client-Info", id.clientInfo(bundleAccountsd))
	req.SetBasicAuth(user, pet)

	code, data, err := a.send(req)
	if err != nil {
		return "", nil, err
	}
	var resp map[string]any
	_, perr := plist.Unmarshal(data, &resp)
	delegates, _ := resp["delegates"].(map[string]any)
	mobileme, _ := delegates["com.apple.mobileme"].(map[string]any)
	sd, _ := mobileme["service-data"].(map[string]any)
	raw, _ := sd["tokens"].(map[string]any)
	if perr != nil || code != http.StatusOK || asInt(resp["status"]) != 0 || resp["localizedError"] != nil || raw["searchPartyToken"] == nil {
		e := &AppleError{Op: "loginDelegates", HTTP: code, EC: asInt(resp["status"])}
		for _, m := range []any{resp["localizedError"], resp["status-message"], mobileme["status-message"]} {
			if s, _ := m.(string); s != "" {
				e.EM = s
				break
			}
		}
		if e.EM == "" && perr == nil {
			e.EM = "no searchPartyToken"
		}
		return "", nil, e
	}
	tokens = map[string]string{}
	for k, v := range raw {
		if s, ok := v.(string); ok {
			tokens[k] = s
		}
	}
	for _, v := range []any{resp["dsid"], sd["dsid"]} {
		if dsid == "" {
			switch d := v.(type) {
			case string:
				dsid = d
			case uint64, int64:
				dsid = strconv.FormatInt(asInt(d), 10)
			}
		}
	}
	if dsid == "" {
		return "", nil, errors.New("icloud: loginDelegates reply has no dsid")
	}
	return dsid, tokens, nil
}

type Phone struct {
	ID     int64
	Number string
}

var bootArgs = regexp.MustCompile(`(?is)<script[^>]*class=["'][^"']*\bboot_args\b[^"']*["'][^>]*>(.*?)</script`)

func (sf *SecondFactor) do(ctx context.Context, method, path string, body []byte, extra map[string]string) ([]byte, error) {
	anisette, err := sf.a.anisette.Headers()
	if err != nil {
		return nil, fmt.Errorf("icloud: anisette: %w", err)
	}
	id, err := identityOf(anisette)
	if err != nil {
		return nil, err
	}
	req, err := http.NewRequestWithContext(ctx, method, sf.a.gsaURL+path, bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	for k, v := range withoutClientInfo(anisette) {
		req.Header.Set(k, v)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", "Xcode")
	req.Header.Set("Accept-Language", "en-us")
	req.Header.Set("X-Apple-Identity-Token", base64.StdEncoding.EncodeToString([]byte(sf.adsid+":"+sf.idms)))
	req.Header.Set("X-Mme-Client-Info", id.clientInfo(bundleAkd))
	req.Header.Set("X-Apple-App-Info", "com.apple.gs.xcode.auth")
	req.Header.Set("X-Xcode-Version", "11.2 (11B41)")
	for k, v := range extra {
		req.Header.Set(k, v)
	}
	code, data, err := sf.a.send(req)
	if err != nil {
		return nil, err
	}
	if code < 200 || code > 299 {
		return nil, &AppleError{Op: path, HTTP: code}
	}
	return data, nil
}

var plistNegotiation = map[string]string{"Content-Type": "text/x-xml-plist", "Accept": "text/x-xml-plist"}

func (sf *SecondFactor) Phones(ctx context.Context) ([]Phone, error) {
	var page []byte
	err := sf.run(ctx, func() (err error) {
		page, err = sf.do(ctx, http.MethodGet, "/auth", nil, nil)
		return err
	}, false)
	if err != nil {
		return nil, err
	}
	m := bootArgs.FindSubmatch(page)
	if m == nil {
		return nil, errors.New("icloud: no boot_args on the 2FA page")
	}
	var args struct {
		Direct struct {
			PhoneNumberVerification struct {
				TrustedPhoneNumbers []struct {
					ID     int64  `json:"id"`
					Number string `json:"numberWithDialCode"`
				} `json:"trustedPhoneNumbers"`
			} `json:"phoneNumberVerification"`
		} `json:"direct"`
	}
	if err := json.Unmarshal(m[1], &args); err != nil {
		return nil, fmt.Errorf("icloud: boot_args: %w", err)
	}
	var phones []Phone
	for _, p := range args.Direct.PhoneNumberVerification.TrustedPhoneNumbers {
		phones = append(phones, Phone{ID: p.ID, Number: p.Number})
	}
	return phones, nil
}

func smsBody(phoneID int64, code string) []byte {
	body := map[string]any{"phoneNumber": map[string]any{"id": phoneID}, "mode": "sms"}
	if code != "" {
		body["securityCode"] = map[string]any{"code": code}
	}
	data, _ := json.Marshal(body)
	return data
}
