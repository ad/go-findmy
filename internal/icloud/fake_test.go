package icloud

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/pbkdf2"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"howett.net/plist"
)

const macClientInfo = "<MacBookPro13,2> <macOS;13.1;22C65> <com.apple.AuthKit/1 (com.apple.akd/1.0)>"

type fakeAnisette struct {
	mu        sync.Mutex
	calls     int
	resyncs   int
	err       error
	resyncErr error
}

func (f *fakeAnisette) Headers() (map[string]string, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.err != nil {
		return nil, f.err
	}
	f.calls++
	return map[string]string{
		"X-Apple-I-MD":      fmt.Sprintf("otp%d", f.calls),
		"X-Apple-I-MD-M":    "mid",
		"X-Apple-I-MD-LU":   base64.StdEncoding.EncodeToString([]byte("LOCAL-USER")),
		"X-Mme-Client-Info": macClientInfo,
		"X-Mme-Device-Id":   "00006000-0123456789ABCDEF",
	}, nil
}

func (f *fakeAnisette) Resync() error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.resyncs++
	return f.resyncErr
}

// SRP here uses the server-side equations, so a client that only agrees with itself fails.
type fakeApple struct {
	t        *testing.T
	srv      *httptest.Server
	password string
	sp       string

	mu     sync.Mutex
	log    []string
	reqs   map[string]*http.Request
	bodies map[string]string
	cpd    map[string]any

	initStatus     func() (int, map[string]any)
	completeStatus func() (int, map[string]any)
	delegates      func() (int, map[string]any)
	codeAccepted   bool
	phonesStatus   int

	salt []byte
	a, b *big.Int
	v    *big.Int
	bigB *big.Int
}

func newFakeApple(t *testing.T, password string) *fakeApple {
	f := &fakeApple{t: t, password: password, sp: "s2k", reqs: map[string]*http.Request{}, bodies: map[string]string{}, codeAccepted: true}
	f.initStatus = func() (int, map[string]any) { return 200, map[string]any{"ec": 0} }
	f.completeStatus = func() (int, map[string]any) { return 200, map[string]any{"ec": 0} }
	f.delegates = func() (int, map[string]any) {
		return 200, map[string]any{
			"status": 0,
			"dsid":   uint64(1234567890),
			"delegates": map[string]any{"com.apple.mobileme": map[string]any{
				"status": 0,
				"service-data": map[string]any{"tokens": map[string]any{
					"searchPartyToken": "spt", "mmeAuthToken": "mme", "cloudKitToken": "ck",
				}},
			}},
		}
	}
	mux := http.NewServeMux()
	mux.HandleFunc("POST /grandslam/GsService2", f.gsa)
	mux.HandleFunc("POST /setup/iosbuddy/loginDelegates", f.loginDelegates)
	mux.HandleFunc("GET /auth", f.authPage)
	mux.HandleFunc("GET /auth/verify/trusteddevice", f.ok("push"))
	mux.HandleFunc("GET /grandslam/GsService2/validate", f.validate)
	mux.HandleFunc("PUT /auth/verify/phone", f.ok("sms"))
	mux.HandleFunc("POST /auth/verify/phone/securitycode", f.ok("smscode"))
	f.srv = httptest.NewServer(mux)
	t.Cleanup(f.srv.Close)
	return f
}

func (f *fakeApple) account(t *testing.T, dir string, an Anisette) *Account {
	t.Helper()
	a, err := Open(dir, an)
	if err != nil {
		t.Fatal(err)
	}
	a.gsaURL, a.setupURL, a.http = f.srv.URL, f.srv.URL, f.srv.Client()
	return a
}

func (f *fakeApple) record(name string, r *http.Request) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.log = append(f.log, name)
	f.reqs[name] = r
}

func (f *fakeApple) requests() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]string(nil), f.log...)
}

func (f *fakeApple) header(name, key string) string {
	f.mu.Lock()
	defer f.mu.Unlock()
	if r := f.reqs[name]; r != nil {
		return r.Header.Get(key)
	}
	return ""
}

func (f *fakeApple) ok(name string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		f.record(name, r)
		f.mu.Lock()
		f.bodies[name] = string(body)
		f.mu.Unlock()
	}
}

func writePlist(w http.ResponseWriter, status int, v any) {
	data, err := plist.Marshal(v, plist.XMLFormat)
	if err != nil {
		panic(err)
	}
	w.WriteHeader(status)
	w.Write(data)
}

func sum(parts ...[]byte) []byte {
	h := sha256.New()
	for _, p := range parts {
		h.Write(p)
	}
	return h.Sum(nil)
}

func padN(b []byte) []byte { return append(make([]byte, 256-len(b)), b...) }

func (f *fakeApple) gsa(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Header  map[string]any `plist:"Header"`
		Request map[string]any `plist:"Request"`
	}
	data, _ := io.ReadAll(r.Body)
	if _, err := plist.Unmarshal(data, &body); err != nil {
		f.t.Errorf("gsa body: %v", err)
	}
	op, _ := body.Request["o"].(string)
	f.record(op, r)
	f.mu.Lock()
	f.cpd, _ = body.Request["cpd"].(map[string]any)
	f.mu.Unlock()

	n, _ := new(big.Int).SetString(srpN, 16)
	g := big.NewInt(2)
	switch op {
	case "init":
		code, status := f.initStatus()
		if code != 200 {
			w.WriteHeader(code)
			return
		}
		f.a = new(big.Int).SetBytes(body.Request["A2k"].([]byte))
		f.salt = []byte("0123456789abcdef")
		digest := sha256.Sum256([]byte(f.password))
		p := digest[:]
		if f.sp == "s2k_fo" {
			p = []byte(hex.EncodeToString(digest[:]))
		}
		key, _ := pbkdf2.Key(sha256.New, string(p), f.salt, 1000, 32)
		x := new(big.Int).SetBytes(sum(f.salt, sum([]byte(":"), key)))
		f.v = new(big.Int).Exp(g, x, n)
		f.b, _ = rand.Int(rand.Reader, n)
		k := new(big.Int).SetBytes(sum(n.Bytes(), padN(g.Bytes())))
		f.bigB = new(big.Int).Mod(new(big.Int).Add(new(big.Int).Mul(k, f.v), new(big.Int).Exp(g, f.b, n)), n)
		writePlist(w, 200, map[string]any{"Response": map[string]any{
			"Status": status, "sp": f.sp, "s": f.salt, "i": 1000, "B": f.bigB.Bytes(), "c": "challenge",
		}})
	case "complete":
		code, status := f.completeStatus()
		if code != 200 {
			w.WriteHeader(code)
			return
		}
		u := new(big.Int).SetBytes(sum(padN(f.a.Bytes()), padN(f.bigB.Bytes())))
		s := new(big.Int).Exp(new(big.Int).Mul(f.a, new(big.Int).Exp(f.v, u, n)), f.b, n)
		key := sum(s.Bytes())
		hn, hg := sum(n.Bytes()), sum(padN(g.Bytes()))
		for i := range hn {
			hn[i] ^= hg[i]
		}
		user, _ := body.Request["u"].(string)
		m1 := sum(hn, sum([]byte(user)), f.salt, f.a.Bytes(), f.bigB.Bytes(), key)
		if !bytes.Equal(m1, body.Request["M1"].([]byte)) {
			writePlist(w, 200, map[string]any{"Response": map[string]any{
				"Status": map[string]any{"ec": -22406, "em": "Enter the correct password", "hsc": 401},
			}})
			return
		}
		spd, _ := plist.Marshal(map[string]any{
			"adsid": "ADSID", "GsIdmsToken": "IDMS",
			"t": map[string]any{"com.apple.gs.idms.pet": map[string]any{"token": "pet"}},
		}, plist.XMLFormat)
		writePlist(w, 200, map[string]any{"Response": map[string]any{
			"Status": status, "M2": sum(f.a.Bytes(), m1, key), "spd": encryptSPD(key, spd),
		}})
	default:
		f.t.Errorf("unexpected GSA op %q", op)
	}
}

func encryptSPD(key, plain []byte) []byte {
	mac := func(msg string) []byte {
		h := hmac.New(sha256.New, key)
		h.Write([]byte(msg))
		return h.Sum(nil)
	}
	pad := aes.BlockSize - len(plain)%aes.BlockSize
	plain = append(plain, bytes.Repeat([]byte{byte(pad)}, pad)...)
	block, _ := aes.NewCipher(mac("extra data key:"))
	out := make([]byte, len(plain))
	cipher.NewCBCEncrypter(block, mac("extra data iv:")[:aes.BlockSize]).CryptBlocks(out, plain)
	return out
}

func (f *fakeApple) loginDelegates(w http.ResponseWriter, r *http.Request) {
	f.record("loginDelegates", r)
	user, pass, _ := r.BasicAuth()
	var body map[string]any
	data, _ := io.ReadAll(r.Body)
	plist.Unmarshal(data, &body)
	if pass != "pet" || user != body["apple-id"] || body["password"] != "pet" || body["client-id"] != "LOCAL-USER" {
		f.t.Errorf("loginDelegates auth %q/%q body %v", user, pass, body)
	}
	code, resp := f.delegates()
	writePlist(w, code, resp)
}

func (f *fakeApple) authPage(w http.ResponseWriter, r *http.Request) {
	f.record("auth", r)
	if f.phonesStatus != 0 {
		w.WriteHeader(f.phonesStatus)
		return
	}
	args, _ := json.Marshal(map[string]any{"direct": map[string]any{"phoneNumberVerification": map[string]any{
		"trustedPhoneNumbers": []map[string]any{{"id": 2, "numberWithDialCode": "+7 •••-••-12"}},
	}}})
	fmt.Fprintf(w, `<html><script type="application/json" class="boot_args">%s</script></html>`, args)
}

func (f *fakeApple) validate(w http.ResponseWriter, r *http.Request) {
	f.record("validate", r)
	ec := 0
	if !f.codeAccepted {
		ec = -21669
	}
	writePlist(w, 200, map[string]any{"Status": map[string]any{"ec": ec, "em": "Incorrect verification code."}})
}

var errBoom = errors.New("boom")

type clock struct{ t time.Time }

func (c *clock) now() time.Time { return c.t }
