package icloud

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/cookiejar"
	"os"
	"path/filepath"
	"sync"
	"time"

	"howett.net/plist"
)

const (
	stateFile = "account.json"
	cooldown  = 45 * time.Minute
)

var (
	ErrNeedLogin = errors.New("icloud: login needed, run go-findmy login")
	ErrCooldown  = errors.New("icloud: cooldown after Apple refused, nothing is sent to Apple")
)

type Anisette interface {
	Headers() (map[string]string, error)
	Resync() error
}

type state struct {
	AppleID        string            `json:"appleId,omitempty"`
	PasswordSHA256 []byte            `json:"passwordSha256,omitempty"`
	DSID           string            `json:"dsid,omitempty"`
	ADSID          string            `json:"adsid,omitempty"`
	Tokens         map[string]string `json:"tokens,omitempty"`
	NeedLogin      string            `json:"needLogin,omitempty"`
	CooldownUntil  time.Time         `json:"cooldownUntil,omitzero"`
	ReloginAt      time.Time         `json:"reloginAt,omitzero"`
}

type Account struct {
	mu       sync.Mutex
	path     string
	anisette Anisette
	st       state

	http     *http.Client
	gsaURL   string
	setupURL string
	now      func() time.Time
}

func Open(dir string, anisette Anisette) (*Account, error) {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, err
	}
	jar, _ := cookiejar.New(nil)
	a := &Account{
		path:     filepath.Join(dir, stateFile),
		anisette: anisette,
		http:     &http.Client{Jar: jar, Timeout: 30 * time.Second},
		gsaURL:   "https://gsa.apple.com",
		setupURL: "https://setup.icloud.com",
		now:      time.Now,
	}
	data, err := os.ReadFile(a.path)
	if errors.Is(err, os.ErrNotExist) {
		return a, nil
	}
	if err != nil {
		return nil, err
	}
	if err := json.Unmarshal(data, &a.st); err != nil {
		return nil, fmt.Errorf("icloud: %s: %w", a.path, err)
	}
	return a, nil
}

func (a *Account) save() error {
	data, err := json.MarshalIndent(a.st, "", "  ")
	if err != nil {
		return err
	}
	tmp, err := os.CreateTemp(filepath.Dir(a.path), stateFile+".*")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name())
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmp.Name(), a.path)
}

func (a *Account) cooling() error {
	if until := a.st.CooldownUntil; a.now().Before(until) {
		return fmt.Errorf("%w until %s: %s", ErrCooldown, until.UTC().Format(time.RFC3339), a.st.NeedLogin)
	}
	return nil
}

// Refusals persist across restarts: a retry loop is what locked the user's Apple ID.
func (a *Account) settle(err error, auto bool) error {
	if err == nil || errors.Is(err, ErrCooldown) {
		return err
	}
	if auto {
		a.st.CooldownUntil = a.now().Add(cooldown)
	}
	var refused *AppleError
	switch {
	case errors.Is(err, ErrThrottled), errors.Is(err, ErrLocked), errors.Is(err, ErrBadPassword):
		a.st.CooldownUntil = a.now().Add(cooldown)
		a.st.NeedLogin = err.Error()
	case auto && (errors.As(err, &refused) || errors.Is(err, errSecondFactor)):
		a.st.NeedLogin = err.Error()
	}
	return errors.Join(err, a.save())
}

func (a *Account) Cooldown() error {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.cooling()
}

func (a *Account) SearchPartyAuth() (dsid, token string, err error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.st.NeedLogin != "" {
		return "", "", fmt.Errorf("%w: %s", ErrNeedLogin, a.st.NeedLogin)
	}
	if a.st.Tokens["searchPartyToken"] == "" {
		return "", "", ErrNeedLogin
	}
	return a.st.DSID, a.st.Tokens["searchPartyToken"], nil
}

func (a *Account) Login(ctx context.Context, appleID, password string) (*SecondFactor, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	digest := sha256.Sum256([]byte(password))
	r, err := a.authenticate(ctx, appleID, digest[:])
	if err != nil {
		return nil, a.settle(err, false)
	}
	if r.secondFactor {
		return &SecondFactor{a: a, appleID: appleID, digest: digest[:], adsid: r.adsid, idms: r.idms, TrustedDevice: r.trustedDevice}, nil
	}
	return nil, a.settle(a.finish(ctx, appleID, digest[:], r), false)
}

var errSecondFactor = errors.New("icloud: Apple asks for a second factor")

func (a *Account) Relogin(ctx context.Context) error {
	a.mu.Lock()
	defer a.mu.Unlock()
	if err := a.cooling(); err != nil {
		return err
	}
	if a.st.NeedLogin != "" || a.st.PasswordSHA256 == nil {
		return fmt.Errorf("%w: %s", ErrNeedLogin, a.st.NeedLogin)
	}
	if at := a.st.ReloginAt; !at.IsZero() && a.now().Before(at.Add(cooldown)) {
		a.st.NeedLogin = "Apple rejected the token of the relogin at " + at.UTC().Format(time.RFC3339)
		return errors.Join(fmt.Errorf("%w: %s", ErrNeedLogin, a.st.NeedLogin), a.save())
	}
	r, err := a.authenticate(ctx, a.st.AppleID, a.st.PasswordSHA256)
	if err == nil && r.secondFactor {
		err = errSecondFactor
	}
	if err == nil {
		err = a.finish(ctx, a.st.AppleID, a.st.PasswordSHA256, r)
	}
	if err != nil {
		return a.settle(err, true)
	}
	a.st.ReloginAt = a.now()
	return a.save()
}

func (a *Account) finish(ctx context.Context, appleID string, digest []byte, r gsaResult) error {
	dsid, tokens, err := a.loginDelegates(ctx, appleID, r.adsid, r.pet)
	if err != nil {
		return err
	}
	a.st = state{AppleID: appleID, PasswordSHA256: digest, DSID: dsid, ADSID: r.adsid, Tokens: tokens}
	return a.save()
}

type SecondFactor struct {
	a             *Account
	appleID       string
	digest        []byte
	adsid, idms   string
	TrustedDevice bool
}

func (sf *SecondFactor) run(ctx context.Context, step func() error, done bool) error {
	sf.a.mu.Lock()
	defer sf.a.mu.Unlock()
	err := step()
	if err == nil && done {
		var r gsaResult
		r, err = sf.a.authenticate(ctx, sf.appleID, sf.digest)
		if err == nil && r.secondFactor {
			err = errors.New("icloud: Apple still asks for a second factor, the code was not accepted")
		}
		if err == nil {
			err = sf.a.finish(ctx, sf.appleID, sf.digest, r)
		}
	}
	return sf.a.settle(err, false)
}

func (sf *SecondFactor) RequestTrustedDeviceCode(ctx context.Context) error {
	return sf.run(ctx, func() error {
		_, err := sf.do(ctx, http.MethodGet, "/auth/verify/trusteddevice", nil, plistNegotiation)
		return err
	}, false)
}

func (sf *SecondFactor) SubmitTrustedDeviceCode(ctx context.Context, code string) error {
	return sf.run(ctx, func() error {
		extra := map[string]string{"security-code": code}
		for k, v := range plistNegotiation {
			extra[k] = v
		}
		data, err := sf.do(ctx, http.MethodGet, "/grandslam/GsService2/validate", nil, extra)
		if err != nil {
			return err
		}
		var reply struct {
			Status struct {
				EC int64  `plist:"ec"`
				EM string `plist:"em"`
			} `plist:"Status"`
		}
		if _, err := plist.Unmarshal(data, &reply); err == nil && reply.Status.EC != 0 {
			return &AppleError{Op: "validate", HTTP: 200, EC: reply.Status.EC, EM: reply.Status.EM}
		}
		return nil
	}, true)
}

func (sf *SecondFactor) RequestSMSCode(ctx context.Context, phoneID int64) error {
	return sf.run(ctx, func() error {
		_, err := sf.do(ctx, http.MethodPut, "/auth/verify/phone", smsBody(phoneID, ""), nil)
		return err
	}, false)
}

func (sf *SecondFactor) SubmitSMSCode(ctx context.Context, phoneID int64, code string) error {
	return sf.run(ctx, func() error {
		_, err := sf.do(ctx, http.MethodPost, "/auth/verify/phone/securitycode", smsBody(phoneID, code), nil)
		return err
	}, true)
}
