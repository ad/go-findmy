package icloud

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"
)

var ctx = context.Background()

func status(fields map[string]any) func() (int, map[string]any) {
	return func() (int, map[string]any) { return 200, fields }
}

func httpStatus(code int) func() (int, map[string]any) {
	return func() (int, map[string]any) { return code, nil }
}

func loggedIn(t *testing.T, apple *fakeApple, an Anisette) (*Account, string) {
	t.Helper()
	dir := t.TempDir()
	a := apple.account(t, dir, an)
	if sf, err := a.Login(ctx, "user@example.com", "hunter2"); err != nil || sf != nil {
		t.Fatalf("login: %v %v", sf, err)
	}
	apple.mu.Lock()
	apple.log = nil
	apple.mu.Unlock()
	return a, dir
}

func TestGSAHeadersSpeakAsTheSidecarMac(t *testing.T) {
	apple := newFakeApple(t, "hunter2")
	loggedIn(t, apple, &fakeAnisette{})
	apple.mu.Lock()
	defer apple.mu.Unlock()
	r := apple.reqs["complete"]
	if ua := r.Header.Get("User-Agent"); ua != "akd/1.0 CFNetwork/1404.0.5 Darwin/22.2.0" {
		t.Errorf("GSA User-Agent = %q", ua)
	}
	if ci := r.Header.Get("X-Mme-Client-Info"); ci != macClientInfo {
		t.Errorf("GSA client info = %q", ci)
	}
	if apple.cpd["X-Apple-I-MD"] == nil || apple.cpd["bootstrap"] != true {
		t.Errorf("cpd lacks anisette or flags: %v", apple.cpd)
	}
	for k := range apple.cpd {
		if strings.EqualFold(k, "X-Mme-Client-Info") {
			t.Error("cpd carries the sidecar client info")
		}
	}
	d := apple.reqs["loginDelegates"]
	if ci := d.Header.Get("X-Mme-Client-Info"); ci != "<MacBookPro13,2> <macOS;13.1;22C65> <com.apple.AOSKit/282 (com.apple.accountsd/113)>" {
		t.Errorf("loginDelegates client info = %q", ci)
	}
	if ua := d.Header.Get("User-Agent"); ua != "com.apple.iCloudHelper/282 CFNetwork/1404.0.5 Darwin/22.2.0" {
		t.Errorf("loginDelegates User-Agent = %q", ua)
	}
	if d.Header.Get("X-Apple-ADSID") != "ADSID" || d.Header.Get("X-Apple-I-MD") == "" {
		t.Errorf("loginDelegates lacks ADSID or anisette: %v", d.Header)
	}
}

func TestFreshAnisettePerRequestAndNoStaleReuse(t *testing.T) {
	apple := newFakeApple(t, "hunter2")
	an := &fakeAnisette{}
	a, _ := loggedIn(t, apple, an)
	if an.calls != 3 {
		t.Errorf("anisette calls = %d for 3 requests", an.calls)
	}
	an.err = errBoom
	if _, err := a.Login(ctx, "user@example.com", "hunter2"); !errors.Is(err, errBoom) {
		t.Errorf("err = %v, want the anisette error", err)
	}
	if got := apple.requests(); len(got) != 0 {
		t.Errorf("sent %v with no anisette", got)
	}
}

func TestRefusalsStopWithCooldownOnDisk(t *testing.T) {
	for _, tc := range []struct {
		name     string
		init     func() (int, map[string]any)
		complete func() (int, map[string]any)
		want     error
		sent     []string
	}{
		{"locked at init", status(map[string]any{"ec": -20209, "hsc": 409, "au": "iForgotAppleIdLocked", "em": "This Apple Account has been locked"}), nil, ErrLocked, []string{"init"}},
		{"wrong password", nil, status(map[string]any{"ec": -22406, "hsc": 401}), ErrBadPassword, []string{"init", "complete"}},
		{"429 at complete", nil, httpStatus(429), ErrThrottled, []string{"init", "complete"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			apple := newFakeApple(t, "hunter2")
			if tc.init != nil {
				apple.initStatus = tc.init
			}
			if tc.complete != nil {
				apple.completeStatus = tc.complete
			}
			dir := t.TempDir()
			clk := &clock{t: time.Date(2026, 10, 26, 18, 0, 0, 0, time.UTC)}
			a := apple.account(t, dir, &fakeAnisette{})
			a.now = clk.now

			sf, err := a.Login(ctx, "user@example.com", "hunter2")
			if !errors.Is(err, tc.want) || sf != nil {
				t.Fatalf("Login = %v, %v; want %v", sf, err, tc.want)
			}
			if tc.want == ErrLocked && !strings.Contains(err.Error(), "iforgot.apple.com") {
				t.Errorf("locked error does not point to iforgot: %v", err)
			}
			if got := apple.requests(); !slices.Equal(got, tc.sent) {
				t.Errorf("requests = %v, want %v", got, tc.sent)
			}

			clk.t = clk.t.Add(44 * time.Minute)
			b := apple.account(t, dir, &fakeAnisette{})
			b.now = clk.now
			if _, err := b.Login(ctx, "user@example.com", "hunter2"); !errors.Is(err, ErrCooldown) {
				t.Errorf("Login in cooldown after reopen = %v", err)
			}
			if err := b.Relogin(ctx); !errors.Is(err, ErrCooldown) {
				t.Errorf("Relogin in cooldown = %v", err)
			}
			if got := apple.requests(); !slices.Equal(got, tc.sent) {
				t.Errorf("cooldown sent %v", got[len(tc.sent):])
			}
		})
	}
}

func TestAutoReloginIsOneAttempt(t *testing.T) {
	for _, tc := range []struct {
		name     string
		complete func() (int, map[string]any)
		want     error
	}{
		{"wrong password", status(map[string]any{"ec": -22406}), ErrBadPassword},
		{"locked", status(map[string]any{"ec": -20209, "hsc": 409, "au": "iForgotAppleIdLocked"}), ErrLocked},
		{"429", httpStatus(429), ErrThrottled},
		{"second factor", status(map[string]any{"ec": 0, "hsc": 409}), errSecondFactor},
		{"unknown refusal", status(map[string]any{"ec": -20101}), nil},
	} {
		t.Run(tc.name, func(t *testing.T) {
			apple := newFakeApple(t, "hunter2")
			a, dir := loggedIn(t, apple, &fakeAnisette{})
			clk := &clock{t: time.Date(2026, 10, 26, 18, 0, 0, 0, time.UTC)}
			a.now = clk.now
			apple.completeStatus = tc.complete

			err := a.Relogin(ctx)
			if err == nil || tc.want != nil && !errors.Is(err, tc.want) {
				t.Fatalf("Relogin = %v, want %v", err, tc.want)
			}
			sent := len(apple.requests())

			clk.t = clk.t.Add(2 * time.Hour)
			apple.completeStatus = status(map[string]any{"ec": 0})
			b := apple.account(t, dir, &fakeAnisette{})
			b.now = clk.now
			for _, acc := range []*Account{a, b} {
				if err := acc.Relogin(ctx); !errors.Is(err, ErrNeedLogin) {
					t.Errorf("second Relogin = %v, want ErrNeedLogin", err)
				}
				if _, _, err := acc.SearchPartyAuth(); !errors.Is(err, ErrNeedLogin) {
					t.Errorf("SearchPartyAuth = %v, want ErrNeedLogin", err)
				}
			}
			if got := apple.requests(); len(got) != sent {
				t.Errorf("after the failed attempt it sent %v", got[sent:])
			}

			if sf, err := b.Login(ctx, "user@example.com", "hunter2"); err != nil || sf != nil {
				t.Fatalf("manual login: %v %v", sf, err)
			}
			if _, _, err := b.SearchPartyAuth(); err != nil {
				t.Errorf("manual login did not clear the stop: %v", err)
			}
		})
	}
}

func TestReloginRefreshesTheToken(t *testing.T) {
	apple := newFakeApple(t, "hunter2")
	a, _ := loggedIn(t, apple, &fakeAnisette{})
	apple.delegates = func() (int, map[string]any) {
		return 200, map[string]any{"dsid": "42", "delegates": map[string]any{"com.apple.mobileme": map[string]any{
			"service-data": map[string]any{"tokens": map[string]any{"searchPartyToken": "spt2"}},
		}}}
	}
	if err := a.Relogin(ctx); err != nil {
		t.Fatal(err)
	}
	if dsid, token, err := a.SearchPartyAuth(); dsid != "42" || token != "spt2" || err != nil {
		t.Errorf("SearchPartyAuth = %q, %q, %v", dsid, token, err)
	}
	if got := apple.requests(); !slices.Equal(got, []string{"init", "complete", "loginDelegates"}) {
		t.Errorf("requests = %v", got)
	}
}

func TestExpiredMachineIsResyncedOnce(t *testing.T) {
	apple := newFakeApple(t, "hunter2")
	expired := true
	apple.initStatus = func() (int, map[string]any) {
		if expired {
			expired = false
			return 200, map[string]any{"ec": -22421, "hsc": 434}
		}
		return 200, map[string]any{"ec": 0}
	}
	an := &fakeAnisette{}
	a := apple.account(t, t.TempDir(), an)
	if _, err := a.Login(ctx, "user@example.com", "hunter2"); err != nil {
		t.Fatal(err)
	}
	if an.resyncs != 1 {
		t.Errorf("resyncs = %d", an.resyncs)
	}

	apple.initStatus = httpStatus(434)
	an.resyncs = 0
	if _, err := a.Login(ctx, "user@example.com", "hunter2"); err == nil {
		t.Error("a machine refused after resync logged in")
	}
	if an.resyncs != 1 {
		t.Errorf("resyncs after a second 434 = %d, want 1", an.resyncs)
	}
}

func TestResyncAtCompleteRestartsFromInit(t *testing.T) {
	apple := newFakeApple(t, "hunter2")
	expired := true
	apple.completeStatus = func() (int, map[string]any) {
		if expired {
			expired = false
			return 434, nil
		}
		return 200, map[string]any{"ec": 0}
	}
	an := &fakeAnisette{}
	a := apple.account(t, t.TempDir(), an)
	if _, err := a.Login(ctx, "user@example.com", "hunter2"); err != nil {
		t.Fatal(err)
	}
	want := []string{"init", "complete", "init", "complete", "loginDelegates"}
	if got := apple.requests(); !slices.Equal(got, want) || an.resyncs != 1 {
		t.Errorf("requests = %v, resyncs = %d; want %v and 1", got, an.resyncs, want)
	}
}

func TestReloginAfterAnyFailureWaitsForCooldown(t *testing.T) {
	apple := newFakeApple(t, "hunter2")
	an := &fakeAnisette{}
	a, _ := loggedIn(t, apple, an)
	clk := &clock{t: time.Date(2026, 10, 26, 18, 0, 0, 0, time.UTC)}
	a.now = clk.now
	apple.srv.Close()

	if err := a.Relogin(ctx); err == nil {
		t.Fatal("Relogin with Apple unreachable succeeded")
	}
	clk.t = clk.t.Add(44 * time.Minute)
	if err := a.Relogin(ctx); !errors.Is(err, ErrCooldown) {
		t.Errorf("second Relogin = %v, want ErrCooldown", err)
	}
}

func TestTokenRejectedRightAfterReloginStops(t *testing.T) {
	apple := newFakeApple(t, "hunter2")
	a, _ := loggedIn(t, apple, &fakeAnisette{})
	clk := &clock{t: time.Date(2026, 10, 26, 18, 0, 0, 0, time.UTC)}
	a.now = clk.now
	if err := a.Relogin(ctx); err != nil {
		t.Fatal(err)
	}
	clk.t = clk.t.Add(15 * time.Minute)
	if err := a.Relogin(ctx); !errors.Is(err, ErrNeedLogin) {
		t.Errorf("Relogin 15 min after a successful one = %v, want ErrNeedLogin", err)
	}
	if got := apple.requests(); len(got) != 3 {
		t.Errorf("requests = %v, want one login", got)
	}
	if _, _, err := a.SearchPartyAuth(); !errors.Is(err, ErrNeedLogin) {
		t.Errorf("SearchPartyAuth = %v", err)
	}
}

func TestThrottledPhoneListCoolsDown(t *testing.T) {
	apple := newFakeApple(t, "hunter2")
	apple.completeStatus = status(map[string]any{"ec": 0, "au": "secondaryAuth"})
	a := apple.account(t, t.TempDir(), &fakeAnisette{})
	sf, err := a.Login(ctx, "user@example.com", "hunter2")
	if err != nil || sf == nil {
		t.Fatalf("Login = %v, %v", sf, err)
	}
	apple.phonesStatus = 429
	if _, err := sf.Phones(ctx); !errors.Is(err, ErrThrottled) {
		t.Fatalf("Phones = %v", err)
	}
	if err := a.Cooldown(); !errors.Is(err, ErrCooldown) {
		t.Errorf("Cooldown = %v", err)
	}
}

func TestLoginDelegatesStatusOneIsNotRetried(t *testing.T) {
	apple := newFakeApple(t, "hunter2")
	apple.delegates = func() (int, map[string]any) {
		return 200, map[string]any{"status": 1, "status-message": "We can not process your request, please try again later"}
	}
	a := apple.account(t, t.TempDir(), &fakeAnisette{})
	_, err := a.Login(ctx, "user@example.com", "hunter2")
	if err == nil || !strings.Contains(err.Error(), "We can not process your request") {
		t.Errorf("err = %v", err)
	}
	if got := apple.requests(); !slices.Equal(got, []string{"init", "complete", "loginDelegates"}) {
		t.Errorf("requests = %v", got)
	}
	if _, _, err := a.SearchPartyAuth(); !errors.Is(err, ErrNeedLogin) {
		t.Errorf("SearchPartyAuth = %v", err)
	}
}

func TestDelegatesWithoutSearchPartyTokenFail(t *testing.T) {
	apple := newFakeApple(t, "hunter2")
	apple.delegates = func() (int, map[string]any) {
		return 200, map[string]any{"dsid": "1", "delegates": map[string]any{"com.apple.mobileme": map[string]any{
			"service-data": map[string]any{"tokens": map[string]any{"mmeAuthToken": "mme"}},
		}}}
	}
	a := apple.account(t, t.TempDir(), &fakeAnisette{})
	if _, err := a.Login(ctx, "user@example.com", "hunter2"); err == nil || !strings.Contains(err.Error(), "searchPartyToken") {
		t.Errorf("err = %v", err)
	}
}

func TestHSC409AtCompleteIsTrustedDeviceSecondFactor(t *testing.T) {
	apple := newFakeApple(t, "hunter2")
	apple.completeStatus = status(map[string]any{"ec": 0, "hsc": 409})
	a := apple.account(t, t.TempDir(), &fakeAnisette{})

	sf, err := a.Login(ctx, "user@example.com", "hunter2")
	if err != nil || sf == nil || !sf.TrustedDevice {
		t.Fatalf("Login = %+v, %v", sf, err)
	}
	if err := sf.RequestTrustedDeviceCode(ctx); err != nil {
		t.Fatal(err)
	}
	apple.codeAccepted = false
	if err := sf.SubmitTrustedDeviceCode(ctx, "000000"); err == nil {
		t.Fatal("wrong code accepted")
	}
	apple.codeAccepted = true
	apple.completeStatus = status(map[string]any{"ec": 0})
	if err := sf.SubmitTrustedDeviceCode(ctx, "123456"); err != nil {
		t.Fatal(err)
	}
	want := []string{"init", "complete", "push", "validate", "validate", "init", "complete", "loginDelegates"}
	if got := apple.requests(); !slices.Equal(got, want) {
		t.Errorf("requests = %v\nwant %v", got, want)
	}
	if apple.header("validate", "security-code") != "123456" {
		t.Errorf("security-code = %q", apple.header("validate", "security-code"))
	}
	if ci := apple.header("push", "X-Mme-Client-Info"); ci != "<MacBookPro13,2> <macOS;13.1;22C65> <com.apple.AOSKit/282 (com.apple.dt.Xcode/3594.4.19)>" {
		t.Errorf("2FA client info = %q", ci)
	}
	if tok := apple.header("push", "X-Apple-Identity-Token"); tok != "QURTSUQ6SURNUw==" {
		t.Errorf("identity token = %q, want b64(ADSID:IDMS)", tok)
	}
	if _, token, err := a.SearchPartyAuth(); token != "spt" || err != nil {
		t.Errorf("SearchPartyAuth = %q, %v", token, err)
	}
}

func TestSMSSecondFactor(t *testing.T) {
	apple := newFakeApple(t, "hunter2")
	apple.completeStatus = status(map[string]any{"ec": 0, "au": "secondaryAuth"})
	a := apple.account(t, t.TempDir(), &fakeAnisette{})

	sf, err := a.Login(ctx, "user@example.com", "hunter2")
	if err != nil || sf == nil || sf.TrustedDevice {
		t.Fatalf("Login = %+v, %v", sf, err)
	}
	phones, err := sf.Phones(ctx)
	if err != nil || len(phones) != 1 || phones[0].ID != 2 {
		t.Fatalf("Phones = %v, %v", phones, err)
	}
	if err := sf.RequestSMSCode(ctx, phones[0].ID); err != nil {
		t.Fatal(err)
	}
	apple.completeStatus = status(map[string]any{"ec": 0})
	if err := sf.SubmitSMSCode(ctx, phones[0].ID, "654321"); err != nil {
		t.Fatal(err)
	}
	apple.mu.Lock()
	sms, code := apple.bodies["sms"], apple.bodies["smscode"]
	apple.mu.Unlock()
	if sms != `{"mode":"sms","phoneNumber":{"id":2}}` {
		t.Errorf("sms body = %s", sms)
	}
	if code != `{"mode":"sms","phoneNumber":{"id":2},"securityCode":{"code":"654321"}}` {
		t.Errorf("sms code body = %s", code)
	}
	if _, token, err := a.SearchPartyAuth(); token != "spt" || err != nil {
		t.Errorf("SearchPartyAuth = %q, %v", token, err)
	}
}

func TestLoginWithoutSecondFactorGetsSearchPartyToken(t *testing.T) {
	for _, sp := range []string{"s2k", "s2k_fo"} {
		t.Run(sp, func(t *testing.T) {
			apple := newFakeApple(t, "hunter2")
			apple.sp = sp
			dir := t.TempDir()
			a := apple.account(t, dir, &fakeAnisette{})

			sf, err := a.Login(context.Background(), "user@example.com", "hunter2")
			if err != nil {
				t.Fatal(err)
			}
			if sf != nil {
				t.Fatal("asked for a second factor")
			}
			if got := apple.requests(); !slices.Equal(got, []string{"init", "complete", "loginDelegates"}) {
				t.Errorf("requests = %v", got)
			}
			dsid, token, err := a.SearchPartyAuth()
			if err != nil || dsid != "1234567890" || token != "spt" {
				t.Errorf("SearchPartyAuth = %q, %q, %v", dsid, token, err)
			}

			info, err := os.Stat(filepath.Join(dir, stateFile))
			if err != nil {
				t.Fatal(err)
			}
			if info.Mode().Perm() != 0o600 {
				t.Errorf("state file mode %v, want 0600", info.Mode().Perm())
			}
			data, _ := os.ReadFile(filepath.Join(dir, stateFile))
			if strings.Contains(string(data), "hunter2") {
				t.Error("plaintext password in the state file")
			}

			reopened, err := Open(dir, &fakeAnisette{err: errBoom})
			if err != nil {
				t.Fatal(err)
			}
			if dsid, token, err := reopened.SearchPartyAuth(); err != nil || dsid != "1234567890" || token != "spt" {
				t.Errorf("after reopen: %q, %q, %v", dsid, token, err)
			}
			if got := apple.requests(); len(got) != 3 {
				t.Errorf("reopen sent requests: %v", got)
			}
		})
	}
}
