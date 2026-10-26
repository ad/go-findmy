package anisette

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func fakeSidecar(t *testing.T, handler http.HandlerFunc) *Sidecar {
	t.Helper()
	srv := httptest.NewServer(handler)
	t.Cleanup(srv.Close)
	return New(srv.URL)
}

func TestHeadersAreFetchedOnEveryCall(t *testing.T) {
	calls := 0
	s := fakeSidecar(t, func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet || r.URL.Path != "/headers" {
			t.Errorf("got %s %s, want GET /headers", r.Method, r.URL.Path)
		}
		calls++
		fmt.Fprintf(w, `{"X-Apple-I-MD":"otp%d","X-Apple-I-MD-M":"mid"}`, calls)
	})

	first, err := s.Headers()
	if err != nil {
		t.Fatal(err)
	}
	second, err := s.Headers()
	if err != nil {
		t.Fatal(err)
	}
	if first["X-Apple-I-MD"] != "otp1" || second["X-Apple-I-MD"] != "otp2" {
		t.Errorf("MD = %q, %q; want otp1, otp2", first["X-Apple-I-MD"], second["X-Apple-I-MD"])
	}
}

func TestHeadersSpellClientInfoTheWayAppleservicesReadsIt(t *testing.T) {
	s := fakeSidecar(t, func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, `{"X-Apple-I-MD":"otp","X-Apple-I-MD-M":"mid","X-MMe-Client-Info":"<MacBookPro13,2>","X-Mme-Device-Id":"00006000-AB"}`)
	})

	h, err := s.Headers()
	if err != nil {
		t.Fatal(err)
	}
	if h["X-Mme-Client-Info"] != "<MacBookPro13,2>" {
		t.Errorf("X-Mme-Client-Info = %q", h["X-Mme-Client-Info"])
	}
	if _, ok := h["X-MMe-Client-Info"]; ok {
		t.Error("X-MMe-Client-Info left in place next to X-Mme-Client-Info")
	}
	if h["X-Mme-Device-Id"] != "00006000-AB" {
		t.Errorf("X-Mme-Device-Id = %q", h["X-Mme-Device-Id"])
	}
}

func TestHeadersFailWithoutOTP(t *testing.T) {
	for _, body := range []string{`{"X-Apple-I-MD-M":"mid"}`, `{"X-Apple-I-MD":"otp"}`} {
		s := fakeSidecar(t, func(w http.ResponseWriter, r *http.Request) { fmt.Fprint(w, body) })
		if _, err := s.Headers(); err == nil {
			t.Errorf("%s: want error", body)
		}
	}
}

func TestHeadersReportSidecarError(t *testing.T) {
	s := fakeSidecar(t, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusServiceUnavailable)
		fmt.Fprint(w, `{"error":"/data/anisette is not provisioned"}`)
	})

	_, err := s.Headers()
	if err == nil || !strings.Contains(err.Error(), "not provisioned") {
		t.Errorf("err = %v, want the sidecar's message", err)
	}
}

func TestResync(t *testing.T) {
	for _, tc := range []struct {
		status  int
		body    string
		wantErr bool
	}{
		{http.StatusOK, `{"result":"revived"}`, false},
		{http.StatusBadGateway, `{"result":"refused"}`, true},
	} {
		s := fakeSidecar(t, func(w http.ResponseWriter, r *http.Request) {
			if r.Method != http.MethodPost || r.URL.Path != "/resync" {
				t.Errorf("got %s %s, want POST /resync", r.Method, r.URL.Path)
			}
			w.WriteHeader(tc.status)
			fmt.Fprint(w, tc.body)
		})
		err := s.Resync()
		if (err != nil) != tc.wantErr {
			t.Errorf("%s: err = %v", tc.body, err)
		}
		if err != nil && !strings.Contains(err.Error(), "refused") {
			t.Errorf("err = %v, want the verdict", err)
		}
	}
}

func TestHeadersAddLocFromLocale(t *testing.T) {
	s := fakeSidecar(t, func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, `{"X-Apple-I-MD":"otp","X-Apple-I-MD-M":"mid","X-Apple-Locale":"en_US"}`)
	})

	h, err := s.Headers()
	if err != nil {
		t.Fatal(err)
	}
	if h["loc"] != "en_US" {
		t.Errorf("loc = %q, want en_US", h["loc"])
	}
}

func TestProvision(t *testing.T) {
	for _, result := range []string{"provisioned", "exists"} {
		s := fakeSidecar(t, func(w http.ResponseWriter, r *http.Request) {
			if r.Method != http.MethodPost || r.URL.Path != "/provision" {
				t.Errorf("got %s %s, want POST /provision", r.Method, r.URL.Path)
			}
			fmt.Fprintf(w, `{"result":%q}`, result)
		})
		fresh, err := s.Provision()
		if err != nil {
			t.Fatal(err)
		}
		if fresh != (result == "provisioned") {
			t.Errorf("%s: fresh = %v", result, fresh)
		}
	}
}
