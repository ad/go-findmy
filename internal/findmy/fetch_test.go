package findmy

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"slices"
	"testing"
	"time"
)

type fakeAnisette struct{ calls int }

func (a *fakeAnisette) Headers() (map[string]string, error) {
	a.calls++
	return map[string]string{
		"X-Apple-I-MD":      "otp",
		"X-Apple-I-MD-M":    "machine",
		"X-MMe-Client-Info": "<MacBookPro18,3> <Mac OS X;13.4.1;22F8>",
	}, nil
}

type fakeCreds struct{ dsid, token string }

func (c *fakeCreds) SearchPartyAuth() (string, string, error) { return c.dsid, c.token, nil }

type sleepLog []time.Duration

func (s *sleepLog) sleep(_ context.Context, d time.Duration) error {
	*s = append(*s, d)
	return nil
}

func newTestFetcher(t *testing.T, h http.HandlerFunc) (*Fetcher, *sleepLog) {
	t.Helper()
	srv := httptest.NewServer(h)
	t.Cleanup(srv.Close)
	f := NewFetcher(&fakeAnisette{}, &fakeCreds{"123", "tok"}, nil)
	f.URL = srv.URL
	f.HTTP = srv.Client()
	sl := &sleepLog{}
	f.Sleep = sl.sleep
	return f, sl
}

func payloadResponse(id string, payloads ...string) string {
	b, _ := json.Marshal(map[string]any{"acsnLocations": map[string]any{
		"statusCode":      "200",
		"locationPayload": []map[string]any{{"id": id, "locationInfo": payloads}},
	}})
	return string(b)
}

func TestFetchStaticSendsV2RequestAndDecrypts(t *testing.T) {
	v, priv := loadReportVectors(t)
	now := time.Date(2026, 10, 26, 12, 0, 0, 0, time.UTC)
	other := Key{ID: "b3RoZXI=", Private: priv}

	var body struct {
		ClientContext map[string]string `json:"clientContext"`
		Fetch         []map[string]any  `json:"fetch"`
	}
	f, _ := newTestFetcher(t, func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			t.Errorf("method %s", r.Method)
		}
		if u, p, ok := r.BasicAuth(); !ok || u != "123" || p != "tok" {
			t.Errorf("basic auth %q %q %v", u, p, ok)
		}
		if r.Header.Get("X-Apple-I-MD") != "otp" || r.Header.Get("X-Apple-I-MD-M") != "machine" {
			t.Errorf("anisette headers missing: %v", r.Header)
		}
		if r.Header.Get("X-Mme-Client-Info") != "" {
			t.Errorf("client info sent: %q", r.Header.Get("X-Mme-Client-Info"))
		}
		if r.Header.Get("Content-Type") != "application/json" {
			t.Errorf("content type %q", r.Header.Get("Content-Type"))
		}
		raw, _ := io.ReadAll(r.Body)
		if err := json.Unmarshal(raw, &body); err != nil {
			t.Errorf("body %s: %v", raw, err)
		}
		io.WriteString(w, payloadResponse(v.ID, v.Reports[0].Payload, v.Reports[1].Payload))
	})

	got, err := f.LatestStatic(context.Background(), []Key{{ID: v.ID, Private: priv}, other}, now)
	if err != nil {
		t.Fatal(err)
	}

	want := map[string]string{
		"clientBundleIdentifier": "com.apple.icloud.searchpartyuseragent",
		"policy":                 "foregroundClient",
	}
	for k, w := range want {
		if body.ClientContext[k] != w {
			t.Errorf("clientContext[%s] = %q, want %q", k, body.ClientContext[k], w)
		}
	}
	if len(body.Fetch) != 2 {
		t.Fatalf("%d fetch entries, want one per key", len(body.Fetch))
	}
	end := float64(now.UnixMilli())
	start := float64(now.Add(-7 * 24 * time.Hour).UnixMilli())
	e := body.Fetch[0]
	if e["keyType"] != 1.0 || e["startDate"] != start || e["startDateSecondary"] != start || e["endDate"] != end {
		t.Errorf("entry dates/type: %v", e)
	}
	if ids, _ := e["primaryIds"].([]any); len(ids) != 1 || ids[0] != v.ID {
		t.Errorf("primaryIds %v", e["primaryIds"])
	}
	for _, k := range []string{"secondaryIds", "ownedDeviceIds"} {
		if l, ok := e[k].([]any); !ok || len(l) != 0 {
			t.Errorf("%s = %v, want []", k, e[k])
		}
	}

	r, ok := got[v.ID]
	if !ok {
		t.Fatalf("no report for %s: %v", v.ID, got)
	}
	if r.Time.Unix() != v.Reports[1].Timestamp || r.Latitude != v.Reports[1].Latitude {
		t.Errorf("latest = %+v, want the report at %d", r, v.Reports[1].Timestamp)
	}
	if _, ok := got[other.ID]; ok {
		t.Errorf("report for a key without payloads")
	}
}

func staticKey(t *testing.T) Key {
	v, priv := loadReportVectors(t)
	return Key{ID: v.ID, Private: priv}
}

func seconds(s ...int) sleepLog {
	out := sleepLog{}
	for _, n := range s {
		out = append(out, time.Duration(n)*time.Second)
	}
	return out
}

func TestFetchRetriesEmptyResponse(t *testing.T) {
	v, _ := loadReportVectors(t)
	for _, tc := range []struct {
		name       string
		okAt       int
		wantErr    error
		wantSleeps sleepLog
	}{
		{"recovers", 3, nil, seconds(2, 4)},
		{"gives up after 5 retries", 0, ErrEmptyResponse, seconds(2, 4, 6, 8, 10)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			calls := 0
			f, sl := newTestFetcher(t, func(w http.ResponseWriter, r *http.Request) {
				calls++
				if calls == tc.okAt {
					io.WriteString(w, payloadResponse(v.ID, v.Reports[0].Payload))
				}
			})
			got, err := f.LatestStatic(context.Background(), []Key{staticKey(t)}, time.Now())
			if !errors.Is(err, tc.wantErr) {
				t.Fatalf("err %v, want %v", err, tc.wantErr)
			}
			if tc.wantErr == nil && len(got) != 1 {
				t.Errorf("reports %v", got)
			}
			if want := len(tc.wantSleeps) + 1; calls != want {
				t.Errorf("%d requests, want %d", calls, want)
			}
			if an := f.Anisette.(*fakeAnisette); an.calls != calls {
				t.Errorf("%d anisette fetches for %d requests", an.calls, calls)
			}
			if !slices.Equal(*sl, tc.wantSleeps) {
				t.Errorf("sleeps %v, want %v", *sl, tc.wantSleeps)
			}
		})
	}
}

func TestFetch401ReloginsOnceAndRetries(t *testing.T) {
	v, _ := loadReportVectors(t)
	creds := &fakeCreds{"123", "old"}
	var tokens []string
	f, _ := newTestFetcher(t, func(w http.ResponseWriter, r *http.Request) {
		_, p, _ := r.BasicAuth()
		tokens = append(tokens, p)
		if p != "new" {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		io.WriteString(w, payloadResponse(v.ID, v.Reports[0].Payload))
	})
	f.Credentials = creds
	relogins := 0
	f.Relogin = func(context.Context) error {
		relogins++
		creds.token = "new"
		return nil
	}

	got, err := f.LatestStatic(context.Background(), []Key{staticKey(t)}, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 || relogins != 1 || !slices.Equal(tokens, []string{"old", "new"}) {
		t.Errorf("reports %d, relogins %d, tokens %v", len(got), relogins, tokens)
	}
}

func TestFetch401LoginNeeded(t *testing.T) {
	reloginErr := errors.New("2fa required")
	for _, tc := range []struct {
		name         string
		relogin      error
		wantRequests int
	}{
		{"relogin fails", reloginErr, 1},
		{"still 401 after relogin", nil, 2},
	} {
		t.Run(tc.name, func(t *testing.T) {
			calls := 0
			f, _ := newTestFetcher(t, func(w http.ResponseWriter, r *http.Request) {
				calls++
				w.WriteHeader(http.StatusUnauthorized)
			})
			relogins := 0
			f.Relogin = func(context.Context) error {
				relogins++
				return tc.relogin
			}
			_, err := f.LatestStatic(context.Background(), []Key{staticKey(t)}, time.Now())
			if !errors.Is(err, ErrUnauthorized) {
				t.Fatalf("err %v, want ErrUnauthorized", err)
			}
			if tc.relogin != nil && !errors.Is(err, tc.relogin) {
				t.Errorf("err %v does not carry the relogin error", err)
			}
			if calls != tc.wantRequests || relogins != 1 {
				t.Errorf("%d requests, %d relogins; want %d and 1", calls, relogins, tc.wantRequests)
			}
		})
	}
}

func sealReport(t *testing.T, priv []byte, at time.Time, lat int32) string {
	t.Helper()
	curve := elliptic.P224()
	recipient, err := ecdsa.ParseRawPrivateKey(curve, priv)
	if err != nil {
		t.Fatal(err)
	}
	eph, err := ecdsa.GenerateKey(curve, rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	ephPub, _ := eph.PublicKey.Bytes()
	x, _ := curve.ScalarMult(recipient.X, recipient.Y, eph.D.Bytes())
	h := sha256.Sum256(slices.Concat(x.FillBytes(make([]byte, 28)), []byte{0, 0, 0, 1}, ephPub))
	block, _ := aes.NewCipher(h[:16])
	gcm, _ := cipher.NewGCMWithNonceSize(block, 16)
	plain := binary.BigEndian.AppendUint32(nil, uint32(lat))
	plain = append(plain, 0, 0, 0, 0, 10, 0)
	payload := binary.BigEndian.AppendUint32(nil, uint32(at.Unix()-appleEpoch))
	payload = append(payload, 1)
	payload = append(payload, ephPub...)
	payload = gcm.Seal(payload, h[16:], plain, nil)
	return base64.StdEncoding.EncodeToString(payload)
}

func TestFetchAccessoryStopsAtFirstBatchWithReports(t *testing.T) {
	v := loadVectors(t)
	a := loadAccessory(t, v.FreshAccessory)
	now := mustTime(t, v.Batches.Now)
	batches := a.pollBatches(now)
	if len(batches) < 3 {
		t.Fatalf("%d batches, the test needs 3", len(batches))
	}
	target := batches[1].Primary[0]
	newest := now.Add(-time.Hour).Truncate(time.Second).UTC()

	requests := 0
	f, _ := newTestFetcher(t, func(w http.ResponseWriter, r *http.Request) {
		var body struct {
			Fetch []struct {
				PrimaryIDs []string `json:"primaryIds"`
			} `json:"fetch"`
		}
		json.NewDecoder(r.Body).Decode(&body)
		requests++
		if !slices.Contains(body.Fetch[0].PrimaryIDs, target.ID) {
			io.WriteString(w, `{"acsnLocations":{"statusCode":"200","locationPayload":[]}}`)
			return
		}
		io.WriteString(w, payloadResponse(target.ID,
			sealReport(t, target.Private, newest.Add(-time.Hour), 1),
			sealReport(t, target.Private, newest, 2),
		))
	})

	got, err := f.LatestAccessory(context.Background(), a, now)
	if err != nil {
		t.Fatal(err)
	}
	if requests != 2 {
		t.Fatalf("%d requests, want 2", requests)
	}
	if got == nil || !got.Time.Equal(newest) || got.Latitude != 2e-7 {
		t.Errorf("latest %+v, want lat 2e-7 at %v", got, newest)
	}
	if a.alignmentIndex != target.Index || !a.alignmentDate.Equal(newest) {
		t.Errorf("alignment %d at %v, want %d at %v", a.alignmentIndex, a.alignmentDate, target.Index, newest)
	}
}

func TestFetchAccessoryFindsKeysAboveMaxIndex(t *testing.T) {
	v := loadVectors(t)
	a := loadAccessory(t, v.FreshAccessory)
	now := mustTime(t, v.Batches.Now)
	hi := a.MaxIndex(now)
	stale, fresh := a.chain(a.skn, hi, hi, false)[0], a.chain(a.skn, hi+29, hi+29, false)[0]
	at := now.Add(-20 * time.Minute).Truncate(time.Second).UTC()

	requests := 0
	f, _ := newTestFetcher(t, func(w http.ResponseWriter, r *http.Request) {
		var body struct {
			Fetch []struct {
				PrimaryIDs []string `json:"primaryIds"`
			} `json:"fetch"`
		}
		json.NewDecoder(r.Body).Decode(&body)
		requests++
		switch ids := body.Fetch[0].PrimaryIDs; {
		case slices.Contains(ids, fresh.ID):
			io.WriteString(w, payloadResponse(fresh.ID, sealReport(t, fresh.Private, at, 1)))
		case slices.Contains(ids, stale.ID):
			io.WriteString(w, payloadResponse(stale.ID, sealReport(t, stale.Private, at.Add(-3*time.Hour), 2)))
		default:
			io.WriteString(w, `{"acsnLocations":{"statusCode":"200","locationPayload":[]}}`)
		}
	})

	got, err := f.LatestAccessory(context.Background(), a, now)
	if err != nil {
		t.Fatal(err)
	}
	if requests != 1 || got == nil || !got.Time.Equal(at) {
		t.Fatalf("%d requests, latest %+v; want the report at %v from the first request", requests, got, at)
	}
	if a.alignmentIndex != hi+29 {
		t.Errorf("alignment %d, want %d", a.alignmentIndex, hi+29)
	}
}

func TestFetchRejectsBadAppleStatus(t *testing.T) {
	f, _ := newTestFetcher(t, func(w http.ResponseWriter, r *http.Request) {
		io.WriteString(w, `{"acsnLocations":{"statusCode":"500"}}`)
	})
	if _, err := f.LatestStatic(context.Background(), []Key{staticKey(t)}, time.Now()); err == nil {
		t.Fatal("no error")
	}
}

func TestFetchAccessoryRetriesSameBatchesAfterError(t *testing.T) {
	v := loadVectors(t)
	a := loadAccessory(t, v.FreshAccessory)
	now := mustTime(t, v.Batches.Now)
	newest := a.pollBatches(now)[0].Primary[0].ID

	fail := true
	var firstIDs []string
	f, _ := newTestFetcher(t, func(w http.ResponseWriter, r *http.Request) {
		var body struct {
			Fetch []struct {
				PrimaryIDs []string `json:"primaryIds"`
			} `json:"fetch"`
		}
		json.NewDecoder(r.Body).Decode(&body)
		firstIDs = append(firstIDs, body.Fetch[0].PrimaryIDs[0])
		if fail {
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		io.WriteString(w, `{"acsnLocations":{"statusCode":"200","locationPayload":[]}}`)
	})
	if _, err := f.LatestAccessory(context.Background(), a, now); err == nil {
		t.Fatal("no error from HTTP 500")
	}
	fail, firstIDs = false, nil
	if _, err := f.LatestAccessory(context.Background(), a, now); err != nil {
		t.Fatal(err)
	}
	if len(firstIDs) == 0 || firstIDs[0] != newest {
		t.Errorf("after an error the scan moved on instead of retrying the newest batch")
	}
}

func TestFetchAccessoryCapsRequestsAndResumesNextPoll(t *testing.T) {
	v := loadVectors(t)
	now := time.Date(2026, 10, 26, 12, 0, 0, 0, time.UTC)
	var raw map[string]any
	if err := json.Unmarshal(v.FreshAccessory, &raw); err != nil {
		t.Fatal(err)
	}
	raw["paired_at"] = now.Add(-30 * 24 * time.Hour).Format(time.RFC3339)
	raw["alignment_date"], raw["alignment_index"] = nil, nil
	data, _ := json.Marshal(raw)
	a := loadAccessory(t, data)

	batches := a.pollBatches(now)
	if len(batches) < 2*MaxAccessoryRequests {
		t.Fatalf("%d batches, the test needs %d", len(batches), 2*MaxAccessoryRequests)
	}
	target := batches[MaxAccessoryRequests+1].Primary[0]

	var firstIDs []string
	f, _ := newTestFetcher(t, func(w http.ResponseWriter, r *http.Request) {
		var body struct {
			Fetch []struct {
				PrimaryIDs []string `json:"primaryIds"`
			} `json:"fetch"`
		}
		json.NewDecoder(r.Body).Decode(&body)
		firstIDs = append(firstIDs, body.Fetch[0].PrimaryIDs[0])
		if !slices.Contains(body.Fetch[0].PrimaryIDs, target.ID) {
			io.WriteString(w, `{"acsnLocations":{"statusCode":"200","locationPayload":[]}}`)
			return
		}
		io.WriteString(w, payloadResponse(target.ID, sealReport(t, target.Private, now.Add(-time.Hour), 1)))
	})
	ctx := context.Background()

	got, err := f.LatestAccessory(ctx, a, now)
	if err != nil || got != nil {
		t.Fatalf("poll 1: %+v, %v; want no report", got, err)
	}
	want := []string{batches[0].Primary[0].ID, batches[1].Primary[0].ID, batches[2].Primary[0].ID}
	if !slices.Equal(firstIDs, want) {
		t.Fatalf("poll 1 sent batches %v, want the newest %d", firstIDs, MaxAccessoryRequests)
	}

	firstIDs = nil
	got, err = f.LatestAccessory(ctx, a, now)
	if err != nil || got == nil {
		t.Fatalf("poll 2: %+v, %v; want a report", got, err)
	}
	want = []string{batches[3].Primary[0].ID, batches[4].Primary[0].ID}
	if !slices.Equal(firstIDs, want) {
		t.Fatalf("poll 2 sent batches %v, want 3 and 4", firstIDs)
	}

	firstIDs = nil
	if _, err := f.LatestAccessory(ctx, a, now); err != nil {
		t.Fatal(err)
	}
	if len(firstIDs) == 0 || firstIDs[0] != a.pollBatches(now)[0].Primary[0].ID {
		t.Errorf("poll 3 did not restart from the newest batch after a hit")
	}
}
