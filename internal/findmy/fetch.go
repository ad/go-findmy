package findmy

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"time"
)

const FetchURL = "https://gateway.icloud.com/findmyservice/v2/fetch"

const maxEmptyRetries = 5

var (
	ErrUnauthorized  = errors.New("fetch: unauthorized, login needed")
	ErrEmptyResponse = errors.New("fetch: empty response from Apple after retries")
)

type Anisette interface {
	Headers() (map[string]string, error)
}

type Credentials interface {
	SearchPartyAuth() (dsid, token string, err error)
}

type Fetcher struct {
	Anisette    Anisette
	Credentials Credentials
	Relogin     func(context.Context) error
	HTTP        *http.Client
	URL         string
	Sleep       func(context.Context, time.Duration) error
}

func NewFetcher(a Anisette, c Credentials, relogin func(context.Context) error) *Fetcher {
	return &Fetcher{Anisette: a, Credentials: c, Relogin: relogin, HTTP: &http.Client{Timeout: time.Minute}, URL: FetchURL, Sleep: sleep}
}

func sleep(ctx context.Context, d time.Duration) error {
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-t.C:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

type fetchEntry struct {
	OwnedDeviceIDs     []string `json:"ownedDeviceIds"`
	KeyType            int      `json:"keyType"`
	StartDate          int64    `json:"startDate"`
	StartDateSecondary int64    `json:"startDateSecondary"`
	EndDate            int64    `json:"endDate"`
	PrimaryIDs         []string `json:"primaryIds"`
	SecondaryIDs       []string `json:"secondaryIds"`
}

func newEntry(primary, secondary []Key, now time.Time) fetchEntry {
	start := now.Add(-fetchWindow).UnixMilli()
	e := fetchEntry{
		OwnedDeviceIDs: []string{}, KeyType: 1,
		StartDate: start, StartDateSecondary: start, EndDate: now.UnixMilli(),
		PrimaryIDs: []string{}, SecondaryIDs: []string{},
	}
	for _, k := range primary {
		e.PrimaryIDs = append(e.PrimaryIDs, k.ID)
	}
	for _, k := range secondary {
		e.SecondaryIDs = append(e.SecondaryIDs, k.ID)
	}
	return e
}

func (f *Fetcher) LatestStatic(ctx context.Context, keys []Key, now time.Time) (map[string]Report, error) {
	out := map[string]Report{}
	if len(keys) == 0 {
		return out, nil
	}
	entries := make([]fetchEntry, len(keys))
	for i, k := range keys {
		entries[i] = newEntry([]Key{k}, nil, now)
	}
	reports, err := f.fetch(ctx, entries, keys)
	if err != nil {
		return nil, err
	}
	for _, r := range reports {
		if cur, ok := out[r.key.ID]; !ok || r.Time.After(cur.Time) {
			out[r.key.ID] = r.Report
		}
	}
	return out, nil
}

func (f *Fetcher) LatestAccessory(ctx context.Context, a *Accessory, now time.Time) (*Report, error) {
	for _, b := range a.Batches(now) {
		keys := append(append([]Key(nil), b.Primary...), b.Secondary...)
		reports, err := f.fetch(ctx, []fetchEntry{newEntry(b.Primary, b.Secondary, now)}, keys)
		if err != nil {
			return nil, err
		}
		var latest *Report
		for _, r := range reports {
			a.UpdateAlignment(r.Time, r.key.Index)
			if latest == nil || r.Time.After(latest.Time) {
				latest = &r.Report
			}
		}
		if latest != nil {
			return latest, nil
		}
	}
	return nil, nil
}

type keyedReport struct {
	Report
	key Key
}

func (f *Fetcher) fetch(ctx context.Context, entries []fetchEntry, keys []Key) ([]keyedReport, error) {
	body, err := json.Marshal(map[string]any{
		"clientContext": map[string]string{
			"clientBundleIdentifier": "com.apple.icloud.searchpartyuseragent",
			"policy":                 "foregroundClient",
		},
		"fetch": entries,
	})
	if err != nil {
		return nil, err
	}

	status, resp, err := f.postRetryingEmpty(ctx, body)
	if err == nil && status == http.StatusUnauthorized {
		if err := f.Relogin(ctx); err != nil {
			return nil, fmt.Errorf("%w: relogin: %w", ErrUnauthorized, err)
		}
		status, resp, err = f.postRetryingEmpty(ctx, body)
	}
	if err != nil {
		return nil, err
	}
	if status == http.StatusUnauthorized {
		return nil, ErrUnauthorized
	}

	var parsed struct {
		AcsnLocations struct {
			StatusCode      string `json:"statusCode"`
			LocationPayload []struct {
				ID           string   `json:"id"`
				LocationInfo []string `json:"locationInfo"`
			} `json:"locationPayload"`
		} `json:"acsnLocations"`
	}
	if status != http.StatusOK {
		return nil, fmt.Errorf("fetch: HTTP %d", status)
	}
	if err := json.Unmarshal(resp, &parsed); err != nil {
		return nil, fmt.Errorf("fetch: %w", err)
	}
	if parsed.AcsnLocations.StatusCode != "200" {
		return nil, fmt.Errorf("fetch: acsnLocations.statusCode %q", parsed.AcsnLocations.StatusCode)
	}

	byID := make(map[string]Key, len(keys))
	for _, k := range keys {
		byID[k.ID] = k
	}
	var out []keyedReport
	for _, p := range parsed.AcsnLocations.LocationPayload {
		k, ok := byID[p.ID]
		if !ok {
			continue
		}
		for _, info := range p.LocationInfo {
			payload, err := base64.StdEncoding.DecodeString(info)
			if err != nil {
				return nil, fmt.Errorf("fetch: report for %s: %w", p.ID, err)
			}
			r, err := DecryptReport(payload, k.Private)
			if err != nil {
				log.Printf("skipping a report for %s: %v", p.ID, err)
				continue
			}
			out = append(out, keyedReport{r, k})
		}
	}
	return out, nil
}

func (f *Fetcher) postRetryingEmpty(ctx context.Context, body []byte) (int, []byte, error) {
	for n := 1; ; n++ {
		status, resp, err := f.post(ctx, body)
		if err != nil || status != http.StatusOK || len(bytes.TrimSpace(resp)) > 0 {
			return status, resp, err
		}
		if n > maxEmptyRetries {
			return 0, nil, ErrEmptyResponse
		}
		if err := f.Sleep(ctx, time.Duration(2*n)*time.Second); err != nil {
			return 0, nil, err
		}
	}
}

func (f *Fetcher) post(ctx context.Context, body []byte) (int, []byte, error) {
	headers, err := f.Anisette.Headers()
	if err != nil {
		return 0, nil, fmt.Errorf("fetch: anisette: %w", err)
	}
	dsid, token, err := f.Credentials.SearchPartyAuth()
	if err != nil {
		return 0, nil, fmt.Errorf("fetch: credentials: %w", err)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, f.URL, bytes.NewReader(body))
	if err != nil {
		return 0, nil, err
	}
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	req.Header.Del("X-Mme-Client-Info")
	req.Header.Set("Content-Type", "application/json")
	req.SetBasicAuth(dsid, token)

	resp, err := f.HTTP.Do(req)
	if err != nil {
		return 0, nil, err
	}
	defer resp.Body.Close()
	data, err := io.ReadAll(resp.Body)
	return resp.StatusCode, data, err
}
