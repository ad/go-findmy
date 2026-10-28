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
	"slices"
	"strings"
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
	scanFrom    map[string]int
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

// An unaligned accessory spans up to ~120 batches; fetching all of them every poll risks a ban.
const MaxAccessoryRequests = 3

func (f *Fetcher) LatestAccessory(ctx context.Context, a *Accessory, now time.Time) (*Report, error) {
	latest, err := f.latestAccessory(ctx, a, now)
	if err != nil {
		return nil, err
	}
	if swept := f.sweepSecondary(ctx, a, now); swept != nil && (latest == nil || swept.Time.After(latest.Time)) {
		return swept, nil
	}
	return latest, nil
}

// A tag away from its owner showed in Find My but on none of the secondary keys secondaryRange gives.
// shortcut: asks for every secondary key up to 400 days past the guess on each poll; narrow it once the log shows the offset.
func (f *Fetcher) sweepSecondary(ctx context.Context, a *Accessory, now time.Time) *Report {
	keys := a.chain(a.sks, 0, a.MaxIndex(now)/96+400, true)
	var entries []fetchEntry
	for c := range slices.Chunk(keys, maxBatchIDs) {
		entries = append(entries, newEntry(nil, c, now))
	}
	reports, err := f.fetch(ctx, entries, keys)
	if err != nil {
		log.Printf("debug %s: secondary sweep: %v", a.Identifier(), err)
		return nil
	}
	newest := newestOf(reports)
	if newest == nil {
		log.Printf("debug %s: secondary sweep of 0..%d: no reports", a.Identifier(), len(keys)-1)
		return nil
	}
	log.Printf("debug %s: secondary sweep of 0..%d: %d reports, newest %s at secondary index %d (primary %d/96 = %d): %s",
		a.Identifier(), len(keys)-1, len(reports), newest.Time.Format(time.RFC3339), newest.key.Index, a.MaxIndex(now), a.MaxIndex(now)/96, timeline(reports))

	// FindMy.py #274: a 2nd generation tag ran past this ceiling, and its fresh reports sat on the keys above it.
	hi := a.MaxIndex(now)
	above := a.chain(a.skn, hi+1, hi+3*maxBatchIDs, false)
	entries = entries[:0]
	for c := range slices.Chunk(above, maxBatchIDs) {
		entries = append(entries, newEntry(c, nil, now))
	}
	recent, err := f.fetch(ctx, entries, above)
	if err != nil {
		log.Printf("debug %s: primary above the ceiling %d: %v", a.Identifier(), hi, err)
		return &newest.Report
	}
	log.Printf("debug %s: primary %d..%d above the ceiling, %d steps of 15 minutes since pairing at %s: %d reports: %s",
		a.Identifier(), hi+1, hi+3*maxBatchIDs, int(now.Sub(a.pairedAt)/keyInterval), a.pairedAt.Format(time.RFC3339), len(recent), timeline(recent))
	if r := newestOf(recent); r != nil && r.Time.After(newest.Time) {
		return &r.Report
	}
	return &newest.Report
}

func newestOf(reports []keyedReport) *keyedReport {
	var newest *keyedReport
	for _, r := range reports {
		if newest == nil || r.Time.After(newest.Time) {
			newest = &r
		}
	}
	return newest
}

func timeline(reports []keyedReport) string {
	out := make([]string, len(reports))
	for i, r := range reports {
		out[i] = fmt.Sprintf("%s@%d", r.Time.Format(time.RFC3339), r.key.Index)
	}
	slices.Sort(out)
	return strings.Join(out, " ")
}

func (f *Fetcher) latestAccessory(ctx context.Context, a *Accessory, now time.Time) (*Report, error) {
	if f.scanFrom == nil {
		f.scanFrom = map[string]int{}
	}
	id := a.Identifier()
	batches := a.Batches(now)
	hi := batches[0].Primary[0].Index
	from := f.scanFrom[id] % len(batches)
	for n, b := range batches[from:min(from+MaxAccessoryRequests, len(batches))] {
		keys := append(append([]Key(nil), b.Primary...), b.Secondary...)
		reports, err := f.fetch(ctx, []fetchEntry{newEntry(b.Primary, b.Secondary, now)}, keys)
		if err != nil {
			return nil, err
		}
		var latest *Report
		var newest [2]keyedReport
		var count [2]int
		for _, r := range reports {
			kind := 0
			if r.key.Secondary {
				kind = 1
			}
			count[kind]++
			if r.Time.After(newest[kind].Time) {
				newest[kind] = r
			}
			// A secondary key spans a day of primary indices, so it cannot tell which one the tag was at.
			if !r.key.Secondary {
				a.UpdateAlignment(r.Time, r.key.Index)
			}
			if latest == nil || r.Time.After(latest.Time) {
				latest = &r.Report
			}
		}
		log.Printf("debug %s: batch %d/%d, primary index %d..%d: %d primary reports, newest %s at index %d; %d secondary, newest %s at secondary index %d (primary %d/96 = %d); alignment %s index %d; %s",
			id, from+n, len(batches), b.Primary[len(b.Primary)-1].Index, b.Primary[0].Index,
			count[0], newest[0].Time.Format(time.RFC3339), newest[0].key.Index,
			count[1], newest[1].Time.Format(time.RFC3339), newest[1].key.Index, hi, hi/96,
			a.alignmentDate.Format(time.RFC3339), a.alignmentIndex, timeline(reports))
		if latest != nil {
			delete(f.scanFrom, id)
			return latest, nil
		}
	}
	f.scanFrom[id] = from + MaxAccessoryRequests
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
