package findmy

import (
	"encoding/hex"
	"encoding/json"
	"os"
	"slices"
	"testing"
	"time"
)

type vectorKey struct {
	Index     int
	Secondary bool
	Private   string
	Adv       string
	ID        string
}

type vectors struct {
	Accessory      json.RawMessage `json:"accessory"`
	FreshAccessory json.RawMessage `json:"fresh_accessory"`
	Primary        []vectorKey
	Secondary      []vectorKey
	KeysAt         []struct {
		Index int
		IDs   []string
	} `json:"keys_at"`
	Bounds []struct {
		Date      string
		Accessory [2]int
		Fresh     [2]int
	}
	Batches struct {
		Now     string
		Batches []struct{ Primary, Secondary []string }
	}
	OpenHaystack struct {
		Private, Adv, ID, MAC, Payload string
	}
}

func loadVectors(t *testing.T) vectors {
	t.Helper()
	raw, err := os.ReadFile("testdata/findmypy-22e4879.json")
	if err != nil {
		t.Fatal(err)
	}
	var v vectors
	if err := json.Unmarshal(raw, &v); err != nil {
		t.Fatal(err)
	}
	return v
}

func loadAccessory(t *testing.T, raw json.RawMessage) *Accessory {
	t.Helper()
	a, err := ParseAccessory(raw)
	if err != nil {
		t.Fatal(err)
	}
	return a
}

func ids(keys []Key) []string {
	out := make([]string, len(keys))
	for i, k := range keys {
		out[i] = k.ID
	}
	slices.Sort(out)
	return out
}

func TestKeysAtMatchesFindMyPy(t *testing.T) {
	v := loadVectors(t)
	a := loadAccessory(t, v.Accessory)

	for _, want := range v.KeysAt {
		if got := ids(a.KeysAt(want.Index)); !slices.Equal(got, want.IDs) {
			t.Errorf("KeysAt(%d) ids = %v, want %v", want.Index, got, want.IDs)
		}
	}

	byID := map[string]Key{}
	for _, vk := range v.Primary {
		for _, i := range []int{vk.Index, 0, 96, 5000} {
			for _, k := range a.KeysAt(i) {
				byID[k.ID] = k
			}
		}
	}
	for _, want := range append(v.Primary, v.Secondary...) {
		k, ok := byID[want.ID]
		if !ok {
			t.Errorf("key %s (index %d, secondary %v) not produced", want.ID, want.Index, want.Secondary)
			continue
		}
		if got := hex.EncodeToString(k.Private); got != want.Private || k.Secondary != want.Secondary {
			t.Errorf("key %s: private %s secondary %v, want %s %v", want.ID, got, k.Secondary, want.Private, want.Secondary)
		}
	}
}

func mustTime(t *testing.T, s string) time.Time {
	t.Helper()
	ts, err := time.Parse(time.RFC3339, s)
	if err != nil {
		t.Fatal(err)
	}
	return ts
}

func TestIndexBoundsMatchFindMyPy(t *testing.T) {
	v := loadVectors(t)
	aligned := loadAccessory(t, v.Accessory)
	fresh := loadAccessory(t, v.FreshAccessory)

	for _, b := range v.Bounds {
		at := mustTime(t, b.Date)
		if got := [2]int{aligned.MinIndex(at), aligned.MaxIndex(at)}; got != b.Accessory {
			t.Errorf("aligned at %s: %v, want %v", b.Date, got, b.Accessory)
		}
		if got := [2]int{fresh.MinIndex(at), fresh.MaxIndex(at)}; got != b.Fresh {
			t.Errorf("fresh at %s: %v, want %v", b.Date, got, b.Fresh)
		}
	}
}

func TestBatchesMatchFindMyPy(t *testing.T) {
	v := loadVectors(t)
	a := loadAccessory(t, v.Accessory)

	got := a.Batches(mustTime(t, v.Batches.Now))
	if len(got) != len(v.Batches.Batches) {
		t.Fatalf("%d batches, want %d", len(got), len(v.Batches.Batches))
	}
	for i, want := range v.Batches.Batches {
		if p := ids(got[i].Primary); !slices.Equal(p, want.Primary) {
			t.Errorf("batch %d primary: %d ids, want %d", i, len(p), len(want.Primary))
		}
		if s := ids(got[i].Secondary); !slices.Equal(s, want.Secondary) {
			t.Errorf("batch %d secondary: %v, want %v", i, s, want.Secondary)
		}
	}
}

func TestAlignmentMovesOnlyForward(t *testing.T) {
	v := loadVectors(t)
	at := mustTime(t, "2026-03-01T12:07:00Z")

	cases := []struct {
		name    string
		date    time.Time
		index   int
		wantIdx int
	}{
		{"older date", at.Add(-time.Hour), 6000, 5000},
		{"lower index", at.Add(time.Hour), 4999, 5000},
		{"newer date and index", at.Add(time.Hour), 5003, 5003},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			a := loadAccessory(t, v.Accessory)
			a.UpdateAlignment(c.date, c.index)
			probe := at.Add(time.Hour)
			if got := a.MinIndex(probe); got != c.wantIdx {
				t.Errorf("MinIndex after update = %d, want %d", got, c.wantIdx)
			}
		})
	}
}

func TestSavedAccessoryKeepsAlignmentAndUnknownFields(t *testing.T) {
	v := loadVectors(t)
	var withEmoji map[string]any
	if err := json.Unmarshal(v.Accessory, &withEmoji); err != nil {
		t.Fatal(err)
	}
	withEmoji["emoji"] = "🔑"
	raw, _ := json.Marshal(withEmoji)
	a := loadAccessory(t, raw)

	seen := mustTime(t, "2026-03-02T00:00:00Z")
	a.UpdateAlignment(seen, 5100)
	path := t.TempDir() + "/tag.json"
	if err := a.Save(path); err != nil {
		t.Fatal(err)
	}

	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if perm := info.Mode().Perm(); perm != 0o600 {
		t.Errorf("file mode %o, want 600", perm)
	}
	saved, _ := os.ReadFile(path)
	b := loadAccessory(t, saved)
	if got := b.MinIndex(seen); got != 5100 {
		t.Errorf("reloaded alignment index = %d, want 5100", got)
	}
	var fields map[string]any
	json.Unmarshal(saved, &fields)
	if fields["emoji"] != "🔑" {
		t.Errorf("emoji = %v, want it preserved", fields["emoji"])
	}
}

func TestParseAccessoryRejectsBadInput(t *testing.T) {
	v := loadVectors(t)
	edit := func(f func(m map[string]any)) []byte {
		var m map[string]any
		json.Unmarshal(v.Accessory, &m)
		f(m)
		b, _ := json.Marshal(m)
		return b
	}

	cases := map[string][]byte{
		"not json":         []byte("{"),
		"wrong type":       edit(func(m map[string]any) { m["type"] = "custom_rolling_key_accessory" }),
		"short master_key": edit(func(m map[string]any) { m["master_key"] = m["master_key"].(string)[2:] }),
		"long skn":         edit(func(m map[string]any) { m["skn"] = m["skn"].(string) + "00" }),
		"null sks":         edit(func(m map[string]any) { m["sks"] = nil }),
		"non-hex skn":      edit(func(m map[string]any) { m["skn"] = "zz" }),
		"naive paired_at":  edit(func(m map[string]any) { m["paired_at"] = "2026-01-01T00:00:00" }),
		"null paired_at":   edit(func(m map[string]any) { m["paired_at"] = nil }),
		"negative index":   edit(func(m map[string]any) { m["alignment_index"] = -1 }),
	}
	for _, field := range []string{"type", "master_key", "skn", "sks", "paired_at", "name", "model", "identifier", "alignment_date", "alignment_index"} {
		cases["missing "+field] = edit(func(m map[string]any) { delete(m, field) })
	}
	for name, data := range cases {
		t.Run(name, func(t *testing.T) {
			if _, err := ParseAccessory(data); err == nil {
				t.Error("ParseAccessory accepted it")
			}
		})
	}
}

func TestParseAccessoryAcceptsNullOptionalFields(t *testing.T) {
	v := loadVectors(t)
	if _, err := ParseAccessory(v.FreshAccessory); err != nil {
		t.Fatal(err)
	}
	var m map[string]any
	json.Unmarshal(v.Accessory, &m)
	m["alignment_date"], m["alignment_index"] = nil, nil
	b, _ := json.Marshal(m)
	if _, err := ParseAccessory(b); err != nil {
		t.Fatal(err)
	}
}

func TestKeysAtNegativeIndexIsEmpty(t *testing.T) {
	a := loadAccessory(t, loadVectors(t).Accessory)
	if keys := a.KeysAt(-1); len(keys) != 0 {
		t.Errorf("KeysAt(-1) = %d keys, want none", len(keys))
	}
}
