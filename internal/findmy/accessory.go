package findmy

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"os"
	"path/filepath"
	"time"
)

const keyInterval = 15 * time.Minute

type Accessory struct {
	masterKey      []byte
	skn            []byte
	sks            []byte
	alignmentDate  time.Time
	alignmentIndex int
	raw            map[string]json.RawMessage
}

type Key struct {
	ID        string
	Private   []byte
	Index     int
	Secondary bool
}

var requiredFields = []string{
	"type", "master_key", "skn", "sks", "paired_at",
	"name", "model", "identifier", "alignment_date", "alignment_index",
}

func ParseAccessory(data []byte) (*Accessory, error) {
	a := &Accessory{}
	if err := json.Unmarshal(data, &a.raw); err != nil {
		return nil, err
	}
	for _, name := range requiredFields {
		if _, ok := a.raw[name]; !ok {
			return nil, fmt.Errorf("accessory: missing field %q", name)
		}
	}

	var f struct {
		Type      string     `json:"type"`
		MasterKey string     `json:"master_key"`
		SKN       string     `json:"skn"`
		SKS       string     `json:"sks"`
		PairedAt  time.Time  `json:"paired_at"`
		AlignDate *time.Time `json:"alignment_date"`
		AlignIdx  *int       `json:"alignment_index"`
	}
	if err := json.Unmarshal(data, &f); err != nil {
		return nil, fmt.Errorf("accessory: %w", err)
	}
	if f.Type != "accessory" {
		return nil, fmt.Errorf("accessory: type %q, want \"accessory\"", f.Type)
	}
	for _, k := range []struct {
		name string
		hex  string
		dst  *[]byte
		size int
	}{
		{"master_key", f.MasterKey, &a.masterKey, 28},
		{"skn", f.SKN, &a.skn, 32},
		{"sks", f.SKS, &a.sks, 32},
	} {
		b, err := hex.DecodeString(k.hex)
		if err != nil || len(b) != k.size {
			return nil, fmt.Errorf("accessory: %s must be %d bytes of hex", k.name, k.size)
		}
		*k.dst = b
	}
	if f.PairedAt.IsZero() {
		return nil, errors.New("accessory: paired_at is empty")
	}

	a.alignmentDate = f.PairedAt
	if f.AlignDate != nil {
		a.alignmentDate = *f.AlignDate
	}
	if f.AlignIdx != nil {
		a.alignmentIndex = *f.AlignIdx
	}
	if a.alignmentIndex < 0 {
		return nil, errors.New("accessory: alignment_index is negative")
	}
	return a, nil
}

func (a *Accessory) UpdateAlignment(t time.Time, i int) {
	if t.Before(a.alignmentDate) || i < a.alignmentIndex {
		return
	}
	a.alignmentDate, a.alignmentIndex = t, i
}

func (a *Accessory) Save(path string) error {
	a.raw["alignment_date"], _ = json.Marshal(a.alignmentDate)
	a.raw["alignment_index"], _ = json.Marshal(a.alignmentIndex)
	data, err := json.MarshalIndent(a.raw, "", "  ")
	if err != nil {
		return err
	}
	f, err := os.CreateTemp(filepath.Dir(path), filepath.Base(path)+".tmp*")
	if err != nil {
		return err
	}
	defer os.Remove(f.Name())
	if _, err := f.Write(data); err != nil {
		f.Close()
		return err
	}
	if err := f.Sync(); err != nil {
		f.Close()
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	return os.Rename(f.Name(), path)
}

func (a *Accessory) MinIndex(t time.Time) int {
	if !t.Before(a.alignmentDate) {
		return a.alignmentIndex
	}
	return a.alignmentIndex - int(a.alignmentDate.Sub(t)/keyInterval)
}

func (a *Accessory) MaxIndex(t time.Time) int {
	if !t.After(a.alignmentDate) {
		return a.alignmentIndex
	}
	return a.alignmentIndex + int(t.Sub(a.alignmentDate)/keyInterval)
}

// Secondary indices i/96+1 and i/96+2 are FindMy.py's guess, unconfirmed against Apple.
func (a *Accessory) KeysAt(i int) []Key {
	if i < 0 {
		return nil
	}
	keys := append(a.chain(a.skn, i, i, false), a.chain(a.sks, i/96+1, i/96+2, true)...)
	for j := range keys {
		keys[j].Index = i
	}
	return keys
}

type Batch struct {
	Primary   []Key
	Secondary []Key
}

const (
	fetchWindow = 7 * 24 * time.Hour
	maxBatchIDs = 290
)

func (a *Accessory) Batches(now time.Time) []Batch {
	lo := max(a.MinIndex(now.Add(-fetchWindow)), 0)
	hi := a.MaxIndex(now)
	primary := a.chain(a.skn, lo, hi, false)
	secondary := a.chain(a.sks, lo/96+1, hi/96+2, true)

	var out []Batch
	var cur Batch
	seen := map[string]bool{}
	for i := hi; i >= lo; i-- {
		p := primary[i-lo]
		s := secondary[i/96-lo/96 : i/96-lo/96+2]
		fresh := s[:0:0]
		for _, k := range s {
			if !seen[k.ID] {
				fresh = append(fresh, k)
			}
		}
		if len(cur.Primary)+1 > maxBatchIDs || len(cur.Secondary)+len(fresh) > maxBatchIDs {
			out = append(out, cur)
			cur, seen, fresh = Batch{}, map[string]bool{}, s
		}
		p.Index = i
		cur.Primary = append(cur.Primary, p)
		for _, k := range fresh {
			k.Index = i
			seen[k.ID] = true
			cur.Secondary = append(cur.Secondary, k)
		}
	}
	return append(out, cur)
}

func (a *Accessory) chain(seed []byte, from, to int, secondary bool) []Key {
	sk := seed
	for range from {
		sk = x963(sk, "update", 32)
	}
	keys := make([]Key, 0, to-from+1)
	for range to - from + 1 {
		priv := derivePrivate(a.masterKey, sk)
		k, err := ecdsa.ParseRawPrivateKey(elliptic.P224(), priv)
		if err != nil {
			panic(err)
		}
		keys = append(keys, Key{ID: hashedKey(advKey(k)), Private: priv, Secondary: secondary})
		sk = x963(sk, "update", 32)
	}
	return keys
}

func derivePrivate(master, sk []byte) []byte {
	n := elliptic.P224().Params().N
	n1 := new(big.Int).Sub(n, big.NewInt(1))
	at := x963(sk, "diversify", 72)
	u := new(big.Int).SetBytes(at[:36])
	u.Mod(u, n1).Add(u, big.NewInt(1))
	v := new(big.Int).SetBytes(at[36:])
	v.Mod(v, n1).Add(v, big.NewInt(1))
	d := new(big.Int).SetBytes(master)
	d.Mul(d, u).Add(d, v).Mod(d, n)
	return d.FillBytes(make([]byte, 28))
}

func x963(secret []byte, info string, n int) []byte {
	var out []byte
	for counter := uint32(1); len(out) < n; counter++ {
		h := sha256.New()
		h.Write(secret)
		binary.Write(h, binary.BigEndian, counter)
		h.Write([]byte(info))
		out = h.Sum(out)
	}
	return out[:n]
}
