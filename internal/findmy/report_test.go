package findmy

import (
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"os"
	"testing"
	"time"
)

type reportVectors struct {
	Private string `json:"private"`
	ID      string `json:"id"`
	Reports []struct {
		Len        int     `json:"len"`
		Payload    string  `json:"payload"`
		Timestamp  int64   `json:"timestamp"`
		Confidence int     `json:"confidence"`
		Latitude   float64 `json:"latitude"`
		Longitude  float64 `json:"longitude"`
		Accuracy   int     `json:"accuracy"`
		Status     int     `json:"status"`
	} `json:"reports"`
}

func loadReportVectors(t *testing.T) (reportVectors, []byte) {
	t.Helper()
	data, err := os.ReadFile("testdata/findmypy-22e4879-reports.json")
	if err != nil {
		t.Fatal(err)
	}
	var v reportVectors
	if err := json.Unmarshal(data, &v); err != nil {
		t.Fatal(err)
	}
	priv, err := hex.DecodeString(v.Private)
	if err != nil {
		t.Fatal(err)
	}
	return v, priv
}

func TestDecryptReportMatchesFindMyPy(t *testing.T) {
	v, priv := loadReportVectors(t)
	for _, want := range v.Reports {
		payload, err := base64.StdEncoding.DecodeString(want.Payload)
		if err != nil {
			t.Fatal(err)
		}
		if len(payload) != want.Len {
			t.Fatalf("fixture length %d, want %d", len(payload), want.Len)
		}
		got, err := DecryptReport(payload, priv)
		if err != nil {
			t.Fatalf("len %d: %v", want.Len, err)
		}
		exp := Report{
			Time:       time.Unix(want.Timestamp, 0).UTC(),
			Latitude:   want.Latitude,
			Longitude:  want.Longitude,
			Accuracy:   want.Accuracy,
			Confidence: want.Confidence,
			Status:     want.Status,
		}
		if got != exp {
			t.Errorf("len %d:\n got %+v\nwant %+v", want.Len, got, exp)
		}
	}
}

func TestDecryptReportRejectsBadInput(t *testing.T) {
	v, priv := loadReportVectors(t)
	good, _ := base64.StdEncoding.DecodeString(v.Reports[0].Payload)
	tampered := append([]byte(nil), good...)
	tampered[len(tampered)-1] ^= 1
	for name, p := range map[string][]byte{
		"short":    good[:87],
		"long":     append(append([]byte(nil), good...), 0, 0),
		"tampered": tampered,
	} {
		if _, err := DecryptReport(p, priv); err == nil {
			t.Errorf("%s: no error", name)
		}
	}
}
