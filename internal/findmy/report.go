package findmy

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"time"
)

const appleEpoch = 978307200

type Report struct {
	Time       time.Time `json:"timestamp"`
	Latitude   float64   `json:"latitude"`
	Longitude  float64   `json:"longitude"`
	Accuracy   int       `json:"accuracy"`
	Confidence int       `json:"confidence"`
	Status     int       `json:"status"`
}

func DecryptReport(payload, priv []byte) (Report, error) {
	var r Report
	var data []byte
	switch len(payload) {
	case 88:
		r.Confidence, data = int(payload[4]), payload[5:]
	case 89:
		r.Confidence, data = int(payload[5]), payload[6:]
	default:
		return Report{}, fmt.Errorf("report: length %d, want 88 or 89", len(payload))
	}
	r.Time = time.Unix(int64(binary.BigEndian.Uint32(payload[0:4]))+appleEpoch, 0).UTC()

	curve := elliptic.P224()
	eph := data[0:57]
	pub, err := ecdsa.ParseUncompressedPublicKey(curve, eph)
	if err != nil {
		return Report{}, fmt.Errorf("report: ephemeral key: %w", err)
	}
	x, _ := curve.ScalarMult(pub.X, pub.Y, priv)
	h := sha256.New()
	h.Write(x.FillBytes(make([]byte, 28)))
	h.Write([]byte{0, 0, 0, 1})
	h.Write(eph)
	sum := h.Sum(nil)

	block, err := aes.NewCipher(sum[:16])
	if err != nil {
		return Report{}, err
	}
	gcm, err := cipher.NewGCMWithNonceSize(block, 16)
	if err != nil {
		return Report{}, err
	}
	plain, err := gcm.Open(nil, sum[16:], data[57:83], nil)
	if err != nil {
		return Report{}, fmt.Errorf("report: %w", err)
	}

	r.Latitude = float64(int32(binary.BigEndian.Uint32(plain[0:4]))) / 1e7
	r.Longitude = float64(int32(binary.BigEndian.Uint32(plain[4:8]))) / 1e7
	r.Accuracy = int(plain[8])
	r.Status = int(plain[9])
	return r, nil
}
