// Apple's SRP-6a variant, adapted from github.com/Laky-64/appleservices internal/srp.
// MIT License, Copyright (c) 2026 Lauren.

package icloud

import (
	"crypto/hmac"
	"crypto/pbkdf2"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"math/big"
)

const srpN = "AC6BDB41324A9A9BF166DE5E1389582FAF72B6651987EE07FC3192943DB56050A37329CBB4A099ED8193E0757767A13DD52312AB4B03310DCD7F48A9DA04FD50E8083969EDB767B0CF6095179A163AB3661A05FBD5FAAAE82918A9962F0B93B855F97993EC975EEAA80D740ADBF4FF747359D041D5C33EA71D281E446B14773BCA97B43A23FB801676BD207A436C6481F1D2B9078717461A5B9D32E688F87748544523B524B0D57D5EA77A2775D2ECFA032CFBDBF52FB3786160279004E57AE6AF874E7303CE53299CCC041C7BC308D82A5698F3A8D0C38271AE35F8E9DBFBB694B5C803D89F7AE435DE236D525F54759B65E372FCD68EF20FA7111F9E4AFF73"

var (
	srpGroup, _ = new(big.Int).SetString(srpN, 16)
	srpG        = big.NewInt(2)
)

func h(parts ...[]byte) []byte {
	s := sha256.New()
	for _, p := range parts {
		s.Write(p)
	}
	return s.Sum(nil)
}

func pad(b []byte) []byte {
	return append(make([]byte, 256-len(b)), b...)
}

type srpClient struct {
	user string
	a, A *big.Int
	m2   []byte
	key  []byte
}

func newSRP(user string) (*srpClient, error) {
	buf := make([]byte, 256)
	if _, err := rand.Read(buf); err != nil {
		return nil, err
	}
	a := new(big.Int).SetBytes(buf)
	return &srpClient{user: user, a: a, A: new(big.Int).Exp(srpG, a, srpGroup)}, nil
}

func srpPassword(digest, salt []byte, iterations int, protocol string) ([]byte, error) {
	switch protocol {
	case "s2k":
	case "s2k_fo":
		digest = []byte(hex.EncodeToString(digest))
	default:
		return nil, fmt.Errorf("unsupported password protocol %q", protocol)
	}
	return pbkdf2.Key(sha256.New, string(digest), salt, iterations, 32)
}

func (c *srpClient) m1(salt, bBytes, password []byte) ([]byte, error) {
	B := new(big.Int).SetBytes(bBytes)
	if new(big.Int).Mod(B, srpGroup).Sign() == 0 {
		return nil, errors.New("srp: B is 0 mod N")
	}
	u := new(big.Int).SetBytes(h(pad(c.A.Bytes()), pad(B.Bytes())))
	if u.Sign() == 0 {
		return nil, errors.New("srp: u is 0")
	}
	x := new(big.Int).SetBytes(h(salt, h([]byte(":"), password)))
	k := new(big.Int).SetBytes(h(srpGroup.Bytes(), pad(srpG.Bytes())))
	kv := new(big.Int).Mul(k, new(big.Int).Exp(srpG, x, srpGroup))
	base := new(big.Int).Mod(new(big.Int).Sub(B, kv), srpGroup)
	S := new(big.Int).Exp(base, new(big.Int).Add(c.a, new(big.Int).Mul(u, x)), srpGroup)
	c.key = h(S.Bytes())

	hn, hg := h(srpGroup.Bytes()), h(pad(srpG.Bytes()))
	for i := range hn {
		hn[i] ^= hg[i]
	}
	m1 := h(hn, h([]byte(c.user)), salt, c.A.Bytes(), B.Bytes(), c.key)
	c.m2 = h(c.A.Bytes(), m1, c.key)
	return m1, nil
}

func (c *srpClient) verify(m2 []byte) bool {
	return c.m2 != nil && hmac.Equal(c.m2, m2)
}
