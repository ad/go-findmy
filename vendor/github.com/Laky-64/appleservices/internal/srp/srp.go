package srp

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"math/big"
)

type Params struct {
	N *big.Int
	G *big.Int
}

const rfc50542048NHex = "" +
	"AC6BDB41324A9A9BF166DE5E1389582FAF72B6651987EE07FC3192943DB56050" +
	"A37329CBB4A099ED8193E0757767A13DD52312AB4B03310DCD7F48A9DA04FD50" +
	"E8083969EDB767B0CF6095179A163AB3661A05FBD5FAAAE82918A9962F0B93B8" +
	"55F97993EC975EEAA80D740ADBF4FF747359D041D5C33EA71D281E446B14773B" +
	"CA97B43A23FB801676BD207A436C6481F1D2B9078717461A5B9D32E688F87748" +
	"544523B524B0D57D5EA77A2775D2ECFA032CFBDBF52FB37861602790" +
	"04E57AE6AF874E7303CE53299CCC041C7BC308D82A5698F3A8D0C38271AE35F8" +
	"E9DBFBB694B5C803D89F7AE435DE236D525F54759B65E372FCD68EF20FA7111F" +
	"9E4AFF73"

func NewParams() Params {
	n := new(big.Int)
	n.SetString(rfc50542048NHex, 16)
	return Params{N: n, G: big.NewInt(2)}
}

func widthPad(b []byte, width int) []byte {
	if len(b) >= width {
		return b
	}
	out := make([]byte, width)
	copy(out[width-len(b):], b)
	return out
}

func (p Params) byteWidth() int {
	return (p.N.BitLen() + 7) / 8
}

func (p Params) DeriveX(salt []byte, passwordBytes []byte) *big.Int {
	inner := sha256.Sum256(append([]byte(":"), passwordBytes...))
	outerInput := append(append([]byte{}, salt...), inner[:]...)
	outer := sha256.Sum256(outerInput)
	return new(big.Int).SetBytes(outer[:])
}

func (p Params) DeriveXWithUsername(salt []byte, username string, password []byte) *big.Int {
	innerInput := append(append([]byte(username), ':'), password...)
	inner := sha256.Sum256(innerInput)
	outerInput := append(append([]byte{}, salt...), inner[:]...)
	outer := sha256.Sum256(outerInput)
	return new(big.Int).SetBytes(outer[:])
}

func sha256Sum(b []byte) []byte {
	sum := sha256.Sum256(b)
	return sum[:]
}

func randBigInt(numBytes int) (*big.Int, error) {
	buf := make([]byte, numBytes)
	if _, err := rand.Read(buf); err != nil {
		return nil, err
	}
	return new(big.Int).SetBytes(buf), nil
}

func computeK(p Params) *big.Int {
	width := p.byteWidth()
	nb := widthPad(p.N.Bytes(), width)
	gb := widthPad(p.G.Bytes(), width)
	h := sha256Sum(append(append([]byte{}, nb...), gb...))
	return new(big.Int).SetBytes(h)
}

func computeU(p Params, A, B *big.Int) *big.Int {
	width := p.byteWidth()
	ab := widthPad(A.Bytes(), width)
	bb := widthPad(B.Bytes(), width)
	h := sha256Sum(append(append([]byte{}, ab...), bb...))
	return new(big.Int).SetBytes(h)
}

func calcM1(p Params, identity string, salt []byte, A, B *big.Int, sessionKey []byte) []byte {
	width := p.byteWidth()
	hn := sha256Sum(widthPad(p.N.Bytes(), width))
	hg := sha256Sum(widthPad(p.G.Bytes(), width))
	hnxorg := make([]byte, len(hn))
	for i := range hn {
		hnxorg[i] = hn[i] ^ hg[i]
	}
	hi := sha256Sum([]byte(identity))

	buf := append([]byte{}, hnxorg...)
	buf = append(buf, hi...)
	buf = append(buf, salt...)
	buf = append(buf, A.Bytes()...)
	buf = append(buf, B.Bytes()...)
	buf = append(buf, sessionKey...)
	return sha256Sum(buf)
}

func calcM2(A *big.Int, m1, sessionKey []byte) []byte {
	buf := append([]byte{}, A.Bytes()...)
	buf = append(buf, m1...)
	buf = append(buf, sessionKey...)
	return sha256Sum(buf)
}

type Client struct {
	params   Params
	username string
	a        *big.Int
	A        *big.Int
	m1       []byte
	key      []byte
}

func NewClient(params Params, username string) *Client {
	a, err := randBigInt(32)
	if err != nil {
		panic("srp: failed to generate random ephemeral: " + err.Error())
	}
	A := new(big.Int).Exp(params.G, a, params.N)
	return &Client{params: params, username: username, a: a, A: A}
}

func (c *Client) PublicA() *big.Int {
	return c.A
}

func (c *Client) ProcessChallenge(x *big.Int, salt []byte, B *big.Int) (m1 []byte, sessionKey []byte, err error) {
	if new(big.Int).Mod(B, c.params.N).Sign() == 0 {
		return nil, nil, errors.New("srp: server sent B == 0 mod N")
	}
	k := computeK(c.params)
	u := computeU(c.params, c.A, B)
	if u.Sign() == 0 {
		return nil, nil, errors.New("srp: u == 0")
	}

	gx := new(big.Int).Exp(c.params.G, x, c.params.N)
	kgx := new(big.Int).Mod(new(big.Int).Mul(k, gx), c.params.N)
	base := new(big.Int).Mod(new(big.Int).Sub(B, kgx), c.params.N)
	if base.Sign() < 0 {
		base.Add(base, c.params.N)
	}
	exp := new(big.Int).Add(c.a, new(big.Int).Mul(u, x))
	S := new(big.Int).Exp(base, exp, c.params.N)

	sessionKey = sha256Sum(S.Bytes())
	m1 = calcM1(c.params, c.username, salt, c.A, B, sessionKey)

	c.m1 = m1
	c.key = sessionKey
	return m1, sessionKey, nil
}

func (c *Client) VerifyServer(m2 []byte) error {
	if c.m1 == nil {
		return errors.New("srp: ProcessChallenge must be called before VerifyServer")
	}
	expected := calcM2(c.A, c.m1, c.key)
	if !hmac.Equal(expected, m2) {
		return errors.New("srp: server proof (M2) did not match — possible MITM or wrong password")
	}
	return nil
}
