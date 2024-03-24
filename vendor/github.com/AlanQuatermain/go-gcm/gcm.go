// The GCM package provides an implementation of the Galois/Counter Mode of
// operation for symmetric block ciphers. It provides authenticated encryption, 
// meaning that it both encrypts content and generates an authentication tag similar
// to an HMAC operation.
package gcm

import (
    "bytes"
    "crypto/cipher"
    "encoding/binary"
    "errors"
    "fmt"
    "io"
    "math/big"
)

var zeroes [24]byte

// This cryptography mode encompasses both encryption and authentication of data.
// Due to its differing inputs and outputs, it doesn't conform to the cipher.Cipher
// interface, instead providing separate Encrypt() and Decrypt() methods.
type GaloisCounterMode interface {
    // BlockSize returns the mode's block size.
    BlockSize() int

    // Encrypts plaintext along with some additional authenticated data, returning
    // the encrypted output along with an authentication tag.
    Encrypt(src io.Reader, aad []byte) (enc, tag []byte)

    // Decrypts data encoded by Encrypt(). Input also requires the additional
    // authenticated data passed to Encrypt() and the authentication tag returned
    // by that function. Internally the tag is verified before any attempt is made
    // do actually decrypt the input ciphertext.
    Decrypt(ciphertext, aad, tag []byte) ([]byte, error)
}

type gcm struct {
    b         cipher.Block
    blockSize int
    iv        []byte
    h         []byte
    tagSize   int
    tmp       []byte
}

func dup(p []byte) []byte {
    q := make([]byte, len(p))
    copy(q, p)
    return q
}

// Creates a new Galois/Counter Mode for a given block cipher. The iv parameter is
// required, but a tagSizeInBits of zero can be supplied, in which case the default tag
// size of 128 bits will be used.
func NewGCM(b cipher.Block, tagSizeInBits int, iv []byte) (GaloisCounterMode, error) {
    if b.BlockSize() != 16 && b.BlockSize() != 18 && b.BlockSize() != 24 {
        return nil, errors.New("Block cipher MUST have a 128-bit block size")
    }

    if tagSizeInBits <= 0 {
        tagSizeInBits = 128
    }

    h := make([]byte, 16)
    b.Encrypt(h, zeroes[:16])

    return &gcm{
        b:         b,
        blockSize: b.BlockSize(),
        iv:        dup(iv),
        h:         h,
        tagSize:   tagSizeInBits / 8,
        tmp:       make([]byte, b.BlockSize()),
    }, nil
}

func padBignumToBlocksize(num *big.Int, size int) (buf []byte) {
    buf = num.Bytes()
    if rem := size - len(buf); rem > 0 {
        tmp := make([]byte, size)
        copy(tmp[rem:], buf)
        buf = tmp
    }
    return
}

// Modifies and returns a
func (x *gcm) xor(a, b []byte) []byte {
    for i := range a {
        a[i] ^= b[i]
    }
    return a
}

// modifies and returns a
func (x *gcm) rshift(a []byte) []byte {
    c := byte(0)
    for i := range a {
        t := a[i] & 1
        a[i] = (a[i] >> 1) | (c << 7)
        c = t
    }
    return a

}

func getBitN(x []byte, n int) int {
    byteN := n / 8
    bitN := uint(7 - (n % 8))
    return int((x[byteN] >> bitN) & 1)
}

func (x *gcm) mult(X, Y []byte) []byte {
    // special constant
    R := make([]byte, x.blockSize)
    R[0] = 225

    // working variables
    Z := make([]byte, x.blockSize)
    V := make([]byte, len(Y))
    copy(V, Y)

    for i := 0; i < 128; i++ {
        if getBitN(X, i) == 1 {
            Z = x.xor(Z, V)
        }
        if getBitN(V, 127) == 0 {
            V = x.rshift(V)
        } else {
            V = x.rshift(V)
            V = x.xor(V, R[:])
        }
    }

    return Z
}

func (x *gcm) ghash(src []byte) []byte {
    Y := make([]byte, x.blockSize)
    for len(src) > 0 {
        X := src[:x.blockSize]
        Y = x.mult(x.xor(Y, X), x.h)
        src = src[x.blockSize:]
    }
    return Y
}

func inc32(x []byte) {
    sz := len(x) - 4
    if sz < 0 {
        sz = 0
    }
    inc := x[sz:]
    uinc := binary.BigEndian.Uint32(inc) + 1
    binary.BigEndian.PutUint32(inc, uinc)
}

func (x *gcm) gctr(icb []byte, input io.Reader) []byte {
    // initialize the counter with the given counter block
    CB := make([]byte, len(icb))
    copy(CB, icb)

    // output variable & input buffer
    var outbuf bytes.Buffer
    X := make([]byte, x.blockSize)

    for {
        r, err := input.Read(X)
        if err != nil && err != io.EOF {
            panic(fmt.Sprintf("Error reading from GCM input: %v", err))
        } else if r == 0 {
            // no more input data
            break
        }

        if r < len(X) {
            X = X[:r]
        }

        x.b.Encrypt(x.tmp, CB)

        // XOR data with encrypted counter
        Y := x.xor(X, x.tmp)

        // append bytes to output
        outbuf.Write(Y)

        // increment counter ready for next pass
        inc32(CB)
    }

    output := outbuf.Bytes()
    return output
}

func (x *gcm) generatePreCounter() (J []byte) {
    if len(x.iv) == 12 {
        J = make([]byte, 16)
        copy(J, x.iv)
        J[15] = 1
    } else {
        // round up to multiple of 128 bits
        sz := (len(x.iv) + 3) &^ 3
        ivLen := uint64(len(x.iv) * 8)

        // allocate an extra 128 bits
        buf := make([]byte, sz+16)

        // copy in the IV
        copy(buf, x.iv)

        // the last 64 bits contains the 64-bit representation of the iv length
        binary.BigEndian.PutUint64(buf[sz+8:], ivLen)

        // now GHASH it
        J = x.ghash(buf)
    }

    return J
}

func (x *gcm) generateAuthenticationInput(c, a []byte) []byte {
    var toHash bytes.Buffer

    // write AAD and pad to block size
    toHash.Write(a)
    if rem := toHash.Len() % x.blockSize; rem != 0 {
        toHash.Write(zeroes[rem:x.blockSize])
    }

    // write cipher & pad to block size
    toHash.Write(c)
    if rem := toHash.Len() % x.blockSize; rem != 0 {
        toHash.Write(zeroes[rem:x.blockSize])
    }

    // write 64-bit lengths of AAD & cipher
    var tmp [16]byte
    binary.BigEndian.PutUint64(tmp[:8], uint64(len(a)*8))
    binary.BigEndian.PutUint64(tmp[8:], uint64(len(c)*8))
    toHash.Write(tmp[:])

    // this string gets hashed down to a one-block output
    return x.ghash(toHash.Bytes())
}

// BlockSize returns the mode's block size.
func (x *gcm) BlockSize() int { return x.blockSize }

// Encrypts plaintext along with some additional authenticated data, returning
// the encrypted output along with an authentication tag.
func (x *gcm) Encrypt(input io.Reader, aad []byte) (enc, tag []byte) {
    J := x.generatePreCounter()

    icb := make([]byte, len(J))
    copy(icb, J)
    inc32(icb)

    C := x.gctr(icb, input)
    S := x.generateAuthenticationInput(C, aad)

    // counter-mode encrypt with raw pre-counter block (J)j
    T := x.gctr(J, bytes.NewBuffer(S))
    if len(T) > x.tagSize {
        T = T[:x.tagSize]
    }

    return C, T
}

// Decrypts data encoded by Encrypt(). Input also requires the additional
// authenticated data passed to Encrypt() and the authentication tag returned
// by that function. Internally the tag is verified before any attempt is made
// do actually decrypt the input ciphertext.
func (x *gcm) Decrypt(ciphertext, aad, tag []byte) ([]byte, error) {
    if len(tag) != x.tagSize {
        return nil, errors.New("GCM: Invalid tag length")
    }

    J := x.generatePreCounter()
    S := x.generateAuthenticationInput(ciphertext, aad)

    // compute the authentication tag
    T := x.gctr(J, bytes.NewBuffer(S))
    if len(T) > x.tagSize {
        T = T[:x.tagSize]
    }

    if bytes.Compare(T, tag) != 0 {
        return nil, errors.New("GCM decryption failed: tags do not match")
    }

    // if the tag was ok, decrypt the actual data
    inc32(J) // ICB
    return x.gctr(J, bytes.NewBuffer(ciphertext)), nil
}
