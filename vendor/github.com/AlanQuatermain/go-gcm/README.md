# Galois/Counter Mode Cipher Operation for Go

Version 1.0 -- 29 Oct 2012

## Introduction

In putting together some tools for the correct handling of [XML Encryption][XMLENC] and [XML Digital Signatures][XMLDSig], I ran across the AES-GCM encryption mode. This is included in the XML-ENC 2.0 working draft in large part due to [problems with the more common CBC mode][cbc-warning] of operation. Sadly, there aren't very many easily-accessible implementations of this algorithm out there, and Go is definitely lacking it. I decided I'd try to write one myself.

The package provided here is designed as if it were a part of the [crypto][go-crypto] package, and thus it operates in conjunction with a block Cipher. It could absolutely be made faster: using Go's concurrency primitives would be one way, and implementing the core GHASH and GCTR algorithms in assembler with SIMD instructions is another. I'll probably look into the former myself, but I doubt I'll go as far as the latter.

[XMLENC]: http://www.w3.org/TR/2012/WD-xmlenc-core1-20121018/
[XMLDSig]: http://www.w3.org/TR/xmldsig-core2/
[cbc-warning]: http://www.w3.org/TR/2012/WD-xmlenc-core1-20121018/#cbc-warning
[go-crypto]: http://golang.org/pkg/crypto/

## Installation

Use `go get github.com/AlanQuatermain/go-gcm` to install, and then import it using `import gcm "github.com/AlanQuatermain/go-gcm"`.

##Documentation

Generated documentation for the package's small API can be seen below.

### Package

	package gcm
	    import "gcm"

The GCM package provides an implementation of the Galois/Counter Mode of
operation for symmetric block ciphers. It provides authenticated
encryption, meaning that it both encrypts content and generates an
authentication tag similar to an HMAC operation.

### Types

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

This cryptography mode encompasses both encryption and authentication of
data. Due to its differing inputs and outputs, it doesn't conform to the
cipher.Cipher interface, instead providing separate Encrypt() and
Decrypt() methods.

	func NewGCM(b cipher.Block, tagSizeInBits int, iv []byte) (GaloisCounterMode, error)

Creates a new Galois/Counter Mode for a given block cipher. The iv
parameter is required, but a tagSizeInBits of zero can be supplied, in
which case the default tag size of 128 bits will be used.


