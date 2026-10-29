// Package cbchmac implements AES_CBC_HMAC_SHA2 authenticated encryption as RFC
// 7518 section 5.2 defines it, for A128CBC-HS256, A192CBC-HS384 and
// A256CBC-HS512, behind the crypto/cipher AEAD interface.
package cbchmac

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/binary"
	"errors"
	"fmt"
	"hash"
)

// ErrOpen is the one error Open returns, whatever was wrong, so that neither the
// tag check nor the padding is an oracle. RFC 7516 section 11.5 requires a JWE
// recipient not to distinguish these failures.
var ErrOpen = errors.New("authenticated decryption failed")

const ivSize = aes.BlockSize

type aead struct {
	macKey []byte
	block  cipher.Block
	hash   func() hash.Hash
	tagLen int
}

var sha256Hash = sha256.New

// New returns the AEAD that RFC 7518 section 5.2 defines for a key of 32, 48 or
// 64 octets: A128CBC-HS256, A192CBC-HS384 or A256CBC-HS512. The first half of
// the key is the MAC key and the second half the encryption key, and the tag is
// the first half of the HMAC output.
func New(key []byte) (cipher.AEAD, error) {
	var h func() hash.Hash
	switch len(key) {
	case 32:
		h = sha256Hash
	case 48:
		h = sha512.New384
	case 64:
		h = sha512.New
	default:
		return nil, fmt.Errorf("an AES_CBC_HMAC_SHA2 key is 32, 48 or 64 octets, got %d", len(key))
	}
	half := len(key) / 2
	block, err := newBlock(key[half:])
	if err != nil {
		return nil, err
	}
	return &aead{
		macKey: append([]byte(nil), key[:half]...),
		block:  block,
		hash:   h,
		tagLen: half,
	}, nil
}

func newBlock(key []byte) (cipher.Block, error) {
	return aes.NewCipher(key)
}

func (a *aead) NonceSize() int { return ivSize }

func (a *aead) Overhead() int { return a.tagLen }

// Seal encrypts plaintext under nonce, the 16-octet IV, and returns dst with the
// ciphertext E and the tag T appended, as RFC 7518 section 5.2.2.1 defines. Like
// every cipher.AEAD, it panics on a nonce of the wrong length.
func (a *aead) Seal(dst, nonce, plaintext, additionalData []byte) []byte {
	if len(nonce) != ivSize {
		panic("cbchmac: the IV must be 16 octets")
	}
	padding := ivSize - len(plaintext)%ivSize
	padded := make([]byte, len(plaintext)+padding)
	copy(padded, plaintext)
	for i := len(plaintext); i < len(padded); i++ {
		padded[i] = byte(padding)
	}
	ciphertext := make([]byte, len(padded))
	cipher.NewCBCEncrypter(a.block, nonce).CryptBlocks(ciphertext, padded)
	tag := authenticate(a.macKey, a.hash, a.tagLen, additionalData, nonce, ciphertext)
	return append(append(dst, ciphertext...), tag...)
}

// Open checks the tag before it decrypts, as RFC 7518 section 5.2.2.2 requires,
// and returns ErrOpen for any failure, a malformed input included.
func (a *aead) Open(dst, nonce, sealed, additionalData []byte) ([]byte, error) {
	if len(nonce) != ivSize || len(sealed) < a.tagLen+ivSize || (len(sealed)-a.tagLen)%ivSize != 0 {
		return nil, ErrOpen
	}
	ciphertext, tag := sealed[:len(sealed)-a.tagLen], sealed[len(sealed)-a.tagLen:]
	if !hmac.Equal(tag, authenticate(a.macKey, a.hash, a.tagLen, additionalData, nonce, ciphertext)) {
		return nil, ErrOpen
	}
	padded := make([]byte, len(ciphertext))
	cipher.NewCBCDecrypter(a.block, nonce).CryptBlocks(padded, ciphertext)
	padding := int(padded[len(padded)-1])
	if padding == 0 || padding > ivSize {
		return nil, ErrOpen
	}
	for _, b := range padded[len(padded)-padding:] {
		if int(b) != padding {
			return nil, ErrOpen
		}
	}
	return append(dst, padded[:len(padded)-padding]...), nil
}

func authenticate(macKey []byte, h func() hash.Hash, tagLen int, additionalData, iv, ciphertext []byte) []byte {
	mac := hmac.New(h, macKey)
	mac.Write(additionalData)
	mac.Write(iv)
	mac.Write(ciphertext)
	mac.Write(binary.BigEndian.AppendUint64(nil, uint64(len(additionalData))*8))
	return mac.Sum(nil)[:tagLen]
}
