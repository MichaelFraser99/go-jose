// Package aeskw implements the AES Key Wrap algorithm of RFC 3394, which RFC
// 7518 section 4.4 uses for the A128KW, A192KW and A256KW key management
// algorithms.
package aeskw

import (
	"bytes"
	"crypto/aes"
	"crypto/subtle"
	"encoding/binary"
	"errors"
	"fmt"
)

// ErrUnwrap is the one error Unwrap returns, whatever was wrong, so that the
// failure reveals nothing about the key or the ciphertext. RFC 7516 section 11.5
// requires a JWE recipient not to distinguish these failures.
var ErrUnwrap = errors.New("aes key unwrap failed")

var initialValue = bytes.Repeat([]byte{0xA6}, 8)

// Wrap wraps key with kek as RFC 3394 section 2.2.1 defines. kek is an AES key of
// 16, 24 or 32 octets, and key is at least 16 octets and a multiple of 8.
func Wrap(kek, key []byte) ([]byte, error) {
	block, err := aes.NewCipher(kek)
	if err != nil {
		return nil, fmt.Errorf("a key encryption key is 16, 24 or 32 octets, got %d", len(kek))
	}
	if len(key) < 16 || len(key)%8 != 0 {
		return nil, fmt.Errorf("key data to wrap is at least 16 octets and a multiple of 8, got %d", len(key))
	}
	n := len(key) / 8
	a := bytes.Clone(initialValue)
	r := bytes.Clone(key)
	buf := make([]byte, 16)
	for j := 0; j <= 5; j++ {
		for i := 1; i <= n; i++ {
			copy(buf[:8], a)
			copy(buf[8:], r[(i-1)*8:i*8])
			block.Encrypt(buf, buf)
			binary.BigEndian.PutUint64(a, binary.BigEndian.Uint64(buf[:8])^uint64(n*j+i))
			copy(r[(i-1)*8:i*8], buf[8:])
		}
	}
	return append(a, r...), nil
}

// Unwrap recovers the key data that Wrap wrapped under kek, as RFC 3394 section
// 2.2.2 defines, and checks the integrity value of section 2.2.3 in constant time.
// Any failure is ErrUnwrap.
func Unwrap(kek, wrapped []byte) ([]byte, error) {
	block, err := aes.NewCipher(kek)
	if err != nil {
		return nil, ErrUnwrap
	}
	if len(wrapped) < 24 || len(wrapped)%8 != 0 {
		return nil, ErrUnwrap
	}
	n := len(wrapped)/8 - 1
	a := bytes.Clone(wrapped[:8])
	r := bytes.Clone(wrapped[8:])
	buf := make([]byte, 16)
	for j := 5; j >= 0; j-- {
		for i := n; i >= 1; i-- {
			binary.BigEndian.PutUint64(buf[:8], binary.BigEndian.Uint64(a)^uint64(n*j+i))
			copy(buf[8:], r[(i-1)*8:i*8])
			block.Decrypt(buf, buf)
			copy(a, buf[:8])
			copy(r[(i-1)*8:i*8], buf[8:])
		}
	}
	if subtle.ConstantTimeCompare(a, initialValue) != 1 {
		return nil, ErrUnwrap
	}
	return r, nil
}
