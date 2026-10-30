// Package contentenc builds the authenticated encryption that a JWE "enc" value
// names, from RFC 7518 section 5.
package contentenc

import (
	"crypto/aes"
	"crypto/cipher"
	"fmt"

	"github.com/MichaelFraser99/go-jose/internal/algorithms/cbchmac"
	"github.com/MichaelFraser99/go-jose/joseerror"
	"github.com/MichaelFraser99/go-jose/jwa"
)

// KeySize returns the length in octets of the Content Encryption Key enc uses:
// twice the AES key for AES_CBC_HMAC_SHA2 (RFC 7518 section 5.2.3 to 5.2.5) and
// the AES key for AES GCM (section 5.3). It returns 0 for an enc this library
// does not implement.
func KeySize(enc jwa.Encryption) int {
	switch enc {
	case jwa.A128CBCHS256:
		return 32
	case jwa.A192CBCHS384:
		return 48
	case jwa.A256CBCHS512:
		return 64
	case jwa.A128GCM:
		return 16
	case jwa.A192GCM:
		return 24
	case jwa.A256GCM:
		return 32
	case jwa.UnknownEncryption:
	}
	return 0
}

// New returns the AEAD for enc keyed with cek. Its NonceSize is the length of
// the JWE Initialization Vector, 16 octets for AES_CBC_HMAC_SHA2 and 12 for AES
// GCM (RFC 7518 sections 5.2.2.1 and 5.3), and its Overhead the length of the
// Authentication Tag. A cek of the wrong length for enc is refused.
func New(enc jwa.Encryption, cek []byte) (cipher.AEAD, error) {
	size := KeySize(enc)
	if size == 0 {
		return nil, fmt.Errorf("%w'%s' is not a content encryption algorithm this library implements", joseerror.ErrUnsupportedAlgorithm, enc)
	}
	if len(cek) != size {
		return nil, fmt.Errorf("%s requires a content encryption key of %d octets, got %d", enc, size, len(cek))
	}
	if enc == jwa.A128CBCHS256 || enc == jwa.A192CBCHS384 || enc == jwa.A256CBCHS512 {
		return cbchmac.New(cek)
	}
	block, err := aes.NewCipher(cek)
	if err != nil {
		return nil, err
	}
	return cipher.NewGCM(block)
}
