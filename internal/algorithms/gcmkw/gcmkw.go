// Package gcmkw implements the A128GCMKW, A192GCMKW and A256GCMKW key
// management algorithms of RFC 7518 section 4.7: the CEK is encrypted with AES
// GCM under a shared key of 16, 24 or 32 octets, with a 96-bit IV, empty AAD and
// a 128-bit tag carried in the "iv" and "tag" header parameters.
package gcmkw

import (
	"crypto"
	"crypto/aes"
	"crypto/cipher"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"slices"

	"github.com/MichaelFraser99/go-jose/internal/algorithms/common"
	"github.com/MichaelFraser99/go-jose/internal/algorithms/contentenc"
	"github.com/MichaelFraser99/go-jose/internal/jose/jsonutils"
	"github.com/MichaelFraser99/go-jose/joseerror"
	"github.com/MichaelFraser99/go-jose/jwa"
	"github.com/MichaelFraser99/go-jose/model"
)

// IVSize is the octet length of the "iv" header parameter, the 96 bits RFC
// 7518 section 4.7 requires.
const IVSize = 12

// TagSize is the octet length of the "tag" header parameter, the 128 bits RFC
// 7518 section 4.7 requires.
const TagSize = 16

// ErrUnwrap is the error Decrypt returns for any failure.
var ErrUnwrap = errors.New("AES GCM key unwrap failed")

type Encrypter struct {
	alg jwa.Algorithm
	kek []byte
}

type Decrypter struct {
	alg jwa.Algorithm
	kek []byte
}

var keySizes = map[jwa.Algorithm]int{
	jwa.A128GCMKW: 16,
	jwa.A192GCMKW: 24,
	jwa.A256GCMKW: 32,
}

func checkKey(alg jwa.Algorithm, kek []byte, class error) error {
	size, ok := keySizes[alg]
	if !ok {
		return fmt.Errorf("%w'%s' is not an AES GCM key wrap algorithm", joseerror.ErrUnsupportedAlgorithm, alg)
	}
	if len(kek) != size {
		return fmt.Errorf("%w%s requires a key of %d octets, got %d", class, alg, size, len(kek))
	}
	return nil
}

// NewEncrypter returns an Encrypter for alg that encrypts each new CEK under
// kek, which must be 16, 24 or 32 octets for A128GCMKW, A192GCMKW or A256GCMKW.
// kek is copied.
func NewEncrypter(alg jwa.Algorithm, kek []byte) (*Encrypter, error) {
	if err := checkKey(alg, kek, joseerror.ErrInvalidPublicKey); err != nil {
		return nil, err
	}
	return &Encrypter{alg: alg, kek: slices.Clone(kek)}, nil
}

// NewDecrypter returns a Decrypter for alg that decrypts a CEK with kek, which
// must be 16, 24 or 32 octets for A128GCMKW, A192GCMKW or A256GCMKW. kek is
// copied.
func NewDecrypter(alg jwa.Algorithm, kek []byte) (*Decrypter, error) {
	if err := checkKey(alg, kek, joseerror.ErrInvalidPrivateKey); err != nil {
		return nil, err
	}
	return &Decrypter{alg: alg, kek: slices.Clone(kek)}, nil
}

func newGCM(kek []byte) (cipher.AEAD, error) {
	block, err := aes.NewCipher(kek)
	if err != nil {
		return nil, err
	}
	return cipher.NewGCM(block)
}

func (encrypter *Encrypter) Alg() jwa.Algorithm {
	return encrypter.alg
}

func (encrypter *Encrypter) Public() crypto.PublicKey {
	return common.SecretKey(slices.Clone(encrypter.kek))
}

// WrapKey generates a random CEK of the length enc requires and a random 96-bit
// IV, encrypts the CEK with AES GCM and empty AAD (RFC 7518 section 4.7), and
// writes the IV and tag to header as "iv" and "tag". A header that already holds
// either is refused with ErrMalformedClaim, since section 4.7 makes both the
// output of this encryption.
func (encrypter *Encrypter) WrapKey(rand io.Reader, enc jwa.Encryption, header map[string]any) (cek, encryptedKey []byte, err error) {
	for _, name := range []string{"iv", "tag"} {
		if _, present := header[name]; present {
			return nil, nil, fmt.Errorf("%wthe '%s' header is the output of %s and cannot be given", joseerror.ErrMalformedClaim, name, encrypter.alg)
		}
	}
	size := contentenc.KeySize(enc)
	if size == 0 {
		return nil, nil, fmt.Errorf("%w%s is not a content encryption algorithm this library implements", joseerror.ErrUnsupportedAlgorithm, contentenc.Name(enc))
	}
	aead, err := newGCM(encrypter.kek)
	if err != nil {
		return nil, nil, fmt.Errorf("%w%s", joseerror.ErrEncryptionError, err.Error())
	}
	cek = make([]byte, size)
	if _, err := io.ReadFull(rand, cek); err != nil {
		return nil, nil, fmt.Errorf("%wgenerating a content encryption key: %s", joseerror.ErrEncryptionError, err.Error())
	}
	iv := make([]byte, IVSize)
	if _, err := io.ReadFull(rand, iv); err != nil {
		return nil, nil, fmt.Errorf("%wgenerating a key wrap initialization vector: %s", joseerror.ErrEncryptionError, err.Error())
	}
	sealed := aead.Seal(nil, iv, cek, nil)
	header["iv"] = base64.RawURLEncoding.EncodeToString(iv)
	header["tag"] = base64.RawURLEncoding.EncodeToString(sealed[size:])
	return cek, sealed[:size], nil
}

func (decrypter *Decrypter) Alg() jwa.Algorithm {
	return decrypter.alg
}

func (decrypter *Decrypter) Public() crypto.PublicKey {
	return common.SecretKey(slices.Clone(decrypter.kek))
}

// Decrypt decrypts msg, the JWE Encrypted Key, with AES GCM under the "iv" and
// "tag" of the header in opts, a model.DecrypterOpts, and returns the CEK. Any
// failure is ErrUnwrap.
func (decrypter *Decrypter) Decrypt(_ io.Reader, msg []byte, opts crypto.DecrypterOpts) ([]byte, error) {
	decrypterOpts, ok := opts.(model.DecrypterOpts)
	if !ok {
		return nil, ErrUnwrap
	}
	iv, tag, err := Parameters(decrypterOpts.Header)
	if err != nil {
		return nil, ErrUnwrap
	}
	aead, err := newGCM(decrypter.kek)
	if err != nil {
		return nil, ErrUnwrap
	}
	cek, err := aead.Open(nil, iv, append(slices.Clip(msg), tag...), nil)
	if err != nil {
		return nil, ErrUnwrap
	}
	return cek, nil
}

// Parameters returns the "iv" and "tag" of header. Each must be present (RFC
// 7518 sections 4.7.1.1 and 4.7.1.2), else ErrMissingClaim, and must be a
// base64url string of 12 and 16 octets, else ErrMalformedClaim.
func Parameters(header map[string]any) (iv, tag []byte, err error) {
	for _, member := range []struct {
		name string
		size int
		into *[]byte
	}{{"iv", IVSize, &iv}, {"tag", TagSize, &tag}} {
		value, err := jsonutils.ExtractAndDecodeBase64urlString(header, member.name)
		if err != nil {
			return nil, nil, err
		}
		if len(value) != member.size {
			return nil, nil, fmt.Errorf("%wthe '%s' header must be %d octets, got %d (RFC 7518 section 4.7)", joseerror.ErrMalformedClaim, member.name, member.size, len(value))
		}
		*member.into = value
	}
	return iv, tag, nil
}
