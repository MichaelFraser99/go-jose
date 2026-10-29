// Package direct implements "dir", direct encryption with a shared symmetric
// key, of RFC 7518 section 4.5: the shared key is the CEK, and the JWE
// Encrypted Key is empty.
package direct

import (
	"crypto"
	"errors"
	"fmt"
	"io"
	"slices"

	"github.com/MichaelFraser99/go-jose/internal/algorithms/common"
	"github.com/MichaelFraser99/go-jose/internal/algorithms/contentenc"
	"github.com/MichaelFraser99/go-jose/joseerror"
	"github.com/MichaelFraser99/go-jose/jwa"
)

// ErrEncryptedKey is returned by Decrypt for a JWE Encrypted Key that is not
// empty, which RFC 7516 section 5.2 step 10 requires of "dir".
var ErrEncryptedKey = errors.New("the JWE Encrypted Key of a dir JWE must be empty")

type Encrypter struct {
	key []byte
}

type Decrypter struct {
	key []byte
}

func checkKey(key []byte, class error) error {
	for _, enc := range []jwa.Encryption{jwa.A128GCM, jwa.A192GCM, jwa.A256GCM, jwa.A128CBCHS256, jwa.A192CBCHS384, jwa.A256CBCHS512} {
		if contentenc.KeySize(enc) == len(key) {
			return nil
		}
	}
	return fmt.Errorf("%wa dir key is a content encryption key of 16, 24, 32, 48 or 64 octets, got %d", class, len(key))
}

// NewEncrypter returns an Encrypter that uses key as the CEK. key must be the
// length of a content encryption key; WrapKey refuses an enc whose length it is
// not. key is copied.
func NewEncrypter(key []byte) (*Encrypter, error) {
	if err := checkKey(key, joseerror.ErrInvalidPublicKey); err != nil {
		return nil, err
	}
	return &Encrypter{key: slices.Clone(key)}, nil
}

// NewDecrypter returns a Decrypter whose CEK is key. key must be the length of a
// content encryption key. key is copied.
func NewDecrypter(key []byte) (*Decrypter, error) {
	if err := checkKey(key, joseerror.ErrInvalidPrivateKey); err != nil {
		return nil, err
	}
	return &Decrypter{key: slices.Clone(key)}, nil
}

func (encrypter *Encrypter) Alg() jwa.Algorithm {
	return jwa.Dir
}

func (encrypter *Encrypter) Public() crypto.PublicKey {
	return common.SecretKey(slices.Clone(encrypter.key))
}

// WrapKey returns a copy of the shared key as the CEK and an empty JWE Encrypted
// Key (RFC 7518 section 4.5). An enc whose key length differs from the shared
// key's is refused. It adds nothing to header.
func (encrypter *Encrypter) WrapKey(_ io.Reader, enc jwa.Encryption, header map[string]any) (cek, encryptedKey []byte, err error) {
	size := contentenc.KeySize(enc)
	if size == 0 {
		return nil, nil, fmt.Errorf("%w'%s' is not a content encryption algorithm this library implements", joseerror.ErrUnsupportedAlgorithm, enc)
	}
	if size != len(encrypter.key) {
		return nil, nil, fmt.Errorf("%w%s requires a key of %d octets, and this dir key is %d", joseerror.ErrInvalidPublicKey, enc, size, len(encrypter.key))
	}
	return slices.Clone(encrypter.key), []byte{}, nil
}

func (decrypter *Decrypter) Alg() jwa.Algorithm {
	return jwa.Dir
}

func (decrypter *Decrypter) Public() crypto.PublicKey {
	return common.SecretKey(slices.Clone(decrypter.key))
}

// Decrypt returns a copy of the shared key as the CEK. msg, the JWE Encrypted
// Key, must be empty, else ErrEncryptedKey. opts is not read.
func (decrypter *Decrypter) Decrypt(_ io.Reader, msg []byte, _ crypto.DecrypterOpts) ([]byte, error) {
	if len(msg) != 0 {
		return nil, ErrEncryptedKey
	}
	return slices.Clone(decrypter.key), nil
}
