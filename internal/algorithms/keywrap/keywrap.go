// Package keywrap implements the A128KW, A192KW and A256KW key management
// algorithms of RFC 7518 section 4.4: the CEK is wrapped with AES Key Wrap
// (RFC 3394) under a shared key of 16, 24 or 32 octets.
package keywrap

import (
	"crypto"
	"fmt"
	"io"
	"slices"

	"github.com/MichaelFraser99/go-jose/internal/algorithms/aeskw"
	"github.com/MichaelFraser99/go-jose/internal/algorithms/common"
	"github.com/MichaelFraser99/go-jose/internal/algorithms/contentenc"
	"github.com/MichaelFraser99/go-jose/joseerror"
	"github.com/MichaelFraser99/go-jose/jwa"
)

type Encrypter struct {
	alg jwa.Algorithm
	kek []byte
}

type Decrypter struct {
	alg jwa.Algorithm
	kek []byte
}

var keySizes = map[jwa.Algorithm]int{
	jwa.A128KW: 16,
	jwa.A192KW: 24,
	jwa.A256KW: 32,
}

func checkKey(alg jwa.Algorithm, kek []byte, class error) error {
	size, ok := keySizes[alg]
	if !ok {
		return fmt.Errorf("%w'%s' is not an AES Key Wrap algorithm", joseerror.ErrUnsupportedAlgorithm, alg)
	}
	if len(kek) != size {
		return fmt.Errorf("%w%s requires a key of %d octets, got %d", class, alg, size, len(kek))
	}
	return nil
}

// NewEncrypter returns an Encrypter for alg that wraps each new CEK under kek,
// which must be 16, 24 or 32 octets for A128KW, A192KW or A256KW. kek is copied.
func NewEncrypter(alg jwa.Algorithm, kek []byte) (*Encrypter, error) {
	if err := checkKey(alg, kek, joseerror.ErrInvalidPublicKey); err != nil {
		return nil, err
	}
	return &Encrypter{alg: alg, kek: slices.Clone(kek)}, nil
}

// NewDecrypter returns a Decrypter for alg that unwraps a CEK with kek, which
// must be 16, 24 or 32 octets for A128KW, A192KW or A256KW. kek is copied.
func NewDecrypter(alg jwa.Algorithm, kek []byte) (*Decrypter, error) {
	if err := checkKey(alg, kek, joseerror.ErrInvalidPrivateKey); err != nil {
		return nil, err
	}
	return &Decrypter{alg: alg, kek: slices.Clone(kek)}, nil
}

func (encrypter *Encrypter) Alg() jwa.Algorithm {
	return encrypter.alg
}

func (encrypter *Encrypter) Public() crypto.PublicKey {
	return common.SecretKey(slices.Clone(encrypter.kek))
}

// WrapKey generates a random CEK of the length enc requires and wraps it with
// AES Key Wrap (RFC 7518 section 4.4). It adds nothing to header.
func (encrypter *Encrypter) WrapKey(rand io.Reader, enc jwa.Encryption, header map[string]any) (cek, encryptedKey []byte, err error) {
	size := contentenc.KeySize(enc)
	if size == 0 {
		return nil, nil, fmt.Errorf("%w'%s' is not a content encryption algorithm this library implements", joseerror.ErrUnsupportedAlgorithm, enc)
	}
	cek = make([]byte, size)
	if _, err := io.ReadFull(rand, cek); err != nil {
		return nil, nil, fmt.Errorf("%wgenerating a content encryption key: %s", joseerror.ErrEncryptionError, err.Error())
	}
	encryptedKey, err = aeskw.Wrap(encrypter.kek, cek)
	if err != nil {
		return nil, nil, fmt.Errorf("%wwrapping the content encryption key: %s", joseerror.ErrEncryptionError, err.Error())
	}
	return cek, encryptedKey, nil
}

func (decrypter *Decrypter) Alg() jwa.Algorithm {
	return decrypter.alg
}

func (decrypter *Decrypter) Public() crypto.PublicKey {
	return common.SecretKey(slices.Clone(decrypter.kek))
}

// Decrypt unwraps msg, the JWE Encrypted Key, with AES Key Wrap and returns the
// CEK. Any failure is aeskw.ErrUnwrap. opts is not read.
func (decrypter *Decrypter) Decrypt(_ io.Reader, msg []byte, _ crypto.DecrypterOpts) ([]byte, error) {
	return aeskw.Unwrap(decrypter.kek, msg)
}
