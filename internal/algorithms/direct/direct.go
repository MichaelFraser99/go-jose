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

	"github.com/MichaelFraser99/go-jose/internal/algorithms/contentenc"
	"github.com/MichaelFraser99/go-jose/joseerror"
	"github.com/MichaelFraser99/go-jose/jwa"
	"github.com/MichaelFraser99/go-jose/model"
)

// ErrEncryptedKey is returned by Decrypt for a JWE Encrypted Key that is not
// empty, which RFC 7516 section 5.2 step 10 requires of "dir".
var ErrEncryptedKey = errors.New("the JWE Encrypted Key of a dir JWE must be empty")

// ErrOtherEnc is returned by Decrypt for a JWE whose "enc" is not the one the
// key is bound to.
var ErrOtherEnc = errors.New("the dir key is bound to another enc")

// Key is a shared content encryption key bound to the one content encryption
// algorithm it may be used with, as RFC 8725 section 3.1 requires of every key.
// Key must be the length Enc requires.
type Key struct {
	Key []byte
	Enc jwa.Encryption
}

func (k Key) clone() Key {
	return Key{Key: slices.Clone(k.Key), Enc: k.Enc}
}

type Encrypter struct {
	key Key
}

type Decrypter struct {
	key Key
}

func checkKey(key Key, class error) error {
	size := contentenc.KeySize(key.Enc)
	if size == 0 {
		return fmt.Errorf("%w'%s' is not a content encryption algorithm this library implements", joseerror.ErrUnsupportedAlgorithm, key.Enc)
	}
	if len(key.Key) != size {
		return fmt.Errorf("%w%s requires a key of %d octets, got %d", class, key.Enc, size, len(key.Key))
	}
	return nil
}

// NewEncrypter returns an Encrypter that uses key.Key as the CEK for key.Enc
// only. key is copied.
func NewEncrypter(key Key) (*Encrypter, error) {
	if err := checkKey(key, joseerror.ErrInvalidPublicKey); err != nil {
		return nil, err
	}
	return &Encrypter{key: key.clone()}, nil
}

// NewDecrypter returns a Decrypter whose CEK is key.Key, for a JWE whose "enc"
// is key.Enc only. key is copied.
func NewDecrypter(key Key) (*Decrypter, error) {
	if err := checkKey(key, joseerror.ErrInvalidPrivateKey); err != nil {
		return nil, err
	}
	return &Decrypter{key: key.clone()}, nil
}

func (encrypter *Encrypter) Alg() jwa.Algorithm {
	return jwa.Dir
}

// Public returns a copy of the Key, which GetDecrypter accepts.
func (encrypter *Encrypter) Public() crypto.PublicKey {
	return encrypter.key.clone()
}

// WrapKey returns a copy of the shared key as the CEK and an empty JWE Encrypted
// Key (RFC 7518 section 4.5). An enc other than the key's is refused with
// ErrInvalidPublicKey. It adds nothing to header.
func (encrypter *Encrypter) WrapKey(_ io.Reader, enc jwa.Encryption, header map[string]any) (cek, encryptedKey []byte, err error) {
	if enc != encrypter.key.Enc {
		return nil, nil, fmt.Errorf("%wthis dir key is bound to %s, not %s", joseerror.ErrInvalidPublicKey, encrypter.key.Enc, enc)
	}
	return slices.Clone(encrypter.key.Key), []byte{}, nil
}

func (decrypter *Decrypter) Alg() jwa.Algorithm {
	return jwa.Dir
}

// Public returns a copy of the Key.
func (decrypter *Decrypter) Public() crypto.PublicKey {
	return decrypter.key.clone()
}

// Decrypt returns a copy of the shared key as the CEK. msg, the JWE Encrypted
// Key, must be empty, else ErrEncryptedKey, and opts must be a
// model.DecrypterOpts whose Enc is the key's, else ErrOtherEnc.
func (decrypter *Decrypter) Decrypt(_ io.Reader, msg []byte, opts crypto.DecrypterOpts) ([]byte, error) {
	if len(msg) != 0 {
		return nil, ErrEncryptedKey
	}
	if options, ok := opts.(model.DecrypterOpts); !ok || options.Enc != decrypter.key.Enc {
		return nil, ErrOtherEnc
	}
	return slices.Clone(decrypter.key.Key), nil
}
