package jwe

import (
	"crypto"
	"fmt"

	"github.com/MichaelFraser99/go-jose/internal/algorithms/common"
	"github.com/MichaelFraser99/go-jose/internal/algorithms/direct"
	"github.com/MichaelFraser99/go-jose/internal/algorithms/keywrap"
	"github.com/MichaelFraser99/go-jose/internal/algorithms/rsaoaep"
	"github.com/MichaelFraser99/go-jose/joseerror"
	"github.com/MichaelFraser99/go-jose/jwa"
	"github.com/MichaelFraser99/go-jose/model"
)

// GetEncrypter returns an Encrypter for the key management algorithm alg.
//
// For RSA-OAEP, RSA-OAEP-256, RSA-OAEP-384 and RSA-OAEP-512, key is the
// recipient's *rsa.PublicKey of 2048 bits or more (RFC 7518 section 4.3). For
// A128KW, A192KW and A256KW, key is the shared key of 16, 24 or 32 octets
// (section 4.4). For dir, key is the shared CEK itself (section 4.5). A shared
// key is a []byte, or what Public returns for one, and is copied.
//
// With dir and an AES GCM enc, every token is encrypted under the one shared
// key with a random IV. RFC 7518 section 8.4 says AES GCM MUST NOT be used with
// the same key more than 2^32 times. This library does not count, so a caller
// encrypting more tokens than that under one dir key must change the key.
func GetEncrypter(alg jwa.Algorithm, key crypto.PublicKey) (model.Encrypter, error) {
	var e model.Encrypter
	var err error

	switch alg {
	case jwa.RSAOAEP, jwa.RSAOAEP256, jwa.RSAOAEP384, jwa.RSAOAEP512:
		e, err = rsaoaep.NewEncrypter(alg, key)
	case jwa.A128KW, jwa.A192KW, jwa.A256KW:
		secret, ok := secretBytes(key)
		if !ok {
			return nil, fmt.Errorf("%w%s takes a shared key as a []byte", joseerror.ErrInvalidPublicKey, alg)
		}
		e, err = keywrap.NewEncrypter(alg, secret)
	case jwa.Dir:
		secret, ok := secretBytes(key)
		if !ok {
			return nil, fmt.Errorf("%w%s takes a shared key as a []byte", joseerror.ErrInvalidPublicKey, alg)
		}
		e, err = direct.NewEncrypter(secret)
	case jwa.ES256, jwa.ES384, jwa.ES512, jwa.RS256, jwa.RS384, jwa.RS512, jwa.PS256, jwa.PS384, jwa.PS512, jwa.HS256, jwa.HS384, jwa.HS512, jwa.EdDSA, jwa.Ed25519, jwa.MLDSA44, jwa.MLDSA65, jwa.MLDSA87, jwa.Unknown:
		return nil, fmt.Errorf("%w'%s' is not a key management algorithm this library implements", joseerror.ErrUnsupportedAlgorithm, alg)
	default:
		return nil, fmt.Errorf("%w'%s' is not a key management algorithm this library implements", joseerror.ErrUnsupportedAlgorithm, alg)
	}

	if err != nil {
		return nil, err
	}
	return e, nil
}

// GetDecrypter returns a Decrypter for the key management algorithm alg.
//
// For RSA-OAEP, RSA-OAEP-256, RSA-OAEP-384 and RSA-OAEP-512, key is an
// *rsa.PrivateKey, or a crypto.Decrypter whose Public is an *rsa.PublicKey and
// which accepts *rsa.OAEPOptions, with a modulus of 2048 bits or more (RFC 7518
// section 4.3). For A128KW, A192KW, A256KW and dir, key is the shared key as
// GetEncrypter takes it.
func GetDecrypter(alg jwa.Algorithm, key crypto.PrivateKey) (model.Decrypter, error) {
	var d model.Decrypter
	var err error

	switch alg {
	case jwa.RSAOAEP, jwa.RSAOAEP256, jwa.RSAOAEP384, jwa.RSAOAEP512:
		d, err = rsaoaep.NewDecrypter(alg, key)
	case jwa.A128KW, jwa.A192KW, jwa.A256KW:
		secret, ok := secretBytes(key)
		if !ok {
			return nil, fmt.Errorf("%w%s takes a shared key as a []byte", joseerror.ErrInvalidPrivateKey, alg)
		}
		d, err = keywrap.NewDecrypter(alg, secret)
	case jwa.Dir:
		secret, ok := secretBytes(key)
		if !ok {
			return nil, fmt.Errorf("%w%s takes a shared key as a []byte", joseerror.ErrInvalidPrivateKey, alg)
		}
		d, err = direct.NewDecrypter(secret)
	case jwa.ES256, jwa.ES384, jwa.ES512, jwa.RS256, jwa.RS384, jwa.RS512, jwa.PS256, jwa.PS384, jwa.PS512, jwa.HS256, jwa.HS384, jwa.HS512, jwa.EdDSA, jwa.Ed25519, jwa.MLDSA44, jwa.MLDSA65, jwa.MLDSA87, jwa.Unknown:
		return nil, fmt.Errorf("%w'%s' is not a key management algorithm this library implements", joseerror.ErrUnsupportedAlgorithm, alg)
	default:
		return nil, fmt.Errorf("%w'%s' is not a key management algorithm this library implements", joseerror.ErrUnsupportedAlgorithm, alg)
	}

	if err != nil {
		return nil, err
	}
	return d, nil
}

func secretBytes(key any) ([]byte, bool) {
	switch k := key.(type) {
	case []byte:
		return k, true
	case common.SecretKey:
		return k, true
	}
	return nil, false
}
