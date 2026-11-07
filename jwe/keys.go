package jwe

import (
	"crypto"
	"fmt"
	"slices"

	"github.com/MichaelFraser99/go-jose/internal/algorithms/common"
	"github.com/MichaelFraser99/go-jose/internal/algorithms/direct"
	"github.com/MichaelFraser99/go-jose/internal/algorithms/ecdhes"
	"github.com/MichaelFraser99/go-jose/internal/algorithms/gcmkw"
	"github.com/MichaelFraser99/go-jose/internal/algorithms/keywrap"
	"github.com/MichaelFraser99/go-jose/internal/algorithms/pbes2"
	"github.com/MichaelFraser99/go-jose/internal/algorithms/rsaoaep"
	"github.com/MichaelFraser99/go-jose/joseerror"
	"github.com/MichaelFraser99/go-jose/jwa"
	"github.com/MichaelFraser99/go-jose/model"
)

// DirectKey is the key for "dir": a shared content encryption key bound to the
// one "enc" it may be used with, as RFC 8725 section 3.1 requires of every key.
// Key must be the length Enc requires: 32, 48 or 64 octets for A128CBC-HS256,
// A192CBC-HS384 or A256CBC-HS512, and 16, 24 or 32 for A128GCM, A192GCM or
// A256GCM. Pass it by value.
type DirectKey struct {
	Key []byte
	Enc jwa.Encryption
}

type directEncrypter struct {
	*direct.Encrypter
	key DirectKey
}

func (d *directEncrypter) Public() crypto.PublicKey {
	return DirectKey{Key: slices.Clone(d.key.Key), Enc: d.key.Enc}
}

type directDecrypter struct {
	*direct.Decrypter
	key DirectKey
}

func (d *directDecrypter) Public() crypto.PublicKey {
	return DirectKey{Key: slices.Clone(d.key.Key), Enc: d.key.Enc}
}

// PasswordKey is the key for PBES2-HS256+A128KW, PBES2-HS384+A192KW and
// PBES2-HS512+A256KW: a password, as octets, and the PBKDF2 iteration count to
// encrypt with (RFC 7518 section 4.8). A text password must be its UTF-8
// encoding, as section 4.8 requires. Password must not be empty.
//
// Count is the "p2c" each token is encrypted with. Zero means 600,000, the
// figure draft-ietf-oauth-rfc8725bis section 3.13 cites from OWASP. A negative
// Count is refused, as section 4.8.1.2 requires a positive "p2c". A Count
// below 1000 is accepted, because the section only recommends that minimum,
// but each iteration fewer makes the password cheaper to guess from a token,
// and a recipient with RequireRecommendedPBES2Count set refuses it. A
// recipient using jwe.Decrypt's default refuses more than 1,200,000. A decrypter reads the count from each token and ignores Count.
// Pass it by value.
type PasswordKey struct {
	Password []byte
	Count    int
}

type passwordEncrypter struct {
	*pbes2.Encrypter
	key PasswordKey
}

func (p *passwordEncrypter) Public() crypto.PublicKey {
	return PasswordKey{Password: slices.Clone(p.key.Password), Count: p.key.Count}
}

type passwordDecrypter struct {
	*pbes2.Decrypter
	key PasswordKey
}

func (p *passwordDecrypter) Public() crypto.PublicKey {
	return PasswordKey{Password: slices.Clone(p.key.Password), Count: p.key.Count}
}

// GetEncrypter returns an Encrypter for the key management algorithm alg.
//
// For RSA-OAEP, RSA-OAEP-256, RSA-OAEP-384 and RSA-OAEP-512, key is the
// recipient's *rsa.PublicKey with a modulus of 2048 to 8192 bits (RFC 7518
// section 4.3 sets the minimum). For ECDH-ES, ECDH-ES+A128KW, ECDH-ES+A192KW
// and ECDH-ES+A256KW, key is the recipient's *ecdsa.PublicKey on P-256, P-384
// or P-521, or *ecdh.PublicKey on one of those curves or X25519 (section 4.6,
// RFC 8037 section 3.2). For A128KW, A192KW and A256KW (section 4.4), and for
// A128GCMKW, A192GCMKW and A256GCMKW (section 4.7), key is the shared key of 16,
// 24 or 32 octets, or what Public returns for one. For dir, key is a DirectKey
// (section 4.5), and Encrypt refuses any other enc. For PBES2-HS256+A128KW,
// PBES2-HS384+A192KW and PBES2-HS512+A256KW, key is a PasswordKey (section
// 4.8). A shared key or password is copied.
//
// A shared key has no public half, so the Public method of an A128KW, A192KW,
// A256KW, AES GCM key wrap, PBES2 or dir Encrypter returns the secret itself,
// as an HMAC Signer's does. Do not log or publish what it returns.
//
// With dir and an AES GCM enc, or with an AES GCM key wrap alg, every token is
// encrypted under the one shared key with a random IV. RFC 7518 section 8.4
// says AES GCM MUST NOT be used with the same key more than 2^32 times. This
// library does not count, so a caller encrypting more tokens than that under
// one such key must change the key.
func GetEncrypter(alg jwa.Algorithm, key crypto.PublicKey) (model.Encrypter, error) {
	var e model.Encrypter
	var err error

	switch alg {
	case jwa.RSAOAEP, jwa.RSAOAEP256, jwa.RSAOAEP384, jwa.RSAOAEP512:
		e, err = rsaoaep.NewEncrypter(alg, key)
	case jwa.ECDHES, jwa.ECDHESA128KW, jwa.ECDHESA192KW, jwa.ECDHESA256KW:
		e, err = ecdhes.NewEncrypter(alg, key)
	case jwa.A128KW, jwa.A192KW, jwa.A256KW:
		secret, ok := secretBytes(key)
		if !ok {
			return nil, fmt.Errorf("%w%s takes a shared key as a []byte", joseerror.ErrInvalidPublicKey, alg)
		}
		e, err = keywrap.NewEncrypter(alg, secret)
	case jwa.A128GCMKW, jwa.A192GCMKW, jwa.A256GCMKW:
		secret, ok := secretBytes(key)
		if !ok {
			return nil, fmt.Errorf("%w%s takes a shared key as a []byte", joseerror.ErrInvalidPublicKey, alg)
		}
		e, err = gcmkw.NewEncrypter(alg, secret)
	case jwa.PBES2HS256A128KW, jwa.PBES2HS384A192KW, jwa.PBES2HS512A256KW:
		passwordKey, ok := key.(PasswordKey)
		if !ok {
			return nil, fmt.Errorf("%w%s takes a jwe.PasswordKey", joseerror.ErrInvalidPublicKey, alg)
		}
		inner, err := pbes2.NewEncrypter(alg, passwordKey.Password, passwordKey.Count)
		if err != nil {
			return nil, err
		}
		return &passwordEncrypter{Encrypter: inner, key: PasswordKey{Password: slices.Clone(passwordKey.Password), Count: passwordKey.Count}}, nil
	case jwa.Dir:
		directKey, ok := key.(DirectKey)
		if !ok {
			return nil, fmt.Errorf("%wdir takes a jwe.DirectKey", joseerror.ErrInvalidPublicKey)
		}
		inner, err := direct.NewEncrypter(direct.Key{Key: directKey.Key, Enc: directKey.Enc})
		if err != nil {
			return nil, err
		}
		return &directEncrypter{Encrypter: inner, key: DirectKey{Key: slices.Clone(directKey.Key), Enc: directKey.Enc}}, nil
	case jwa.ES256, jwa.ES384, jwa.ES512, jwa.RS256, jwa.RS384, jwa.RS512, jwa.PS256, jwa.PS384, jwa.PS512, jwa.HS256, jwa.HS384, jwa.HS512, jwa.EdDSA, jwa.Ed25519, jwa.MLDSA44, jwa.MLDSA65, jwa.MLDSA87, jwa.Unknown:
		return nil, fmt.Errorf("%w%s is not a key management algorithm this library implements", joseerror.ErrUnsupportedAlgorithm, algorithmName(alg))
	default:
		return nil, fmt.Errorf("%w%s is not a key management algorithm this library implements", joseerror.ErrUnsupportedAlgorithm, algorithmName(alg))
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
// which accepts *rsa.OAEPOptions, with a modulus of 2048 to 8192 bits (RFC 7518
// section 4.3 sets the minimum). For the ECDH-ES algorithms, key is an
// *ecdsa.PrivateKey on P-256, P-384 or P-521, or an *ecdh.PrivateKey on one of
// those curves or X25519, and a JWE whose "epk" is on another curve fails as
// ErrDecryptionFailed (RFC 8725 section 3.4). For A128KW, A192KW, A256KW, the
// AES GCM key wraps and dir, key is the shared key as GetEncrypter takes it. A
// dir Decrypter decrypts only a JWE whose "enc" is the DirectKey's; any other
// fails as ErrDecryptionFailed. For the PBES2 algorithms, key is a PasswordKey,
// whose Count is ignored: each JWE names its own "p2c", which Decrypt bounds
// with JoseOptions.MaxPBES2Count. The Decrypter's own Decrypt method runs as
// many iterations as the header it is given names, so pass a PBES2 Decrypter
// only to Decrypt.
func GetDecrypter(alg jwa.Algorithm, key crypto.PrivateKey) (model.Decrypter, error) {
	var d model.Decrypter
	var err error

	switch alg {
	case jwa.RSAOAEP, jwa.RSAOAEP256, jwa.RSAOAEP384, jwa.RSAOAEP512:
		d, err = rsaoaep.NewDecrypter(alg, key)
	case jwa.ECDHES, jwa.ECDHESA128KW, jwa.ECDHESA192KW, jwa.ECDHESA256KW:
		d, err = ecdhes.NewDecrypter(alg, key)
	case jwa.A128KW, jwa.A192KW, jwa.A256KW:
		secret, ok := secretBytes(key)
		if !ok {
			return nil, fmt.Errorf("%w%s takes a shared key as a []byte", joseerror.ErrInvalidPrivateKey, alg)
		}
		d, err = keywrap.NewDecrypter(alg, secret)
	case jwa.A128GCMKW, jwa.A192GCMKW, jwa.A256GCMKW:
		secret, ok := secretBytes(key)
		if !ok {
			return nil, fmt.Errorf("%w%s takes a shared key as a []byte", joseerror.ErrInvalidPrivateKey, alg)
		}
		d, err = gcmkw.NewDecrypter(alg, secret)
	case jwa.PBES2HS256A128KW, jwa.PBES2HS384A192KW, jwa.PBES2HS512A256KW:
		passwordKey, ok := key.(PasswordKey)
		if !ok {
			return nil, fmt.Errorf("%w%s takes a jwe.PasswordKey", joseerror.ErrInvalidPrivateKey, alg)
		}
		inner, err := pbes2.NewDecrypter(alg, passwordKey.Password)
		if err != nil {
			return nil, err
		}
		return &passwordDecrypter{Decrypter: inner, key: PasswordKey{Password: slices.Clone(passwordKey.Password), Count: passwordKey.Count}}, nil
	case jwa.Dir:
		directKey, ok := key.(DirectKey)
		if !ok {
			return nil, fmt.Errorf("%wdir takes a jwe.DirectKey", joseerror.ErrInvalidPrivateKey)
		}
		inner, err := direct.NewDecrypter(direct.Key{Key: directKey.Key, Enc: directKey.Enc})
		if err != nil {
			return nil, err
		}
		return &directDecrypter{Decrypter: inner, key: DirectKey{Key: slices.Clone(directKey.Key), Enc: directKey.Enc}}, nil
	case jwa.ES256, jwa.ES384, jwa.ES512, jwa.RS256, jwa.RS384, jwa.RS512, jwa.PS256, jwa.PS384, jwa.PS512, jwa.HS256, jwa.HS384, jwa.HS512, jwa.EdDSA, jwa.Ed25519, jwa.MLDSA44, jwa.MLDSA65, jwa.MLDSA87, jwa.Unknown:
		return nil, fmt.Errorf("%w%s is not a key management algorithm this library implements", joseerror.ErrUnsupportedAlgorithm, algorithmName(alg))
	default:
		return nil, fmt.Errorf("%w%s is not a key management algorithm this library implements", joseerror.ErrUnsupportedAlgorithm, algorithmName(alg))
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

func algorithmName(alg jwa.Algorithm) string {
	if name := alg.String(); name != "" {
		return fmt.Sprintf("%q", name)
	}
	return fmt.Sprintf("jwa.Algorithm(%d)", int(alg))
}
