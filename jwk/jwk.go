package jwk

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/mldsa"
	"crypto/rsa"
	"fmt"
	"github.com/MichaelFraser99/go-jose/internal/algorithms/common"
	internal_jwk "github.com/MichaelFraser99/go-jose/internal/jose/jwk"
	"github.com/MichaelFraser99/go-jose/joseerror"
)

// PublicFromJwk reads a public key from its jwk. An "oct" jwk is refused with
// ErrInvalidPublicKey: a symmetric key (RFC 7518 section 6.4) has no public half.
func PublicFromJwk(jwk map[string]any) (crypto.PublicKey, error) {
	return internal_jwk.PublicFromJwk(jwk)
}

// PublicJwk builds the jwk of a public key. A symmetric key is refused with
// ErrInvalidPublicKey, as it has no public half.
func PublicJwk(publicKey crypto.PublicKey) (*map[string]any, error) {
	var m map[string]any
	var err error
	switch key := publicKey.(type) {
	case *ecdsa.PublicKey:
		m, err = common.JwkFromECDSAPublicKey(key)
	case *rsa.PublicKey:
		m, err = common.JwkFromRSAPublicKey(key)
	case *ed25519.PublicKey:
		m, err = common.JwkFromEdDSAPublicKey(key)
	case ed25519.PublicKey:
		m, err = common.JwkFromEdDSAPublicKey(&key)
	case *mldsa.PublicKey:
		m, err = common.JwkFromMLDSAPublicKey(key)
	case []byte, common.SecretKey:
		return nil, fmt.Errorf("%wa symmetric key has no public half, so it has no public jwk", joseerror.ErrInvalidPublicKey)
	default:
		return nil, fmt.Errorf("%wunknown public key format provided", joseerror.ErrInvalidPublicKey)
	}
	if err != nil {
		return nil, err
	}
	return &m, nil
}

// PrivateFromJwk reads a private or symmetric key from its jwk. An "oct" jwk
// (RFC 7518 section 6.4) is returned as a []byte; its "k" must be present,
// strict base64url and not empty.
func PrivateFromJwk(jwk map[string]any) (crypto.PrivateKey, error) {
	return internal_jwk.PrivateFromJwk(jwk)
}

// PrivateJwk builds the jwk of a private key. A symmetric key, as a []byte or
// what Public returns for one, becomes an "oct" jwk (RFC 7518 section 6.4) with
// no "kid", as RFC 7638 section 7 says its thumbprint should be concealed.
func PrivateJwk(privateKey crypto.PrivateKey) (*map[string]any, error) {
	var m map[string]any
	var err error
	switch key := privateKey.(type) {
	case *ecdsa.PrivateKey:
		m, err = common.JwkFromECDSAPrivateKey(key)
	case *rsa.PrivateKey:
		m, err = common.JwkFromRSAPrivateKey(key)
	case *ed25519.PrivateKey:
		m, err = common.JwkFromEdDSAPrivateKey(key)
	case ed25519.PrivateKey:
		m, err = common.JwkFromEdDSAPrivateKey(&key)
	case *mldsa.PrivateKey:
		m, err = common.JwkFromMLDSAPrivateKey(key)
	case []byte:
		m, err = common.JwkFromSecretKey(key)
	case common.SecretKey:
		m, err = common.JwkFromSecretKey(key)
	default:
		return nil, fmt.Errorf("%wunknown private key format provided", joseerror.ErrInvalidPrivateKey)
	}
	if err != nil {
		return nil, err
	}
	return &m, nil
}

// Thumbprint computes the RFC 7638 JWK SHA-256 Thumbprint of a jwk, base64url
// encoded. It is the "kid" PublicJwk and PrivateJwk give an asymmetric key, and
// the thumbprint of a private jwk is that of its public key. RFC 7638 section 7
// says the thumbprint of an "oct" jwk should be concealed from parties not
// holding the key.
func Thumbprint(jwk map[string]any) (string, error) {
	return common.Thumbprint(jwk)
}
