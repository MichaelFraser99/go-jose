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

func PublicFromJwk(jwk map[string]any) (crypto.PublicKey, error) {
	return internal_jwk.PublicFromJwk(jwk)
}

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
	default:
		return nil, fmt.Errorf("%wunknown public key format provided", joseerror.ErrInvalidPublicKey)
	}
	if err != nil {
		return nil, err
	}
	return &m, nil
}

func PrivateFromJwk(jwk map[string]any) (crypto.PrivateKey, error) {
	return internal_jwk.PrivateFromJwk(jwk)
}

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
	default:
		return nil, fmt.Errorf("%wunknown private key format provided", joseerror.ErrInvalidPrivateKey)
	}
	if err != nil {
		return nil, err
	}
	return &m, nil
}

// Thumbprint computes the RFC 7638 JWK SHA-256 Thumbprint of a jwk, base64url
// encoded. It is the "kid" PublicJwk and PrivateJwk give a key, and the
// thumbprint of a private jwk is that of its public key.
func Thumbprint(jwk map[string]any) (string, error) {
	return common.Thumbprint(jwk)
}
