package jwk

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
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
	default:
		return nil, fmt.Errorf("%wunknown private key format provided", joseerror.ErrInvalidPrivateKey)
	}
	if err != nil {
		return nil, err
	}
	return &m, nil
}
