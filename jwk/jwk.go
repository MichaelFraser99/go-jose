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
	ecdsaPK, ecdsaOk := publicKey.(*ecdsa.PublicKey)
	rsaPK, rsaOk := publicKey.(*rsa.PublicKey)
	eddsaPK, eddsaOk := publicKey.(*ed25519.PublicKey)

	if ecdsaOk {
		m := common.JwkFromECDSAPublicKey(ecdsaPK)
		return &m, nil
	}
	if rsaOk {
		m := common.JwkFromRSAPublicKey(rsaPK)
		return &m, nil
	}
	if eddsaOk {
		m := common.JwkFromEdDSAPublicKey(eddsaPK)
		return &m, nil
	}

	return nil, fmt.Errorf("%wunknown public key format provided", joseerror.ErrInvalidPublicKey)
}

func PrivateFromJwk(jwk map[string]any) (crypto.PrivateKey, error) {
	return internal_jwk.PrivateFromJwk(jwk)
}

func PrivateJwk(privateKey crypto.PrivateKey) (*map[string]any, error) {
	ecdsaPK, ecdsaOk := privateKey.(*ecdsa.PrivateKey)
	rsaPK, rsaOk := privateKey.(*rsa.PrivateKey)
	ed25519PK, ed25519Ok := privateKey.(*ed25519.PrivateKey)

	if ecdsaOk {
		m := common.JwkFromECDSAPrivateKey(ecdsaPK)
		return &m, nil
	}
	if rsaOk {
		m := common.JwkFromRSAPrivateKey(rsaPK)
		return &m, nil
	}
	if ed25519Ok { //is just a byte array - should be the last check
		m := common.JwkFromEdDSAPrivateKey(ed25519PK)
		return &m, nil
	}

	return nil, fmt.Errorf("%wunknown private key format provided", joseerror.ErrInvalidPrivateKey)
}
