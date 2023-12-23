package jwk

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/rsa"
	"fmt"
	e "github.com/MichaelFraser99/go-jose/error"
	"github.com/MichaelFraser99/go-jose/internal/algorithms/common"
)

func PublicJwk(publicKey crypto.PublicKey) (*map[string]any, error) {
	ecdsaPK, ecdsaOk := publicKey.(*ecdsa.PublicKey)
	rsaPK, rsaOk := publicKey.(*rsa.PublicKey)

	if ecdsaOk {
		m := common.JwkFromECDSAPublicKey(ecdsaPK)
		return &m, nil
	}
	if rsaOk {
		m := common.JwkFromRSAPublicKey(rsaPK)
		return &m, nil
	}

	return nil, fmt.Errorf("%wunknown public key format provided", e.InvalidPublicKey)
}

func PrivateJwk(privateKey crypto.PrivateKey) (*map[string]any, error) {
	ecdsaPK, ecdsaOk := privateKey.(*ecdsa.PrivateKey)
	rsaPK, rsaOk := privateKey.(*rsa.PrivateKey)

	if ecdsaOk {
		m := common.JwkFromECDSAPrivateKey(ecdsaPK)
		return &m, nil
	}
	if rsaOk {
		m := common.JwkFromRSAPrivateKey(rsaPK)
		return &m, nil
	}

	return nil, fmt.Errorf("%wunknown private key format provided", e.InvalidPrivateKey)
}
