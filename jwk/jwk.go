package jwk

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/rsa"
	"fmt"
	e "github.com/MichaelFraser99/go-jose/error"
	"github.com/MichaelFraser99/go-jose/internal/algorithms/common"
)

func PublicFromJwk(jwk map[string]any) (crypto.PublicKey, error) {
	if kty, present := jwk["kty"]; present {
		switch kty.(string) {
		case "EC":
			return common.ECDSAPublicKeyFromJwk(jwk)
		case "RSA":
			return common.RSAPublicKeyFromJwk(jwk)
		default:
			return nil, fmt.Errorf("unsupported kty: %s", kty.(string))
		}
	} else {
		return nil, fmt.Errorf("no kty claim present in jwk, cannot infer type of public key to return")
	}
}

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
