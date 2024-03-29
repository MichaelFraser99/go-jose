package jws

import (
	"crypto"
	"fmt"
	e "github.com/MichaelFraser99/go-jose/error"
	"github.com/MichaelFraser99/go-jose/internal/algorithms/es256"
	"github.com/MichaelFraser99/go-jose/internal/algorithms/es384"
	"github.com/MichaelFraser99/go-jose/internal/algorithms/es512"
	"github.com/MichaelFraser99/go-jose/internal/algorithms/hs256"
	"github.com/MichaelFraser99/go-jose/internal/algorithms/hs384"
	"github.com/MichaelFraser99/go-jose/internal/algorithms/hs512"
	"github.com/MichaelFraser99/go-jose/internal/algorithms/ps256"
	"github.com/MichaelFraser99/go-jose/internal/algorithms/ps384"
	"github.com/MichaelFraser99/go-jose/internal/algorithms/ps512"
	"github.com/MichaelFraser99/go-jose/internal/algorithms/rs256"
	"github.com/MichaelFraser99/go-jose/internal/algorithms/rs384"
	"github.com/MichaelFraser99/go-jose/internal/algorithms/rs512"
	"github.com/MichaelFraser99/go-jose/model"
)

// GetSigner
//
// # Returns a Signer implementation for the given algorithm complete with generated keypair
//
// alg - Determines which signer type gets returned
//
// opts - Extra options object to control additional algorithm specific behaviour. BitSize determines the size of key to be returned for RSA keys - if none specified defaults to 2048. SecretKey is used to define a secret key value for HMAC algorithms
func GetSigner(alg model.Algorithm, opts *model.Opts) (model.Signer, error) {
	var s model.Signer
	var err error
	var size int

	if opts == nil || opts.BitSize == 0 {
		size = 2048
	} else {
		size = opts.BitSize
	}

	switch alg {
	case model.ES256:
		s, err = es256.NewSigner()
	case model.ES384:
		s, err = es384.NewSigner()
	case model.ES512:
		s, err = es512.NewSigner()
	case model.RS256:
		s, err = rs256.NewSigner(size)
	case model.RS384:
		s, err = rs384.NewSigner(size)
	case model.RS512:
		s, err = rs512.NewSigner(size)
	case model.PS256:
		s, err = ps256.NewSigner(size)
	case model.PS384:
		s, err = ps384.NewSigner(size)
	case model.PS512:
		s, err = ps512.NewSigner(size)
	case model.HS256:
		if opts == nil || opts.SecretKey == nil {
			return nil, fmt.Errorf("secret key must be specified for HS algorithms")
		}
		s, err = hs256.NewSigner(opts.SecretKey)
	case model.HS384:
		if opts == nil || opts.SecretKey == nil {
			return nil, fmt.Errorf("secret key must be specified for HS algorithms")
		}
		s, err = hs384.NewSigner(opts.SecretKey)
	case model.HS512:
		if opts == nil || opts.SecretKey == nil {
			return nil, fmt.Errorf("secret key must be specified for HS algorithms")
		}
		s, err = hs512.NewSigner(opts.SecretKey)

	default:
		return nil, fmt.Errorf("%wunsupported algorithm: '%s'", e.UnsupportedAlgorithm, alg)
	}

	return s, err
}

// GetSignerFromPrivateKey
//
// # Returns a Signer implementation for the given algorithm and private key
//
// alg - Determines which signer type gets returned
//
// privateKey - The provided `crypto.PrivateKey` implementation. Must be a pointer to the relevant key type for the selected algorithm
func GetSignerFromPrivateKey(alg model.Algorithm, privateKey crypto.PrivateKey) (model.Signer, error) {
	var s model.Signer
	var err error

	switch alg {
	case model.ES256:
		s, err = es256.NewSignerFromPrivateKey(privateKey)
	case model.ES384:
		s, err = es384.NewSignerFromPrivateKey(privateKey)
	case model.ES512:
		s, err = es512.NewSignerFromPrivateKey(privateKey)
	case model.RS256:
		s, err = rs256.NewSignerFromPrivateKey(privateKey)
	case model.RS384:
		s, err = rs384.NewSignerFromPrivateKey(privateKey)
	case model.RS512:
		s, err = rs512.NewSignerFromPrivateKey(privateKey)
	case model.PS256:
		s, err = ps256.NewSignerFromPrivateKey(privateKey)
	case model.PS384:
		s, err = ps384.NewSignerFromPrivateKey(privateKey)
	case model.PS512:
		s, err = ps512.NewSignerFromPrivateKey(privateKey)
	case model.HS256, model.HS384, model.HS512:
		return nil, fmt.Errorf("%wHMAC Signers cannot be created this way - please use GetSigner and specify the secret key using the Opts function", e.UnsupportedAlgorithm)

	default:
		return nil, fmt.Errorf("%wunsupported algorithm: '%s'", e.UnsupportedAlgorithm, alg)
	}

	return s, err
}
