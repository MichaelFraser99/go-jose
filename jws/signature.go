package jws

import (
	"crypto"
	"fmt"
	e "github.com/MichaelFraser99/go-jose/error"
	"github.com/MichaelFraser99/go-jose/internal/algorithms/es256"
	"github.com/MichaelFraser99/go-jose/internal/algorithms/es384"
	"github.com/MichaelFraser99/go-jose/internal/algorithms/es512"
	"github.com/MichaelFraser99/go-jose/internal/algorithms/ps256"
	"github.com/MichaelFraser99/go-jose/internal/algorithms/ps384"
	ps512 "github.com/MichaelFraser99/go-jose/internal/algorithms/ps521"
	"github.com/MichaelFraser99/go-jose/internal/algorithms/rs256"
	"github.com/MichaelFraser99/go-jose/internal/algorithms/rs384"
	"github.com/MichaelFraser99/go-jose/internal/algorithms/rs512"
	"github.com/MichaelFraser99/go-jose/model"
	"slices"
)

// GetSigner
//
// # Returns a Signer implementation for the given algorithm complete with generated keypair
//
// alg - Determines which signer type gets returned
//
// opts - Extra options object to control additional algorithm specific behaviour. Currently only determines the size of key to be returned for RSA keys. If none specified, defaults to 2048
func GetSigner(alg model.Algorithm, opts *model.Opts) (model.Signer, error) {
	var s model.Signer
	var err error
	var size int

	if slices.Contains([]model.Algorithm{model.RS256, model.RS384, model.RS512}, alg) {
		if opts == nil || opts.BitSize == 0 {
			size = 2048
		} else {
			size = opts.BitSize
		}
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

	default:
		return nil, &e.UnsupportedAlgorithm{Message: fmt.Sprintf("unsupported algorithm: '%s'", alg)}
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

	default:
		return nil, &e.UnsupportedAlgorithm{Message: fmt.Sprintf("unsupported algorithm: '%s'", alg)}
	}

	return s, err
}
