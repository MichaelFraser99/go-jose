package jose

import (
	"crypto"
	"fmt"
	e "github.com/MichaelFraser99/go-jose/error"
	"github.com/MichaelFraser99/go-jose/internal/algorithms/es256"
	"github.com/MichaelFraser99/go-jose/internal/algorithms/es384"
	"github.com/MichaelFraser99/go-jose/internal/algorithms/es512"
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
// bitSize - determines the size of key to be returned. Ignored for elliptic curve algorithms. If none specified, defaults to 2048
func GetSigner(alg model.Algorithm, bitSize *int) (model.Signer, error) {
	var s model.Signer
	var err error

	if slices.Contains([]model.Algorithm{model.RS256, model.RS384, model.RS512}, alg) && bitSize == nil {
		size := 2048
		bitSize = &size
	}

	switch alg {
	case model.ES256:
		s, err = es256.NewSigner()
	case model.ES384:
		s, err = es384.NewSigner()
	case model.ES512:
		s, err = es512.NewSigner()
	case model.RS256:
		s, err = rs256.NewSigner(*bitSize)
	case model.RS384:
		s, err = rs384.NewSigner(*bitSize)
	case model.RS512:
		s, err = rs512.NewSigner(*bitSize)

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

	default:
		return nil, &e.UnsupportedAlgorithm{Message: fmt.Sprintf("unsupported algorithm: '%s'", alg)}
	}

	return s, err
}
