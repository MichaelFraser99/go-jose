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
	"github.com/MichaelFraser99/go-jose/internal/algorithms/ps512"
	"github.com/MichaelFraser99/go-jose/internal/algorithms/rs256"
	"github.com/MichaelFraser99/go-jose/internal/algorithms/rs384"
	"github.com/MichaelFraser99/go-jose/internal/algorithms/rs512"
	"github.com/MichaelFraser99/go-jose/model"
)

// GetValidator
//
// # Returns a Validator implementation for the given algorithm and public key
//
// alg - Determines which validator type gets returned
//
// publicKey - `crypto.PublicKey` implementation to be used by the validator
func GetValidator(alg model.Algorithm, publicKey crypto.PublicKey) (model.Validator, error) {
	var v model.Validator
	var err error
	switch alg {
	case model.ES256:
		v, err = es256.NewValidator(publicKey)
	case model.ES384:
		v, err = es384.NewValidator(publicKey)
	case model.ES512:
		v, err = es512.NewValidator(publicKey)
	case model.RS256:
		v, err = rs256.NewValidator(publicKey)
	case model.RS384:
		v, err = rs384.NewValidator(publicKey)
	case model.RS512:
		v, err = rs512.NewValidator(publicKey)
	case model.PS256:
		v, err = ps256.NewValidator(publicKey)
	case model.PS384:
		v, err = ps384.NewValidator(publicKey)
	case model.PS512:
		v, err = ps512.NewValidator(publicKey)
	default:
		return nil, fmt.Errorf("%wunsupported algorithm: '%s'", e.UnsupportedAlgorithm, alg.String())
	}
	return v, err
}

// GetValidatorFromJwk
//
// # Returns a Validator implementation for the given algorithm and jwk-format public key
//
// alg - Determines which validator type gets returned
//
// jwk - jwk format public key
func GetValidatorFromJwk(alg model.Algorithm, jwk []byte) (model.Validator, error) {
	var v model.Validator
	var err error
	switch alg {
	case model.ES256:
		v, err = es256.NewValidatorFromJwk(jwk)
	case model.ES384:
		v, err = es384.NewValidatorFromJwk(jwk)
	case model.ES512:
		v, err = es512.NewValidatorFromJwk(jwk)
	case model.RS256:
		v, err = rs256.NewValidatorFromJwk(jwk)
	case model.RS384:
		v, err = rs384.NewValidatorFromJwk(jwk)
	case model.RS512:
		v, err = rs512.NewValidatorFromJwk(jwk)
	case model.PS256:
		v, err = ps256.NewValidatorFromJwk(jwk)
	case model.PS384:
		v, err = ps384.NewValidatorFromJwk(jwk)
	case model.PS512:
		v, err = ps512.NewValidatorFromJwk(jwk)
	default:
		return nil, fmt.Errorf("%wunsupported algorithm: '%s'", e.UnsupportedAlgorithm, alg.String())
	}
	return v, err
}
