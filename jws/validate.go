package jws

import (
	"crypto"
	"fmt"
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
	"github.com/MichaelFraser99/go-jose/joseerror"
	"github.com/MichaelFraser99/go-jose/jwa"
	"github.com/MichaelFraser99/go-jose/model"
)

// GetValidator
//
// # Returns a Validator implementation for the given algorithm and public key
//
// alg - Determines which validator type gets returned
//
// publicKey - `crypto.PublicKey` implementation to be used by the validator
func GetValidator(alg jwa.Algorithm, publicKey crypto.PublicKey) (model.Validator, error) {
	var v model.Validator
	var err error
	switch alg {
	case jwa.ES256:
		v, err = es256.NewValidator(publicKey)
	case jwa.ES384:
		v, err = es384.NewValidator(publicKey)
	case jwa.ES512:
		v, err = es512.NewValidator(publicKey)
	case jwa.RS256:
		v, err = rs256.NewValidator(publicKey)
	case jwa.RS384:
		v, err = rs384.NewValidator(publicKey)
	case jwa.RS512:
		v, err = rs512.NewValidator(publicKey)
	case jwa.PS256:
		v, err = ps256.NewValidator(publicKey)
	case jwa.PS384:
		v, err = ps384.NewValidator(publicKey)
	case jwa.PS512:
		v, err = ps512.NewValidator(publicKey)
	case jwa.HS256:
		v, err = hs256.NewValidator(publicKey)
	case jwa.HS384:
		v, err = hs384.NewValidator(publicKey)
	case jwa.HS512:
		v, err = hs512.NewValidator(publicKey)
	default:
		return nil, fmt.Errorf("%wunsupported algorithm: '%s'", joseerror.ErrUnsupportedAlgorithm, alg.String())
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
func GetValidatorFromJwk(alg jwa.Algorithm, jwk map[string]any) (model.Validator, error) {
	var v model.Validator
	var err error
	switch alg {
	case jwa.ES256:
		v, err = es256.NewValidatorFromJwk(jwk)
	case jwa.ES384:
		v, err = es384.NewValidatorFromJwk(jwk)
	case jwa.ES512:
		v, err = es512.NewValidatorFromJwk(jwk)
	case jwa.RS256:
		v, err = rs256.NewValidatorFromJwk(jwk)
	case jwa.RS384:
		v, err = rs384.NewValidatorFromJwk(jwk)
	case jwa.RS512:
		v, err = rs512.NewValidatorFromJwk(jwk)
	case jwa.PS256:
		v, err = ps256.NewValidatorFromJwk(jwk)
	case jwa.PS384:
		v, err = ps384.NewValidatorFromJwk(jwk)
	case jwa.PS512:
		v, err = ps512.NewValidatorFromJwk(jwk)
	case jwa.HS256, jwa.HS384, jwa.HS512:
		return nil, fmt.Errorf("%wvalidators cannot be created for symmetric algorithms", joseerror.ErrUnsupportedAlgorithm)
	default:
		return nil, fmt.Errorf("%wunsupported algorithm: '%s'", joseerror.ErrUnsupportedAlgorithm, alg.String())
	}
	return v, err
}
