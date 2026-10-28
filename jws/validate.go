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
	construct, ok := validatorConstructors[alg]
	if !ok {
		return nil, fmt.Errorf("%w'%s'", joseerror.ErrUnsupportedAlgorithm, alg.String())
	}
	v, err := construct(publicKey)
	if err != nil {
		return nil, err
	}
	return v, nil
}

var validatorConstructors = map[jwa.Algorithm]func(crypto.PublicKey) (model.Validator, error){
	jwa.ES256: func(k crypto.PublicKey) (model.Validator, error) { return es256.NewValidator(k) },
	jwa.ES384: func(k crypto.PublicKey) (model.Validator, error) { return es384.NewValidator(k) },
	jwa.ES512: func(k crypto.PublicKey) (model.Validator, error) { return es512.NewValidator(k) },
	jwa.RS256: func(k crypto.PublicKey) (model.Validator, error) { return rs256.NewValidator(k) },
	jwa.RS384: func(k crypto.PublicKey) (model.Validator, error) { return rs384.NewValidator(k) },
	jwa.RS512: func(k crypto.PublicKey) (model.Validator, error) { return rs512.NewValidator(k) },
	jwa.PS256: func(k crypto.PublicKey) (model.Validator, error) { return ps256.NewValidator(k) },
	jwa.PS384: func(k crypto.PublicKey) (model.Validator, error) { return ps384.NewValidator(k) },
	jwa.PS512: func(k crypto.PublicKey) (model.Validator, error) { return ps512.NewValidator(k) },
	jwa.HS256: func(k crypto.PublicKey) (model.Validator, error) { return hs256.NewValidator(k) },
	jwa.HS384: func(k crypto.PublicKey) (model.Validator, error) { return hs384.NewValidator(k) },
	jwa.HS512: func(k crypto.PublicKey) (model.Validator, error) { return hs512.NewValidator(k) },
}

func hasValidator(alg jwa.Algorithm) bool {
	_, ok := validatorConstructors[alg]
	return ok
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
	case jwa.EdDSA, jwa.Unknown:
		return nil, fmt.Errorf("%w'%s'", joseerror.ErrUnsupportedAlgorithm, alg.String())
	default:
		return nil, fmt.Errorf("%w'%s'", joseerror.ErrUnsupportedAlgorithm, alg.String())
	}
	if err != nil {
		return nil, err
	}
	return v, nil
}
