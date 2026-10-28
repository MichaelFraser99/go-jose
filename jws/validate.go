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
	"github.com/MichaelFraser99/go-jose/jwk"
	"github.com/MichaelFraser99/go-jose/model"
)

// GetValidator
//
// # Returns a Validator implementation for the given algorithm and public key
//
// alg - Determines which validator type gets returned
//
// publicKey - `crypto.PublicKey` implementation to be used by the validator
//
// A bare crypto.PublicKey carries no algorithm, so the validator uses the key
// with whatever alg the caller passes: one RSA key builds a validator for each
// of RS256 to PS512. RFC 8725 section 3.1 requires each key to be used with
// exactly one algorithm. Binding the key to it is the caller's job: pass an alg
// the caller chose, not one read from the token, or restrict verification with
// JoseOptions.AllowedSigningAlgorithms.
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

// GetValidatorFromJwk
//
// # Returns a Validator implementation for the given algorithm and jwk-format public key
//
// alg - Determines which validator type gets returned
//
// publicJwk - jwk format public key. Its "kty" selects the key type, and the key
// must suit alg as GetValidator requires. RFC 8725 section 3.1 requires each key
// to be used with exactly one algorithm, so a jwk carrying an "alg" member is
// refused unless that member is the string alg names.
func GetValidatorFromJwk(alg jwa.Algorithm, publicJwk map[string]any) (model.Validator, error) {
	switch alg {
	case jwa.ES256, jwa.ES384, jwa.ES512, jwa.RS256, jwa.RS384, jwa.RS512, jwa.PS256, jwa.PS384, jwa.PS512:
	case jwa.HS256, jwa.HS384, jwa.HS512:
		return nil, fmt.Errorf("%wvalidators cannot be created for symmetric algorithms", joseerror.ErrUnsupportedAlgorithm)
	case jwa.EdDSA, jwa.Unknown:
		return nil, fmt.Errorf("%w'%s'", joseerror.ErrUnsupportedAlgorithm, alg.String())
	default:
		return nil, fmt.Errorf("%w'%s'", joseerror.ErrUnsupportedAlgorithm, alg.String())
	}
	if member, present := publicJwk["alg"]; present {
		if name, _ := member.(string); name != alg.String() {
			return nil, fmt.Errorf("%wthe jwk's alg %v does not name %s", joseerror.ErrInvalidPublicKey, member, alg.String())
		}
	}
	publicKey, err := jwk.PublicFromJwk(publicJwk)
	if err != nil {
		return nil, err
	}
	return GetValidator(alg, publicKey)
}
