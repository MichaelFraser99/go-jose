package jws

import (
	"crypto"
	"fmt"
	"github.com/MichaelFraser99/go-jose/internal/algorithms/eddsa"
	"github.com/MichaelFraser99/go-jose/internal/algorithms/es256"
	"github.com/MichaelFraser99/go-jose/internal/algorithms/es384"
	"github.com/MichaelFraser99/go-jose/internal/algorithms/es512"
	"github.com/MichaelFraser99/go-jose/internal/algorithms/hs256"
	"github.com/MichaelFraser99/go-jose/internal/algorithms/hs384"
	"github.com/MichaelFraser99/go-jose/internal/algorithms/hs512"
	"github.com/MichaelFraser99/go-jose/internal/algorithms/mldsa"
	"github.com/MichaelFraser99/go-jose/internal/algorithms/ps256"
	"github.com/MichaelFraser99/go-jose/internal/algorithms/ps384"
	"github.com/MichaelFraser99/go-jose/internal/algorithms/ps512"
	"github.com/MichaelFraser99/go-jose/internal/algorithms/rs256"
	"github.com/MichaelFraser99/go-jose/internal/algorithms/rs384"
	"github.com/MichaelFraser99/go-jose/internal/algorithms/rs512"
	"github.com/MichaelFraser99/go-jose/internal/jose/jsonutils"
	internal_jwk "github.com/MichaelFraser99/go-jose/internal/jose/jwk"
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
	jwa.ES256:   func(k crypto.PublicKey) (model.Validator, error) { return es256.NewValidator(k) },
	jwa.ES384:   func(k crypto.PublicKey) (model.Validator, error) { return es384.NewValidator(k) },
	jwa.ES512:   func(k crypto.PublicKey) (model.Validator, error) { return es512.NewValidator(k) },
	jwa.RS256:   func(k crypto.PublicKey) (model.Validator, error) { return rs256.NewValidator(k) },
	jwa.RS384:   func(k crypto.PublicKey) (model.Validator, error) { return rs384.NewValidator(k) },
	jwa.RS512:   func(k crypto.PublicKey) (model.Validator, error) { return rs512.NewValidator(k) },
	jwa.PS256:   func(k crypto.PublicKey) (model.Validator, error) { return ps256.NewValidator(k) },
	jwa.PS384:   func(k crypto.PublicKey) (model.Validator, error) { return ps384.NewValidator(k) },
	jwa.PS512:   func(k crypto.PublicKey) (model.Validator, error) { return ps512.NewValidator(k) },
	jwa.HS256:   func(k crypto.PublicKey) (model.Validator, error) { return hs256.NewValidator(k) },
	jwa.HS384:   func(k crypto.PublicKey) (model.Validator, error) { return hs384.NewValidator(k) },
	jwa.HS512:   func(k crypto.PublicKey) (model.Validator, error) { return hs512.NewValidator(k) },
	jwa.EdDSA:   func(k crypto.PublicKey) (model.Validator, error) { return eddsa.NewValidator(k) },
	jwa.Ed25519: func(k crypto.PublicKey) (model.Validator, error) { return eddsa.NewValidator(k) },
	jwa.MLDSA44: func(k crypto.PublicKey) (model.Validator, error) { return mldsa.NewValidator(jwa.MLDSA44, k) },
	jwa.MLDSA65: func(k crypto.PublicKey) (model.Validator, error) { return mldsa.NewValidator(jwa.MLDSA65, k) },
	jwa.MLDSA87: func(k crypto.PublicKey) (model.Validator, error) { return mldsa.NewValidator(jwa.MLDSA87, k) },
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
// publicJwk - jwk format public key. Its "kty" selects the key type, and the key
// must suit alg as GetValidator requires. RFC 8725 section 3.1 requires each key
// to be used with exactly one algorithm, so a jwk carrying an "alg" member is
// refused unless that member is the string alg names. A jwk whose "use" is
// present and is not "sig", or whose "key_ops" is present and lacks "verify",
// is refused too, as RFC 7517 sections 4.2 and 4.3 mark it as not for verifying
// signatures. Every refusal carries ErrInvalidPublicKey. To verify with such a
// key anyway, read it with jwk.PublicFromJwk and pass it to GetValidator,
// which applies no key-use rule.
func GetValidatorFromJwk(alg jwa.Algorithm, publicJwk map[string]any) (model.Validator, error) {
	switch alg {
	case jwa.ES256, jwa.ES384, jwa.ES512, jwa.RS256, jwa.RS384, jwa.RS512, jwa.PS256, jwa.PS384, jwa.PS512, jwa.EdDSA, jwa.Ed25519, jwa.MLDSA44, jwa.MLDSA65, jwa.MLDSA87:
	case jwa.HS256, jwa.HS384, jwa.HS512:
		return nil, fmt.Errorf("%wvalidators cannot be created for symmetric algorithms", joseerror.ErrUnsupportedAlgorithm)
	case jwa.Unknown:
		return nil, fmt.Errorf("%w'%s'", joseerror.ErrUnsupportedAlgorithm, alg.String())
	default:
		return nil, fmt.Errorf("%w'%s'", joseerror.ErrUnsupportedAlgorithm, alg.String())
	}
	if member, present := publicJwk["alg"]; present {
		if name, isString := member.(string); !eddsa.SameAlgorithm(name, alg.String()) {
			named := "a value that is not a string"
			if isString {
				named = jsonutils.QuoteBounded(name)
			}
			return nil, fmt.Errorf("%wthe jwk's alg %s does not name %s", joseerror.ErrInvalidPublicKey, named, alg.String())
		}
	}
	if err := internal_jwk.CheckKeyUse(publicJwk, joseerror.ErrInvalidPublicKey, joseerror.ErrInvalidPublicKey); err != nil {
		return nil, err
	}
	publicKey, err := jwk.PublicFromJwk(publicJwk)
	if err != nil {
		return nil, err
	}
	return GetValidator(alg, publicKey)
}
