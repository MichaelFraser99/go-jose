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
		return nil, notASignatureAlgorithm(alg)
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
// refused unless that member is the string alg names, with "EdDSA" and
// "Ed25519" naming the same algorithm. Its "kid" and "alg" must be strings (RFC
// 7517 sections 4.5 and 4.4). A jwk whose "use" is present and is not "sig", or
// whose "key_ops" is present and lacks "verify", is refused too, as RFC 7517
// sections 4.2 and 4.3 mark it as not for verifying signatures. So is a jwk
// whose "key_ops" lists a value twice, or whose "use" and "key_ops" are not
// consistent, both of which section 4.3 says MUST NOT happen. "key_ops" may be
// a []any or a []string.
// Every refusal carries ErrInvalidPublicKey. To verify with such a key anyway,
// read it with jwk.PublicFromJwk and pass it to GetValidator, which applies no
// key-use rule.
//
// opts - may be nil. With StrictKeyOperations on, a jwk that section 4.3 says
// SHOULD NOT be published is refused too. IgnoreKeyUse does not apply here.
func GetValidatorFromJwk(alg jwa.Algorithm, publicJwk map[string]any, opts *model.JoseOptions) (model.Validator, error) {
	switch alg {
	case jwa.ES256, jwa.ES384, jwa.ES512, jwa.RS256, jwa.RS384, jwa.RS512, jwa.PS256, jwa.PS384, jwa.PS512, jwa.EdDSA, jwa.Ed25519, jwa.MLDSA44, jwa.MLDSA65, jwa.MLDSA87:
	case jwa.HS256, jwa.HS384, jwa.HS512:
		return nil, fmt.Errorf("%wvalidators cannot be created for symmetric algorithms", joseerror.ErrUnsupportedAlgorithm)
	case jwa.RSAOAEP, jwa.RSAOAEP256, jwa.RSAOAEP384, jwa.RSAOAEP512, jwa.A128KW, jwa.A192KW, jwa.A256KW, jwa.Dir, jwa.ECDHES, jwa.ECDHESA128KW, jwa.ECDHESA192KW, jwa.ECDHESA256KW, jwa.A128GCMKW, jwa.A192GCMKW, jwa.A256GCMKW, jwa.PBES2HS256A128KW, jwa.PBES2HS384A192KW, jwa.PBES2HS512A256KW, jwa.Unknown:
		return nil, notASignatureAlgorithm(alg)
	default:
		return nil, notASignatureAlgorithm(alg)
	}
	if err := internal_jwk.CheckMemberShape(publicJwk, joseerror.ErrInvalidPublicKey, false); err != nil {
		return nil, err
	}
	if name, present := publicJwk["alg"].(string); present && !eddsa.SameAlgorithm(name, alg.String()) {
		return nil, fmt.Errorf("%wthe jwk's alg %s does not name %s", joseerror.ErrInvalidPublicKey, jsonutils.QuoteBounded(name), alg.String())
	}
	if err := internal_jwk.CheckKeyUse(publicJwk, "verify", joseerror.ErrInvalidPublicKey, joseerror.ErrInvalidPublicKey, opts != nil && opts.StrictKeyOperations); err != nil {
		return nil, err
	}
	publicKey, err := jwk.PublicFromJwk(publicJwk)
	if err != nil {
		return nil, err
	}
	return GetValidator(alg, publicKey)
}
