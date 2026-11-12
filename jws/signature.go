package jws

import (
	"crypto"
	"errors"
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

var errSignWithEdDSA = fmt.Errorf("%wEdDSA is accepted only for verification: RFC 9864 section 4.1.2 deprecates it, so sign with Ed25519", joseerror.ErrUnsupportedAlgorithm)

// GetSigner
//
// # Returns a Signer implementation for the given algorithm complete with generated keypair
//
// alg - Determines which signer type gets returned
//
// opts - Extra options object to control additional algorithm specific behaviour. BitSize determines the size of key to be returned for RSA keys - if none specified defaults to 2048. SecretKey is used to define a secret key value for HMAC algorithms
func GetSigner(alg jwa.Algorithm, opts *model.Opts) (model.Signer, error) {
	var s model.Signer
	var err error
	var size int

	if opts == nil || opts.BitSize == 0 {
		size = 2048
	} else {
		size = opts.BitSize
	}

	switch alg {
	case jwa.ES256:
		s, err = es256.NewSigner()
	case jwa.ES384:
		s, err = es384.NewSigner()
	case jwa.ES512:
		s, err = es512.NewSigner()
	case jwa.RS256:
		s, err = rs256.NewSigner(size)
	case jwa.RS384:
		s, err = rs384.NewSigner(size)
	case jwa.RS512:
		s, err = rs512.NewSigner(size)
	case jwa.PS256:
		s, err = ps256.NewSigner(size)
	case jwa.PS384:
		s, err = ps384.NewSigner(size)
	case jwa.PS512:
		s, err = ps512.NewSigner(size)
	case jwa.HS256:
		if opts == nil || opts.SecretKey == nil {
			return nil, fmt.Errorf("%wa secret key must be specified for HS algorithms", joseerror.ErrInvalidPrivateKey)
		}
		s, err = hs256.NewSigner(opts.SecretKey)
	case jwa.HS384:
		if opts == nil || opts.SecretKey == nil {
			return nil, fmt.Errorf("%wa secret key must be specified for HS algorithms", joseerror.ErrInvalidPrivateKey)
		}
		s, err = hs384.NewSigner(opts.SecretKey)
	case jwa.HS512:
		if opts == nil || opts.SecretKey == nil {
			return nil, fmt.Errorf("%wa secret key must be specified for HS algorithms", joseerror.ErrInvalidPrivateKey)
		}
		s, err = hs512.NewSigner(opts.SecretKey)
	case jwa.Ed25519:
		s, err = eddsa.NewSigner()
	case jwa.MLDSA44, jwa.MLDSA65, jwa.MLDSA87:
		s, err = mldsa.NewSigner(alg)

	case jwa.EdDSA:
		return nil, errSignWithEdDSA
	case jwa.RSAOAEP, jwa.RSAOAEP256, jwa.RSAOAEP384, jwa.RSAOAEP512, jwa.A128KW, jwa.A192KW, jwa.A256KW, jwa.Dir, jwa.ECDHES, jwa.ECDHESA128KW, jwa.ECDHESA192KW, jwa.ECDHESA256KW, jwa.A128GCMKW, jwa.A192GCMKW, jwa.A256GCMKW, jwa.PBES2HS256A128KW, jwa.PBES2HS384A192KW, jwa.PBES2HS512A256KW, jwa.Unknown:
		return nil, notASignatureAlgorithm(alg)
	default:
		return nil, notASignatureAlgorithm(alg)
	}

	if err != nil {
		return nil, err
	}
	return s, nil
}

// GetSignerFromPrivateKey
//
// # Returns a Signer implementation for the given algorithm and private key
//
// alg - Determines which signer type gets returned
//
// privateKey - The provided `crypto.PrivateKey` implementation. Must be a pointer to the relevant key type for the selected algorithm
func GetSignerFromPrivateKey(alg jwa.Algorithm, privateKey crypto.PrivateKey) (model.Signer, error) {
	var s model.Signer
	var err error

	switch alg {
	case jwa.ES256:
		s, err = es256.NewSignerFromPrivateKey(privateKey)
	case jwa.ES384:
		s, err = es384.NewSignerFromPrivateKey(privateKey)
	case jwa.ES512:
		s, err = es512.NewSignerFromPrivateKey(privateKey)
	case jwa.RS256:
		s, err = rs256.NewSignerFromPrivateKey(privateKey)
	case jwa.RS384:
		s, err = rs384.NewSignerFromPrivateKey(privateKey)
	case jwa.RS512:
		s, err = rs512.NewSignerFromPrivateKey(privateKey)
	case jwa.PS256:
		s, err = ps256.NewSignerFromPrivateKey(privateKey)
	case jwa.PS384:
		s, err = ps384.NewSignerFromPrivateKey(privateKey)
	case jwa.PS512:
		s, err = ps512.NewSignerFromPrivateKey(privateKey)
	case jwa.HS256, jwa.HS384, jwa.HS512:
		return nil, fmt.Errorf("%wHMAC Signers cannot be created this way - please use GetSigner and specify the secret key using the Opts function", joseerror.ErrUnsupportedAlgorithm)
	case jwa.Ed25519:
		s, err = eddsa.NewSignerFromPrivateKey(privateKey)
	case jwa.MLDSA44, jwa.MLDSA65, jwa.MLDSA87:
		s, err = mldsa.NewSignerFromPrivateKey(alg, privateKey)

	case jwa.EdDSA:
		return nil, errSignWithEdDSA
	case jwa.RSAOAEP, jwa.RSAOAEP256, jwa.RSAOAEP384, jwa.RSAOAEP512, jwa.A128KW, jwa.A192KW, jwa.A256KW, jwa.Dir, jwa.ECDHES, jwa.ECDHESA128KW, jwa.ECDHESA192KW, jwa.ECDHESA256KW, jwa.A128GCMKW, jwa.A192GCMKW, jwa.A256GCMKW, jwa.PBES2HS256A128KW, jwa.PBES2HS384A192KW, jwa.PBES2HS512A256KW, jwa.Unknown:
		return nil, notASignatureAlgorithm(alg)
	default:
		return nil, notASignatureAlgorithm(alg)
	}

	if err != nil {
		return nil, err
	}
	return s, nil
}

// GetSignerFromJwk
//
// # Returns a Signer implementation for the given algorithm and jwk-format private key
//
// alg - Determines which signer type gets returned. One that is not a signature
// algorithm this library implements is refused with ErrUnsupportedAlgorithm, and
// so is EdDSA, as RFC 9864 section 4.1.2 deprecates it: sign with Ed25519.
//
// privateJwk - jwk format private key. Its "kty" selects the key type, as
// jwk.PrivateFromJwk reads it. For HS256, HS384 and HS512 it must be an "oct"
// jwk (RFC 7518 section 6.4), and its "k" is the secret, held to the length
// GetSigner requires. For every other algorithm it must be a private key that
// GetSignerFromPrivateKey accepts for alg, and an "oct" jwk is refused. Its
// "kid" and "alg" must be strings (RFC 7517 sections 4.5 and 4.4). RFC 8725
// section 3.1 requires each key to be used with exactly one algorithm, so a jwk
// carrying an "alg" member is refused unless that member is the string alg
// names, except that an "alg" of "EdDSA" is accepted for Ed25519, the one
// algorithm it names with an Ed25519 key. A jwk whose "use" is present and is
// not "sig", or whose "key_ops" is present and lacks "sign", is refused too, as
// RFC 7517 sections 4.2 and 4.3 mark it as not for computing signatures. So is
// a jwk whose "key_ops" lists a value twice, or whose "use" and "key_ops" are
// not consistent, both of which section 4.3 says MUST NOT happen. "key_ops" may
// be a []any, as encoding/json decodes it, or a []string. Every refusal of the
// jwk, including one that holds no private key, carries ErrInvalidPrivateKey.
// To sign with a key whose "use" or "key_ops" is refused, read it with
// jwk.PrivateFromJwk and pass it to GetSignerFromPrivateKey, or a secret to
// GetSigner as Opts.SecretKey. Neither applies a key-use rule.
//
// opts - may be nil. With StrictKeyOperations on, a jwk that section 4.3 says
// SHOULD NOT be published is refused too. No other field applies here.
func GetSignerFromJwk(alg jwa.Algorithm, privateJwk map[string]any, opts *model.JoseOptions) (model.Signer, error) {
	hmac := false
	switch alg {
	case jwa.ES256, jwa.ES384, jwa.ES512, jwa.RS256, jwa.RS384, jwa.RS512, jwa.PS256, jwa.PS384, jwa.PS512, jwa.Ed25519, jwa.MLDSA44, jwa.MLDSA65, jwa.MLDSA87:
	case jwa.HS256, jwa.HS384, jwa.HS512:
		hmac = true
	case jwa.EdDSA:
		return nil, errSignWithEdDSA
	case jwa.RSAOAEP, jwa.RSAOAEP256, jwa.RSAOAEP384, jwa.RSAOAEP512, jwa.A128KW, jwa.A192KW, jwa.A256KW, jwa.Dir, jwa.ECDHES, jwa.ECDHESA128KW, jwa.ECDHESA192KW, jwa.ECDHESA256KW, jwa.A128GCMKW, jwa.A192GCMKW, jwa.A256GCMKW, jwa.PBES2HS256A128KW, jwa.PBES2HS384A192KW, jwa.PBES2HS512A256KW, jwa.Unknown:
		return nil, notASignatureAlgorithm(alg)
	default:
		return nil, notASignatureAlgorithm(alg)
	}
	if err := internal_jwk.CheckMemberShape(privateJwk, joseerror.ErrInvalidPrivateKey, false); err != nil {
		return nil, err
	}
	if name, present := privateJwk["alg"].(string); present && !eddsa.SameAlgorithm(name, alg.String()) {
		return nil, fmt.Errorf("%wthe jwk's alg %s does not name %s", joseerror.ErrInvalidPrivateKey, jsonutils.QuoteBounded(name), alg.String())
	}
	if err := internal_jwk.CheckKeyUse(privateJwk, "sign", joseerror.ErrInvalidPrivateKey, joseerror.ErrInvalidPrivateKey, opts != nil && opts.StrictKeyOperations); err != nil {
		return nil, err
	}
	privateKey, err := jwk.PrivateFromJwk(privateJwk)
	if errors.Is(err, joseerror.ErrInvalidPrivateKey) {
		return nil, err
	}
	if err != nil {
		return nil, fmt.Errorf("%wthe jwk is not a private key for %s: %w", joseerror.ErrInvalidPrivateKey, alg.String(), err)
	}
	secret, symmetric := privateKey.([]byte)
	var s model.Signer
	switch {
	case hmac && symmetric:
		s, err = GetSigner(alg, &model.Opts{SecretKey: &secret})
	case hmac:
		return nil, fmt.Errorf("%w%s takes an oct jwk", joseerror.ErrInvalidPrivateKey, alg.String())
	case symmetric:
		return nil, fmt.Errorf("%wan oct jwk is a key for HS256, HS384 or HS512, not %s", joseerror.ErrInvalidPrivateKey, alg.String())
	default:
		s, err = GetSignerFromPrivateKey(alg, privateKey)
	}
	if err != nil {
		return nil, err
	}
	return s, nil
}
