package jwk

import (
	"crypto"
	"encoding/json"
	"fmt"
	"slices"

	"github.com/MichaelFraser99/go-jose/internal/algorithms/common"
	"github.com/MichaelFraser99/go-jose/internal/algorithms/eddsa"
	"github.com/MichaelFraser99/go-jose/internal/httputils"
	"github.com/MichaelFraser99/go-jose/internal/jose/jsonutils"
	"github.com/MichaelFraser99/go-jose/joseerror"
	"github.com/MichaelFraser99/go-jose/jwa"
	"github.com/MichaelFraser99/go-jose/model"
)

// InlineJWK returns the key of a jwk header when SelectKeys would select it. A key it
// would not select reports ErrNoKeyIdentifierMatch, or ErrMalformedClaim when one of
// the members it judges by has the wrong type.
func InlineJWK(jwk map[string]any, kid *string, alg string, ignoreKeyUse, strictKeyOperations bool) model.Retriever {
	return func() ([]crypto.PublicKey, error) {
		if err := checkMember(jwk, kid, alg, ignoreKeyUse, strictKeyOperations); err != nil {
			return nil, err
		}

		publicKey, err := PublicFromJwk(jwk)
		if err != nil {
			return nil, fmt.Errorf("%wfailed to convert jwk to public key: %w", joseerror.ErrApplicationError, err)
		}

		return []crypto.PublicKey{publicKey}, nil
	}
}

// RetrieveJKU fetches the JWK Set a jku header names and returns the keys SelectKeys
// takes from it. A set from which no key is selected reports ErrNoKeyIdentifierMatch.
func RetrieveJKU(jku string, fetch httputils.Fetch, kid *string, alg string, ignoreKeyUse, strictKeyOperations bool) model.Retriever {
	return func() ([]crypto.PublicKey, error) {
		response, err := fetch(jku, "jku")
		if err != nil {
			return nil, err
		}

		responseBytes, err := httputils.ReadBody(response, "jku")
		if err != nil {
			return nil, err
		}

		var returnedKeystore model.Jwks
		err = json.Unmarshal(responseBytes, &returnedKeystore)
		if err != nil {
			return nil, fmt.Errorf("%wfailed to unmarshal jku response: %w", joseerror.ErrApplicationError, err)
		}

		keystore := SelectKeys(returnedKeystore, kid, alg, ignoreKeyUse, strictKeyOperations)
		if len(keystore) == 0 {
			return nil, fmt.Errorf("%wno usable jwk entry in the returned set matches the identifiers specified in the jose header", joseerror.ErrNoKeyIdentifierMatch)
		}

		return keystore, nil
	}
}

// RetrieveKeySet returns the keys SelectKeys takes from the caller's keySet. The set
// is read each time the retriever is called. A set from which no key is selected
// reports ErrNoKeyIdentifierMatch.
func RetrieveKeySet(keySet *model.Jwks, kid *string, alg string, ignoreKeyUse, strictKeyOperations bool) model.Retriever {
	return func() ([]crypto.PublicKey, error) {
		keys := SelectKeys(*keySet, kid, alg, ignoreKeyUse, strictKeyOperations)
		if len(keys) == 0 {
			return nil, fmt.Errorf("%wno usable jwk entry in JoseOptions.KeySet matches the identifiers specified in the jose header", joseerror.ErrNoKeyIdentifierMatch)
		}
		return keys, nil
	}
}

// PrivateFromJwk reads a private or symmetric key from its jwk. An "oct" jwk
// (RFC 7518 section 6.4) is returned as a []byte.
func PrivateFromJwk(jwk map[string]any) (crypto.PrivateKey, error) {
	if kty, present := jwk["kty"]; present {
		ktyString, ok := kty.(string)
		if !ok {
			return nil, fmt.Errorf("%wthe 'kty' claim must be a string", joseerror.ErrInvalidPrivateKey)
		}
		switch ktyString {
		case "EC":
			key, err := common.ECDSAPrivateKeyFromJwk(jwk)
			if err != nil {
				return nil, err
			}
			return key, nil
		case "RSA":
			key, err := common.RSAPrivateKeyFromJwk(jwk)
			if err != nil {
				return nil, err
			}
			return key, nil
		case "OKP":
			key, err := common.OKPPrivateKeyFromJwk(jwk)
			if err != nil {
				return nil, err
			}
			return key, nil
		case "AKP":
			key, err := common.MLDSAPrivateKeyFromJwk(jwk)
			if err != nil {
				return nil, err
			}
			return key, nil
		case "oct":
			key, err := common.SecretKeyFromJwk(jwk)
			if err != nil {
				return nil, err
			}
			return key, nil
		default:
			return nil, fmt.Errorf("%wthe 'kty' claim is not one of EC, RSA, OKP, AKP and oct", joseerror.ErrUnsupportedAlgorithm)
		}
	} else {
		return nil, fmt.Errorf("%wa jwk must carry the REQUIRED 'kty' claim naming its key type", joseerror.ErrInvalidPrivateKey)
	}
}

// PublicFromJwk reads a public key from its jwk. An "oct" jwk is refused: a
// symmetric key (RFC 7518 section 6.4) has no public half.
func PublicFromJwk(jwk map[string]any) (crypto.PublicKey, error) {
	if kty, present := jwk["kty"]; present {
		ktyString, ok := kty.(string)
		if !ok {
			return nil, fmt.Errorf("%wthe 'kty' claim must be a string", joseerror.ErrInvalidPublicKey)
		}
		switch ktyString {
		case "EC":
			key, err := common.ECDSAPublicKeyFromJwk(jwk)
			if err != nil {
				return nil, err
			}
			return key, nil
		case "RSA":
			key, err := common.RSAPublicKeyFromJwk(jwk)
			if err != nil {
				return nil, err
			}
			return key, nil
		case "OKP":
			key, err := common.OKPPublicKeyFromJwk(jwk)
			if err != nil {
				return nil, err
			}
			return key, nil
		case "AKP":
			key, err := common.MLDSAPublicKeyFromJwk(jwk)
			if err != nil {
				return nil, err
			}
			return key, nil
		case "oct":
			return nil, fmt.Errorf("%wan oct jwk is a symmetric key, which has no public half", joseerror.ErrInvalidPublicKey)
		default:
			return nil, fmt.Errorf("%wthe 'kty' claim is not one of EC, RSA, OKP and AKP", joseerror.ErrUnsupportedAlgorithm)
		}
	} else {
		return nil, fmt.Errorf("%wa jwk must carry the REQUIRED 'kty' claim naming its key type", joseerror.ErrInvalidPublicKey)
	}
}

// SelectKeys returns the key of each member of keySet that can verify a JWS whose
// header names kid and alg, in set order. Each member is judged on its own, so no
// member admits or excludes another. A member is selected when:
//   - this library can read it, since RFC 7517 section 5 says to ignore one it cannot;
//   - its "kid" is absent or equals kid, which RFC 7515 section 4.1.4 calls a hint;
//   - its "alg" is absent or equals alg, since RFC 8725 section 3.1 requires each key
//     be used with exactly one algorithm;
//   - its key type can serve alg, as KeyTypeServes reports;
//   - unless ignoreKeyUse, its "use" is absent or "sig" and its "key_ops" is absent or
//     includes "verify" (RFC 7517 sections 4.2 and 4.3), and, when
//     strictKeyOperations, it passes CheckRecommendedKeyOperations.
func SelectKeys(keySet model.Jwks, kid *string, alg string, ignoreKeyUse, strictKeyOperations bool) []crypto.PublicKey {
	var selected []crypto.PublicKey
	for _, member := range keySet.Keys {
		if checkMember(member, kid, alg, ignoreKeyUse, strictKeyOperations) != nil {
			continue
		}
		publicKey, err := PublicFromJwk(member)
		if err != nil {
			continue
		}
		selected = append(selected, publicKey)
	}
	return selected
}

func checkMember(jwk map[string]any, kid *string, alg string, ignoreKeyUse, strictKeyOperations bool) error {
	if k, present := jwk["kid"]; present {
		sk, ok := k.(string)
		if !ok {
			return fmt.Errorf("%wjwk has malformed kid value", joseerror.ErrMalformedClaim)
		}
		if kid != nil && sk != *kid {
			return fmt.Errorf("%wjwk kid does not match value from jose header", joseerror.ErrNoKeyIdentifierMatch)
		}
	}

	if a, present := jwk["alg"]; present {
		sa, ok := a.(string)
		if !ok {
			return fmt.Errorf("%wjwk has malformed alg value", joseerror.ErrMalformedClaim)
		}
		if !eddsa.SameAlgorithm(sa, alg) {
			return fmt.Errorf("%wjwk alg does not match value from jose header", joseerror.ErrNoKeyIdentifierMatch)
		}
	}

	if !KeyTypeServes(jwk, alg) {
		return fmt.Errorf("%wjwk key type cannot be used with the alg from jose header", joseerror.ErrNoKeyIdentifierMatch)
	}

	if ignoreKeyUse {
		return nil
	}
	return CheckKeyUse(jwk, joseerror.ErrNoKeyIdentifierMatch, joseerror.ErrMalformedClaim, strictKeyOperations)
}

type keyType struct {
	kty, crv string
}

var signatureKeyTypes = map[jwa.Algorithm]keyType{
	jwa.ES256:   {"EC", "P-256"},
	jwa.ES384:   {"EC", "P-384"},
	jwa.ES512:   {"EC", "P-521"},
	jwa.RS256:   {kty: "RSA"},
	jwa.RS384:   {kty: "RSA"},
	jwa.RS512:   {kty: "RSA"},
	jwa.PS256:   {kty: "RSA"},
	jwa.PS384:   {kty: "RSA"},
	jwa.PS512:   {kty: "RSA"},
	jwa.HS256:   {kty: "oct"},
	jwa.HS384:   {kty: "oct"},
	jwa.HS512:   {kty: "oct"},
	jwa.EdDSA:   {"OKP", "Ed25519"},
	jwa.Ed25519: {"OKP", "Ed25519"},
	jwa.MLDSA44: {kty: "AKP"},
	jwa.MLDSA65: {kty: "AKP"},
	jwa.MLDSA87: {kty: "AKP"},
}

var readableCurves = map[string][]string{
	"EC":  {"P-256", "P-384", "P-521"},
	"OKP": {"Ed25519", "X25519"},
}

// KeyTypeServes reports whether a jwk's "kty", and its "crv" where the key type
// has one, can serve the JWS alg. RFC 7518 sections 3.2 to 3.5 give oct to HS*,
// RSA to RS* and PS*, and EC to ES256, ES384 and ES512 on P-256, P-384 and P-521.
// RFC 8037 section 3.1 and RFC 9864 give OKP Ed25519 to EdDSA and Ed25519, and
// RFC 9964 gives AKP to ML-DSA. A "kty" or "crv" that is absent, not a string, or
// not one this library reads is not judged here, so reading the key reports it.
func KeyTypeServes(jwk map[string]any, alg string) bool {
	want, known := signatureKeyTypes[jwa.GetAlgorithm(alg)]
	if !known {
		return true
	}
	kty, ok := jwk["kty"].(string)
	if !ok || !slices.Contains([]string{"EC", "RSA", "OKP", "AKP", "oct"}, kty) {
		return true
	}
	if kty != want.kty {
		return false
	}
	crv, ok := jwk["crv"].(string)
	if !ok || want.crv == "" || !slices.Contains(readableCurves[kty], crv) {
		return true
	}
	return crv == want.crv
}

// CheckKeyUse refuses a jwk its publisher marked as not for verifying signatures:
// one whose "use" is present and is not "sig" (RFC 7517 section 4.2), or whose
// "key_ops" is present and lacks "verify" (RFC 7517 section 4.3). A member of the
// wrong type, or a "key_ops" that lists a value twice, which section 4.3 says
// MUST NOT happen, is refused with malformed, and a mark that excludes verifying
// with refused. When strictKeyOperations, a jwk CheckRecommendedKeyOperations
// refuses is refused with refused.
func CheckKeyUse(jwk map[string]any, refused, malformed error, strictKeyOperations bool) error {
	if u, present := jwk["use"]; present {
		su, ok := u.(string)
		if !ok {
			return fmt.Errorf("%wjwk has malformed use value", malformed)
		}
		if su != "sig" {
			return fmt.Errorf("%wjwk use %s is not sig", refused, jsonutils.QuoteBounded(su))
		}
	}

	if o, present := jwk["key_ops"]; present {
		ops, ok := o.([]any)
		if !ok {
			return fmt.Errorf("%wjwk key_ops must be an array", malformed)
		}
		verify := false
		seen := map[string]bool{}
		for _, op := range ops {
			sop, ok := op.(string)
			if !ok {
				return fmt.Errorf("%wjwk key_ops must hold strings", malformed)
			}
			if seen[sop] {
				return fmt.Errorf("%wjwk key_ops lists %s more than once", malformed, jsonutils.QuoteBounded(sop))
			}
			seen[sop] = true
			if sop == "verify" {
				verify = true
			}
		}
		if !verify {
			return fmt.Errorf("%wjwk key_ops do not include verify", refused)
		}
	}

	if strictKeyOperations {
		return CheckRecommendedKeyOperations(jwk, refused)
	}
	return nil
}

var relatedOperations = [][]string{{"sign", "verify"}, {"encrypt", "decrypt"}, {"wrapKey", "unwrapKey"}}

// CheckRecommendedKeyOperations refuses, with refused, a jwk that RFC 7517
// section 4.3 says SHOULD NOT be published: one carrying both "use" and
// "key_ops", or one whose "key_ops" names unrelated operations. Section 4.3
// relates only "sign" with "verify", "encrypt" with "decrypt", and "wrapKey"
// with "unwrapKey", so a "key_ops" of more than one value must be one of those
// pairs. The jwk's "key_ops" must already have passed the section's MUST rules:
// an array of strings, none listed twice.
func CheckRecommendedKeyOperations(jwk map[string]any, refused error) error {
	ops, present := jwk["key_ops"].([]any)
	if !present {
		return nil
	}
	if _, use := jwk["use"]; use {
		return fmt.Errorf("%wjwk carries both use and key_ops, which RFC 7517 section 4.3 says SHOULD NOT be used together", refused)
	}
	if len(ops) < 2 || len(ops) == 2 && slices.ContainsFunc(relatedOperations, func(pair []string) bool {
		return slices.Contains(ops, any(pair[0])) && slices.Contains(ops, any(pair[1]))
	}) {
		return nil
	}
	return fmt.Errorf("%wjwk key_ops names unrelated operations, which RFC 7517 section 4.3 says SHOULD NOT be combined", refused)
}
