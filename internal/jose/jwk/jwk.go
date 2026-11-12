package jwk

import (
	"crypto"
	"encoding/json"
	"errors"
	"fmt"
	"slices"

	"github.com/MichaelFraser99/go-jose/internal/algorithms/common"
	"github.com/MichaelFraser99/go-jose/internal/algorithms/eddsa"
	"github.com/MichaelFraser99/go-jose/internal/httputils"
	"github.com/MichaelFraser99/go-jose/internal/jose/jsonutils"
	"github.com/MichaelFraser99/go-jose/joseerror"
	"github.com/MichaelFraser99/go-jose/model"
)

// InlineJWK returns the key of a jwk header when SelectKeys would select it. A key it
// would not select reports ErrNoKeyIdentifierMatch. One whose members break RFC 7517,
// as CheckMemberShape judges them, makes the header malformed, so it reports
// ErrMalformedToken and ErrMalformedClaim.
func InlineJWK(jwk map[string]any, kid *string, alg string, ignoreKeyUse, strictKeyOperations bool) model.Retriever {
	return func() ([]crypto.PublicKey, error) {
		err := checkMember(jwk, kid, alg, ignoreKeyUse, strictKeyOperations)
		if errors.Is(err, joseerror.ErrMalformedClaim) {
			return nil, fmt.Errorf("%wthe 'jwk' header breaks RFC 7517: %w", joseerror.ErrMalformedToken, err)
		}
		if err != nil {
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
			return nil, fmt.Errorf("%wthe jku set has no member selected for this token: each was passed over for its kid, alg, use, key_ops or key type", joseerror.ErrNoKeyIdentifierMatch)
		}

		return keystore, nil
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
//   - it passes CheckMemberShape, checking "use" and "key_ops" unless ignoreKeyUse;
//   - its "kid" is absent or equals kid, which RFC 7515 section 4.1.4 calls a hint;
//   - its "alg" is absent or equals alg, since RFC 8725 section 3.1 requires each key
//     be used with exactly one algorithm;
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
	if err := CheckMemberShape(jwk, joseerror.ErrMalformedClaim, !ignoreKeyUse); err != nil {
		return err
	}
	if member, present := jwk["kid"].(string); present && kid != nil && member != *kid {
		return fmt.Errorf("%wjwk kid does not match value from jose header", joseerror.ErrNoKeyIdentifierMatch)
	}
	if member, present := jwk["alg"].(string); present && !eddsa.SameAlgorithm(member, alg) {
		return fmt.Errorf("%wjwk alg does not match value from jose header", joseerror.ErrNoKeyIdentifierMatch)
	}
	if ignoreKeyUse {
		return nil
	}
	return CheckKeyUse(jwk, "verify", joseerror.ErrNoKeyIdentifierMatch, joseerror.ErrMalformedClaim, strictKeyOperations)
}

var memberClause = map[string]string{"kid": "RFC 7517 section 4.5", "alg": "RFC 7517 section 4.4"}

// CheckMemberShape refuses, with malformed, a jwk whose "kid" or "alg" is not a
// string, as RFC 7517 sections 4.5 and 4.4 define each as one. When keyUse, it
// also refuses a jwk CheckKeyUseShape refuses.
func CheckMemberShape(jwk map[string]any, malformed error, keyUse bool) error {
	for _, name := range []string{"kid", "alg"} {
		if raw, present := jwk[name]; present {
			if _, ok := raw.(string); !ok {
				return fmt.Errorf("%wjwk %s is not a string, which %s requires", malformed, name, memberClause[name])
			}
		}
	}
	if keyUse {
		return CheckKeyUseShape(jwk, malformed)
	}
	return nil
}

// KeyOperations reads a jwk's "key_ops", which RFC 7517 section 4.3 makes an
// array of strings with no value listed twice. It takes the array as
// encoding/json decodes it, a []any, or as a Go caller builds it, a []string.
// present reports whether the member is there. Any other shape, or a value
// listed twice, is refused with malformed.
func KeyOperations(jwk map[string]any, malformed error) (ops []string, present bool, err error) {
	raw, present := jwk["key_ops"]
	if !present {
		return nil, false, nil
	}
	switch values := raw.(type) {
	case []string:
		ops = slices.Clone(values)
	case []any:
		ops = make([]string, 0, len(values))
		for _, value := range values {
			op, ok := value.(string)
			if !ok {
				return nil, true, fmt.Errorf("%wjwk key_ops must hold strings", malformed)
			}
			ops = append(ops, op)
		}
	default:
		return nil, true, fmt.Errorf("%wjwk key_ops must be an array of strings", malformed)
	}
	seen := make(map[string]bool, len(ops))
	for _, op := range ops {
		if seen[op] {
			return nil, true, fmt.Errorf("%wjwk key_ops lists %s more than once", malformed, jsonutils.QuoteBounded(op))
		}
		seen[op] = true
	}
	return ops, true, nil
}

var signatureOperations = map[string]bool{"sign": true, "verify": true}

var nonSignatureOperations = map[string]bool{"encrypt": true, "decrypt": true, "wrapKey": true, "unwrapKey": true, "deriveKey": true, "deriveBits": true}

// CheckKeyUseShape refuses, with malformed, a jwk whose "use" or "key_ops"
// breaks RFC 7517: a "use" that is not a string (section 4.2), a "key_ops" that
// KeyOperations refuses, or a "use" and "key_ops" that are not consistent,
// which section 4.3 says they MUST be. A "use" of "sig" is not consistent with
// an encryption, key wrapping or key agreement operation, and a "use" of "enc"
// is not consistent with "sign" or "verify".
func CheckKeyUseShape(jwk map[string]any, malformed error) error {
	raw, usePresent := jwk["use"]
	use, ok := raw.(string)
	if usePresent && !ok {
		return fmt.Errorf("%wjwk use must be a string (RFC 7517 section 4.2)", malformed)
	}
	ops, _, err := KeyOperations(jwk, malformed)
	if err != nil {
		return err
	}
	for _, op := range ops {
		if use == "sig" && nonSignatureOperations[op] || use == "enc" && signatureOperations[op] {
			return fmt.Errorf("%wjwk use %s and key_ops %s are not consistent, which RFC 7517 section 4.3 says they MUST be", malformed, use, op)
		}
	}
	return nil
}

// CheckKeyUse refuses a jwk its publisher marked as not for the signature
// operation named by operation, "sign" or "verify": one whose "use" is present
// and is not "sig" (RFC 7517 section 4.2), or whose "key_ops" is present and
// lacks operation (RFC 7517 section 4.3). Such a mark is refused with refused.
// A jwk CheckKeyUseShape refuses is refused first, with malformed. When
// strictKeyOperations, a jwk CheckRecommendedKeyOperations refuses is refused
// with refused.
func CheckKeyUse(jwk map[string]any, operation string, refused, malformed error, strictKeyOperations bool) error {
	if err := CheckKeyUseShape(jwk, malformed); err != nil {
		return err
	}
	if use, present := jwk["use"].(string); present && use != "sig" {
		return fmt.Errorf("%wjwk use %s is not sig", refused, jsonutils.QuoteBounded(use))
	}
	if ops, present, _ := KeyOperations(jwk, malformed); present && !slices.Contains(ops, operation) {
		return fmt.Errorf("%wjwk key_ops do not include %s", refused, operation)
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
// pairs. A "key_ops" that KeyOperations refuses is refused with refused.
func CheckRecommendedKeyOperations(jwk map[string]any, refused error) error {
	ops, present, err := KeyOperations(jwk, refused)
	if err != nil {
		return err
	}
	if !present {
		return nil
	}
	if _, use := jwk["use"]; use {
		return fmt.Errorf("%wjwk carries both use and key_ops, which RFC 7517 section 4.3 says SHOULD NOT be used together", refused)
	}
	if len(ops) < 2 || len(ops) == 2 && slices.ContainsFunc(relatedOperations, func(pair []string) bool {
		return slices.Contains(ops, pair[0]) && slices.Contains(ops, pair[1])
	}) {
		return nil
	}
	return fmt.Errorf("%wjwk key_ops names unrelated operations, which RFC 7517 section 4.3 says SHOULD NOT be combined", refused)
}
