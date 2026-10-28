package jwk

import (
	"crypto"
	"encoding/json"
	"fmt"
	"github.com/MichaelFraser99/go-jose/internal/algorithms/common"
	"github.com/MichaelFraser99/go-jose/internal/httputils"
	"github.com/MichaelFraser99/go-jose/joseerror"
	"github.com/MichaelFraser99/go-jose/model"
)

// InlineJWK returns the key of a jwk header when SelectKeys would select it. A key it
// would not select reports ErrNoKeyIdentifierMatch, or ErrMalformedClaim when one of
// the members it judges by has the wrong type.
func InlineJWK(jwk map[string]any, kid *string, alg string, ignoreKeyUse bool) model.Retriever {
	return func() ([]crypto.PublicKey, error) {
		if err := checkMember(jwk, kid, alg, ignoreKeyUse); err != nil {
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
func RetrieveJKU(jku string, fetch httputils.Fetch, kid *string, alg string, ignoreKeyUse bool) model.Retriever {
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

		keystore := SelectKeys(returnedKeystore, kid, alg, ignoreKeyUse)
		if len(keystore) == 0 {
			return nil, fmt.Errorf("%wno usable jwk entry in the returned set matches the identifiers specified in the jose header", joseerror.ErrNoKeyIdentifierMatch)
		}

		return keystore, nil
	}
}

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
			key, err := common.EdDSAPrivateKeyFromJwk(jwk)
			if err != nil {
				return nil, err
			}
			return key, nil
		default:
			return nil, fmt.Errorf("%wunsupported kty: %s", joseerror.ErrUnsupportedAlgorithm, ktyString)
		}
	} else {
		return nil, fmt.Errorf("no kty claim present in jwk, cannot infer type of private key to return")
	}
}

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
			key, err := common.EdDSAPublicKeyFromJwk(jwk)
			if err != nil {
				return nil, err
			}
			return key, nil
		default:
			return nil, fmt.Errorf("%wunsupported kty: %s", joseerror.ErrUnsupportedAlgorithm, ktyString)
		}
	} else {
		return nil, fmt.Errorf("no kty claim present in jwk, cannot infer type of public key to return")
	}
}

// SelectKeys returns the key of each member of keySet that can verify a JWS whose
// header names kid and alg, in set order. Each member is judged on its own, so no
// member admits or excludes another. A member is selected when:
//   - this library can read it, since RFC 7517 section 5 says to ignore one it cannot;
//   - its "kid" is absent or equals kid, which RFC 7515 section 4.1.4 calls a hint;
//   - its "alg" is absent or equals alg, since RFC 8725 section 3.1 requires each key
//     be used with exactly one algorithm;
//   - unless ignoreKeyUse, its "use" is absent or "sig" and its "key_ops" is absent or
//     includes "verify" (RFC 7517 sections 4.2 and 4.3).
func SelectKeys(keySet model.Jwks, kid *string, alg string, ignoreKeyUse bool) []crypto.PublicKey {
	var selected []crypto.PublicKey
	for _, member := range keySet.Keys {
		publicKey, err := PublicFromJwk(member)
		if err != nil {
			continue
		}
		if checkMember(member, kid, alg, ignoreKeyUse) != nil {
			continue
		}
		selected = append(selected, publicKey)
	}
	return selected
}

func checkMember(jwk map[string]any, kid *string, alg string, ignoreKeyUse bool) error {
	if kid != nil {
		if k, present := jwk["kid"]; present {
			sk, ok := k.(string)
			if !ok {
				return fmt.Errorf("%wjwk has malformed kid value", joseerror.ErrMalformedClaim)
			}
			if sk != *kid {
				return fmt.Errorf("%wjwk kid does not match value from jose header", joseerror.ErrNoKeyIdentifierMatch)
			}
		}
	}

	if a, present := jwk["alg"]; present {
		sa, ok := a.(string)
		if !ok {
			return fmt.Errorf("%wjwk has malformed alg value", joseerror.ErrMalformedClaim)
		}
		if sa != alg {
			return fmt.Errorf("%wjwk alg does not match value from jose header", joseerror.ErrNoKeyIdentifierMatch)
		}
	}

	if ignoreKeyUse {
		return nil
	}

	if u, present := jwk["use"]; present {
		su, ok := u.(string)
		if !ok {
			return fmt.Errorf("%wjwk has malformed use value", joseerror.ErrMalformedClaim)
		}
		if su != "sig" {
			return fmt.Errorf("%wjwk use %q is not sig", joseerror.ErrNoKeyIdentifierMatch, su)
		}
	}

	if o, present := jwk["key_ops"]; present {
		ops, ok := o.([]any)
		if !ok {
			return fmt.Errorf("%wjwk key_ops must be an array", joseerror.ErrMalformedClaim)
		}
		verify := false
		for _, op := range ops {
			sop, ok := op.(string)
			if !ok {
				return fmt.Errorf("%wjwk key_ops must hold strings", joseerror.ErrMalformedClaim)
			}
			if sop == "verify" {
				verify = true
			}
		}
		if !verify {
			return fmt.Errorf("%wjwk key_ops do not include verify", joseerror.ErrNoKeyIdentifierMatch)
		}
	}

	return nil
}
