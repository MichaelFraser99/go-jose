package jwk

import (
	"crypto"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/MichaelFraser99/go-jose/internal/algorithms/common"
	"github.com/MichaelFraser99/go-jose/internal/httputils"
	"github.com/MichaelFraser99/go-jose/joseerror"
	"github.com/MichaelFraser99/go-jose/model"
	"io"
	"net/http"
)

func InlineJWK(jwk map[string]any, kid *string, alg string) model.Retriever {
	return func() ([]crypto.PublicKey, error) {
		if kid != nil {
			if k, present := jwk["kid"]; present {
				if sk, ok := k.(string); ok {
					if sk != *kid {
						return nil, fmt.Errorf("%wjwk kid does not match value from jose header", joseerror.ErrNoKeyIdentifierMatch)
					}
				} else {
					return nil, fmt.Errorf("%wreturned jwk has malformed kid value", joseerror.ErrMalformedClaim)
				}
			}
		}

		if k, present := jwk["alg"]; present {
			if sk, ok := k.(string); ok {
				if sk != alg {
					return nil, fmt.Errorf("%wjwk alg does not match value from jose header", joseerror.ErrNoKeyIdentifierMatch)
				}
			} else {
				return nil, fmt.Errorf("%wreturned jwk has malformed alg value", joseerror.ErrMalformedClaim)
			}
		}

		publicKey, err := PublicFromJwk(jwk)
		if err != nil {
			return nil, fmt.Errorf("%wfailed to convert jwk to public key: %w", joseerror.ErrApplicationError, err)
		}

		return []crypto.PublicKey{publicKey}, nil
	}
}

func RetrieveJKU(jku string, client *http.Client, kid *string, alg string) model.Retriever {
	return func() ([]crypto.PublicKey, error) {
		response, err := httputils.RetrieveResource(client, jku, "jku")
		if err != nil {
			return nil, err
		}

		if response.Body == nil {
			return nil, fmt.Errorf("%wfailed to retrieve jku: response body is nil", joseerror.ErrApplicationError)
		}

		responseBytes, err := io.ReadAll(response.Body)
		if err != nil {
			return nil, fmt.Errorf("%wfailed to read jku response: %w", joseerror.ErrApplicationError, err)
		}

		err = response.Body.Close()
		if err != nil {
			return nil, fmt.Errorf("%wfailed to close jku response: %w", joseerror.ErrApplicationError, err)
		}

		var returnedKeystore model.Jwks
		err = json.Unmarshal(responseBytes, &returnedKeystore)
		if err != nil {
			return nil, fmt.Errorf("%wfailed to unmarshal jku response: %w", joseerror.ErrApplicationError, err)
		}

		var keystore []crypto.PublicKey

		filteredKeystore := SelectKeys(returnedKeystore, kid, &alg)

		for _, jwk := range filteredKeystore.Keys {

			publicKey, err := PublicFromJwk(jwk)
			if err != nil {
				if errors.Is(err, joseerror.ErrUnsupportedAlgorithm) {
					continue //simply omit jwk if a type the application doesn't support
				} else {
					return nil, fmt.Errorf("%wfailed to convert jwk to public key: %w", joseerror.ErrApplicationError, err)
				}
			} else {
				keystore = append(keystore, publicKey)
			}
		}
		if len(keystore) == 0 {
			return nil, fmt.Errorf("%wnone of the returned jwk entries match the identifiers specified in the jose header", joseerror.ErrNoKeyIdentifierMatch)
		}

		return keystore, err
	}
}

func PrivateFromJwk(jwk map[string]any) (crypto.PrivateKey, error) {
	if kty, present := jwk["kty"]; present {
		switch kty.(string) {
		case "EC":
			return common.ECDSAPrivateKeyFromJwk(jwk)
		case "RSA":
			return common.RSAPrivateKeyFromJwk(jwk)
		case "OKP":
			return common.EdDSAPrivateKeyFromJwk(jwk)
		default:
			return nil, fmt.Errorf("%wunsupported kty: %s", joseerror.ErrUnsupportedAlgorithm, kty.(string))
		}
	} else {
		return nil, fmt.Errorf("no kty claim present in jwk, cannot infer type of private key to return")
	}
}

func PublicFromJwk(jwk map[string]any) (crypto.PublicKey, error) {
	if kty, present := jwk["kty"]; present {
		switch kty.(string) {
		case "EC":
			return common.ECDSAPublicKeyFromJwk(jwk)
		case "RSA":
			return common.RSAPublicKeyFromJwk(jwk)
		case "OKP":
			return common.EdDSAPublicKeyFromJwk(jwk)
		default:
			return nil, fmt.Errorf("%wunsupported kty: %s", joseerror.ErrUnsupportedAlgorithm, kty.(string))
		}
	} else {
		return nil, fmt.Errorf("no kty claim present in jwk, cannot infer type of public key to return")
	}
}

func SelectKeys(keySet model.Jwks, kid, alg *string) model.Jwks { //todo: this can be refactored to be less verbose
	var keys = keySet.Keys

	if kid != nil {
		var kidMatches []map[string]any

		for _, k := range keys {
			if jwkKid, found := k["kid"]; found {
				if jwkKid == *kid {
					kidMatches = append(kidMatches, k)
				}
			}
		}
		if len(kidMatches) > 0 { //if it has narrowed the list at all
			keys = kidMatches
		}
	}

	if alg != nil {
		var algMatches []map[string]any
		for _, k := range keys {
			if jwkAlg, found := k["alg"]; found {
				if jwkAlg == *alg {
					algMatches = append(algMatches, k)
				}
			}
		}
		if len(algMatches) > 0 {
			keys = algMatches
		}
	}

	return model.Jwks{
		Keys: keys,
	}
}
