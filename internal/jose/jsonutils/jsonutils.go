package jsonutils

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"github.com/MichaelFraser99/go-jose/joseerror"
	"github.com/MichaelFraser99/go-jose/jwa"
	"net/url"
	"reflect"
)

type Validator[T any] func(header map[string]any, retrievedValue T) error

func KeyPresent(m map[string]any, key string) bool {
	_, ok := m[key]
	return ok
}

func ExtractAndDecodeBase64urlString(m map[string]any, key string) ([]byte, error) {
	if v, present := m[key]; present {
		if vString, ok := v.(string); ok {
			vBytes, err := base64.RawURLEncoding.DecodeString(vString)
			if err != nil {
				return nil, fmt.Errorf("%winvalid base64url in %q claim", joseerror.MalformedClaim, key)
			}
			return vBytes, nil
		} else {
			return nil, fmt.Errorf("%wprovided %q claim cannot be parsed as a string", joseerror.MalformedClaim, key)
		}
	} else {
		return nil, fmt.Errorf("%wno %q claim present in map", joseerror.MissingClaim, key)
	}
}

func DecodeBase64urlMap(b64u string) (map[string]any, error) {
	decodedBytes, err := base64.RawURLEncoding.DecodeString(b64u)
	if err != nil {
		return nil, err
	}

	var m map[string]any
	if err = json.Unmarshal(decodedBytes, &m); err != nil {
		return nil, err
	}

	return m, nil
}

func RetrieveClaim[T any](jsonInput map[string]any, claimName string, validator ...Validator[T]) (*T, error) {
	var castedValue T
	if value, ok := jsonInput[claimName]; ok {
		if castedValue, ok = value.(T); !ok {
			return nil, fmt.Errorf("%wthe value of claim '%s' cannot be parsed as a %s", joseerror.MalformedClaim, claimName, reflect.TypeOf(castedValue).String())
		}
	} else {
		return nil, fmt.Errorf("%w'%s' key is missing", joseerror.MissingClaim, claimName)
	}

	for _, v := range validator {
		err := v(jsonInput, castedValue)
		if err != nil {
			return nil, err
		}
	}
	return &castedValue, nil
}

var (
	ValidateAlg = func(jsonInput map[string]any, retrievedClaimValue string) error {
		parsedAlg := jwa.GetAlgorithm(retrievedClaimValue)
		if parsedAlg == jwa.Unknown {
			return fmt.Errorf("%w'%s' is not a supported algorithm", joseerror.UnsupportedAlgorithm, retrievedClaimValue)
		}
		return nil
	}

	ValidateHttpsUrlClaim = func(jsonInput map[string]any, retrievedClaimValue string) error {
		parsedUrl, err := url.Parse(retrievedClaimValue)
		if err != nil {
			return fmt.Errorf("%w'%s' is not a valid URL", joseerror.MalformedClaim, retrievedClaimValue)
		}
		if parsedUrl.Scheme != "https" {
			return fmt.Errorf("%w'%s' is not a valid HTTPS URL", joseerror.MalformedClaim, retrievedClaimValue)
		}
		return nil
	}

	ValidateBase64Url = func(jsonInput map[string]any, retrievedClaimValue string) error {
		if retrievedClaimValue == "" {
			return fmt.Errorf("%wthe claim's value is an empty string", joseerror.MalformedClaim)
		}
		_, err := base64.RawURLEncoding.DecodeString(retrievedClaimValue)
		if err != nil {
			return fmt.Errorf("%w'%s' is not valid base64url", joseerror.MalformedClaim, retrievedClaimValue)
		}
		return nil
	}

	ValidateNonEmptySlice = Validator[[]any](func(jsonInput map[string]any, s []any) error {
		if len(s) == 0 {
			return fmt.Errorf("%wthe provided slice is empty", joseerror.MalformedClaim)
		}
		return nil
	})

	ValidateNoDuplicateSliceValues = Validator[[]any](func(jsonInput map[string]any, s []any) error {
		seen := make(map[any]struct{}, len(s))

		for _, v := range s {
			if _, exists := seen[v]; exists {
				return fmt.Errorf("%wthe array has duplicate values", joseerror.MalformedClaim)
			}
			seen[v] = struct{}{}
		}
		return nil
	})

	ValidateNoBannedCriticalValues = Validator[[]any](func(jsonInput map[string]any, critical []any) error {
		bannedCriticalValues := []string{
			"alg", "jku", "jwk", "kid", "x5u", "x5c", "x5t", "x5t#S256", "typ", "cty", "crit",
		}
		for _, claim := range critical {
			if sClaim, ok := claim.(string); !ok {
				return fmt.Errorf("%wthe 'crit' array contains one or more non-string values", joseerror.MalformedClaim)
			} else {
				for _, bannedClaim := range bannedCriticalValues {
					if sClaim == bannedClaim {
						return fmt.Errorf("%wthe 'crit' array contains one or more illegal values", joseerror.MalformedClaim)
					}
				}
			}
		}
		return nil
	})

	ValidateNoBannedCriticalJWEValues = Validator[[]any](func(jsonInput map[string]any, critical []any) error {
		bannedCriticalValues := []string{
			"zip",
		}
		for _, claim := range critical {
			if sClaim, ok := claim.(string); !ok {
				return fmt.Errorf("%wthe 'crit' array contains one or more non-string values", joseerror.MalformedClaim)
			} else {
				for _, bannedClaim := range bannedCriticalValues {
					if sClaim == bannedClaim {
						return fmt.Errorf("%wthe 'crit' array contains one or more illegal values in JWE", joseerror.MalformedClaim)
					}
				}
			}
		}
		return nil
	})

	ValidateCriticalValuesPresent = Validator[[]any](func(jsonInput map[string]any, critical []any) error {
		for _, claim := range critical {
			if sClaim, ok := claim.(string); !ok {
				return fmt.Errorf("%wthe 'crit' array contains one or more non-string values", joseerror.MalformedClaim)
			} else {
				if _, ok := jsonInput[sClaim]; !ok {
					return fmt.Errorf("%wthe 'crit' array contains one or more values not included in the header", joseerror.MissingCriticalClaim)
				}
			}
		}
		return nil
	})
)
