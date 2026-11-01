package jsonutils

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/MichaelFraser99/go-jose/joseerror"
	"github.com/MichaelFraser99/go-jose/jwa"
	"net/url"
	"reflect"
	"slices"
	"strconv"
	"unicode"
	"unicode/utf16"
	"unicode/utf8"
)

// MaxEchoedRunes is how many runes of a peer's value QuoteBounded keeps.
const MaxEchoedRunes = 64

// QuoteBounded quotes a peer's value for an error message, keeping at most
// MaxEchoedRunes runes and marking a cut with a trailing "...".
func QuoteBounded(value string) string {
	runes := 0
	for i := range value {
		if runes == MaxEchoedRunes {
			return strconv.Quote(value[:i]) + "..."
		}
		runes++
	}
	return strconv.Quote(value)
}

// DecodeBase64url decodes Base64url Encoding as RFC 7515 section 2 defines it:
// the RFC 4648 section 5 alphabet with no padding and no line breaks, whitespace
// or other characters. Non-zero pad bits are refused, as RFC 4648 section 3.5
// permits, so each octet sequence has exactly one accepted encoding.
func DecodeBase64url(encoded string) ([]byte, error) {
	for i := 0; i < len(encoded); i++ {
		if !isBase64urlCharacter(encoded[i]) {
			return nil, fmt.Errorf("the character at offset %d is not in the base64url alphabet", i)
		}
	}
	return base64.RawURLEncoding.Strict().DecodeString(encoded)
}

func isBase64urlCharacter(c byte) bool {
	return 'A' <= c && c <= 'Z' || 'a' <= c && c <= 'z' || '0' <= c && c <= '9' || c == '-' || c == '_'
}

type Validator[T any] func(header map[string]any, retrievedValue T) error

func KeyPresent(m map[string]any, key string) bool {
	_, ok := m[key]
	return ok
}

func ExtractAndDecodeBase64urlString(m map[string]any, key string) ([]byte, error) {
	if v, present := m[key]; present {
		if vString, ok := v.(string); ok {
			vBytes, err := DecodeBase64url(vString)
			if err != nil {
				return nil, fmt.Errorf("%winvalid base64url in %q claim", joseerror.ErrMalformedClaim, key)
			}
			return vBytes, nil
		} else {
			return nil, fmt.Errorf("%wprovided %q claim cannot be parsed as a string", joseerror.ErrMalformedClaim, key)
		}
	} else {
		return nil, fmt.Errorf("%wno %q claim present in map", joseerror.ErrMissingClaim, key)
	}
}

// DecodeBase64urlMap decodes a base64url segment with DecodeBase64url and parses
// the octets with DecodeJSONObject.
func DecodeBase64urlMap(b64u string) (map[string]any, error) {
	decodedBytes, err := DecodeBase64url(b64u)
	if err != nil {
		return nil, err
	}
	return DecodeJSONObject(decodedBytes)
}

// DecodeJSONObject parses octets that RFC 7515 section 5.2 step 3 and RFC 7519
// section 7.2 step 10 require to be a UTF-8 representation of a JSON object, so
// invalid UTF-8 (RFC 8725 section 3.7) and null are refused. So is a string
// holding an unpaired UTF-16 surrogate escape, whose meaning RFC 8259 section
// 8.2 calls unpredictable.
func DecodeJSONObject(decodedBytes []byte) (map[string]any, error) {
	if !utf8.Valid(decodedBytes) {
		return nil, errors.New("the decoded octets are not valid UTF-8")
	}
	if hasUnpairedSurrogateEscape(decodedBytes) {
		return nil, errors.New("the decoded JSON holds an unpaired UTF-16 surrogate escape")
	}

	var m map[string]any
	if err := json.Unmarshal(decodedBytes, &m); err != nil {
		return nil, err
	}
	if m == nil {
		return nil, errors.New("the decoded JSON is null, not an object")
	}

	return m, nil
}

func hasUnpairedSurrogateEscape(text []byte) bool {
	inString := false
	for i := 0; i < len(text); i++ {
		switch {
		case !inString:
			inString = text[i] == '"'
		case text[i] == '"':
			inString = false
		case text[i] == '\\':
			high, ok := unicodeEscapeAt(text, i)
			if !ok {
				i++
				continue
			}
			i += 5
			if !utf16.IsSurrogate(high) {
				continue
			}
			low, ok := unicodeEscapeAt(text, i+1)
			if !ok || utf16.DecodeRune(high, low) == unicode.ReplacementChar {
				return true
			}
			i += 6
		}
	}
	return false
}

func unicodeEscapeAt(text []byte, i int) (rune, bool) {
	if i+6 > len(text) || text[i] != '\\' || text[i+1] != 'u' {
		return 0, false
	}
	var r rune
	for _, c := range text[i+2 : i+6] {
		switch {
		case '0' <= c && c <= '9':
			r = r<<4 | rune(c-'0')
		case 'a' <= c && c <= 'f':
			r = r<<4 | rune(c-'a'+10)
		case 'A' <= c && c <= 'F':
			r = r<<4 | rune(c-'A'+10)
		default:
			return 0, false
		}
	}
	return r, true
}

func RetrieveClaim[T any](jsonInput map[string]any, claimName string, validator ...Validator[T]) (*T, error) {
	var castedValue T
	if value, ok := jsonInput[claimName]; ok {
		if castedValue, ok = value.(T); !ok {
			return nil, fmt.Errorf("%wthe value of claim '%s' cannot be parsed as a %s", joseerror.ErrMalformedClaim, claimName, reflect.TypeOf(castedValue).String())
		}
	} else {
		return nil, fmt.Errorf("%w'%s' key is missing", joseerror.ErrMissingClaim, claimName)
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
			return fmt.Errorf("%w%s is not a supported algorithm", joseerror.ErrUnsupportedAlgorithm, QuoteBounded(retrievedClaimValue))
		}
		return nil
	}

	ValidateHttpsUrlClaim = func(jsonInput map[string]any, retrievedClaimValue string) error {
		parsedUrl, err := url.Parse(retrievedClaimValue)
		if err != nil {
			return fmt.Errorf("%w%s is not a valid URL", joseerror.ErrMalformedClaim, QuoteBounded(retrievedClaimValue))
		}
		if parsedUrl.Scheme != "https" {
			return fmt.Errorf("%w%s is not a valid HTTPS URL", joseerror.ErrMalformedClaim, QuoteBounded(retrievedClaimValue))
		}
		return nil
	}

	ValidateBase64Url = func(jsonInput map[string]any, retrievedClaimValue string) error {
		if retrievedClaimValue == "" {
			return fmt.Errorf("%wthe claim's value is an empty string", joseerror.ErrMalformedClaim)
		}
		_, err := DecodeBase64url(retrievedClaimValue)
		if err != nil {
			return fmt.Errorf("%w%s is not valid base64url", joseerror.ErrMalformedClaim, QuoteBounded(retrievedClaimValue))
		}
		return nil
	}

	ValidateNonEmptySlice = Validator[[]any](func(jsonInput map[string]any, s []any) error {
		if len(s) == 0 {
			return fmt.Errorf("%wthe provided slice is empty", joseerror.ErrMalformedClaim)
		}
		return nil
	})

	ValidateNoDuplicateSliceValues = Validator[[]any](func(jsonInput map[string]any, s []any) error {
		seen := make(map[string]struct{}, len(s))

		for _, v := range s {
			key, err := json.Marshal(v)
			if err != nil {
				return fmt.Errorf("%wthe array holds a value that cannot be compared", joseerror.ErrMalformedClaim)
			}
			if _, exists := seen[string(key)]; exists {
				return fmt.Errorf("%wthe array has duplicate values", joseerror.ErrMalformedClaim)
			}
			seen[string(key)] = struct{}{}
		}
		return nil
	})

	ValidateNoBannedCriticalValues = Validator[[]any](func(jsonInput map[string]any, critical []any) error {
		bannedCriticalValues := []string{
			"alg", "jku", "jwk", "kid", "x5u", "x5c", "x5t", "x5t#S256", "typ", "cty", "crit",
		}
		for _, claim := range critical {
			if sClaim, ok := claim.(string); !ok {
				return fmt.Errorf("%wthe 'crit' array contains one or more non-string values", joseerror.ErrMalformedClaim)
			} else {
				for _, bannedClaim := range bannedCriticalValues {
					if sClaim == bannedClaim {
						return fmt.Errorf("%wthe 'crit' array contains one or more illegal values", joseerror.ErrMalformedClaim)
					}
				}
			}
		}
		return nil
	})

	ValidateNoBannedCriticalJWEValues = Validator[[]any](func(jsonInput map[string]any, critical []any) error {
		bannedCriticalValues := []string{
			"alg", "enc", "zip", "jku", "jwk", "kid", "x5u", "x5c", "x5t", "x5t#S256", "typ", "cty", "crit",
			"epk", "apu", "apv", "iv", "tag", "p2s", "p2c",
		}
		for _, claim := range critical {
			if sClaim, ok := claim.(string); !ok {
				return fmt.Errorf("%wthe 'crit' array contains one or more non-string values", joseerror.ErrMalformedClaim)
			} else {
				for _, bannedClaim := range bannedCriticalValues {
					if sClaim == bannedClaim {
						return fmt.Errorf("%wthe 'crit' array contains one or more illegal values in JWE", joseerror.ErrMalformedClaim)
					}
				}
			}
		}
		return nil
	})

	ValidateCriticalValuesPresent = Validator[[]any](func(jsonInput map[string]any, critical []any) error {
		for _, claim := range critical {
			if sClaim, ok := claim.(string); !ok {
				return fmt.Errorf("%wthe 'crit' array contains one or more non-string values", joseerror.ErrMalformedClaim)
			} else {
				if _, ok := jsonInput[sClaim]; !ok {
					return fmt.Errorf("%wthe 'crit' array contains one or more values not included in the header", joseerror.ErrMissingCriticalClaim)
				}
			}
		}
		return nil
	})
)

// UnderstoodCriticalValues builds a validator refusing any 'crit' entry not named
// in understood.
//
// RFC 7515 section 4.1.11 says a JWS whose 'crit' lists an extension the recipient
// does not understand MUST be rejected. This library understands no extensions of
// its own, so with nothing named every entry is refused.
func UnderstoodCriticalValues(understood []string) Validator[[]any] {
	return Validator[[]any](func(jsonInput map[string]any, critical []any) error {
		for _, claim := range critical {
			name, ok := claim.(string)
			if !ok {
				return fmt.Errorf("%wthe 'crit' array contains one or more non-string values", joseerror.ErrMalformedClaim)
			}
			if !slices.Contains(understood, name) {
				return fmt.Errorf("%wthe 'crit' array names %s, which this recipient does not understand", joseerror.ErrMissingCriticalClaim, QuoteBounded(name))
			}
		}
		return nil
	})
}
