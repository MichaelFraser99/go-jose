package jsonutils

import (
	"encoding/base64"
	"errors"
	"fmt"
	"github.com/MichaelFraser99/go-jose/joseerror"
	"reflect"
	"testing"
)

func Test_retrieveClaim(t *testing.T) {
	tests := map[string]struct {
		header map[string]any
		key    string
		want   any
		err    error
	}{
		"happy path": {
			header: map[string]any{
				"alg": "RS256",
			},
			key:  "alg",
			want: "RS256",
			err:  nil,
		},
		"missing key": {
			header: map[string]any{
				"alg": "foo-bar",
			},
			key:  "kid",
			want: nil,
			err:  fmt.Errorf("%w'kid' key is missing", joseerror.MissingClaim),
		},
		"unexpected type": {
			header: map[string]any{
				"alg": 123,
			},
			key:  "alg",
			want: nil,
			err:  fmt.Errorf("%wthe value of claim 'alg' cannot be parsed as a string", joseerror.MalformedClaim),
		},
	}

	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			result, err := RetrieveClaim[string](test.header, test.key)
			if err != nil {
				if test.err == nil {
					t.Fatalf("unexpected error: %v", err)
				}
				if test.err.Error() != err.Error() {
					t.Fatalf("expected error %v, got %v", test.err, err)
				}
			} else {
				if test.err != nil {
					t.Fatalf("expected error %v, got nil", test.err)
				}
				if result == nil {
					if test.want != nil {
						t.Fatalf("nil returned but expected %v", test.want)
					}
				} else {
					if test.want != *result {
						t.Fatalf("expected %v, got %s", test.want, *result)
					}
				}
			}
		})
	}
}

func Test_validateAlg(t *testing.T) {
	tests := map[string]struct {
		retrievedClaimValue string
		errMsg              string
		errTypes            []error
	}{
		"happy path": {
			retrievedClaimValue: "RS256",
		},
		"invalid alg": {
			retrievedClaimValue: "foo-bar",
			errMsg:              "'foo-bar' is not a supported algorithm",
			errTypes:            []error{joseerror.UnsupportedAlgorithm},
		},
		"missing alg": {
			retrievedClaimValue: "",
			errMsg:              "'' is not a supported algorithm",
			errTypes:            []error{joseerror.UnsupportedAlgorithm},
		},
	}

	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			err := ValidateAlg(map[string]any{}, test.retrievedClaimValue)
			validateTestError(t, err, test.errMsg, test.errTypes)
		})
	}
}

func Test_validateHttpsUrlClaim(t *testing.T) {
	tests := map[string]struct {
		retrievedClaimValue string
		errMsg              string
		errTypes            []error
	}{
		"happy path": {
			retrievedClaimValue: "https://example.com",
		},
		"http url": {
			retrievedClaimValue: "http://example.com",
			errMsg:              "'http://example.com' is not a valid HTTPS URL",
			errTypes:            []error{joseerror.MalformedClaim},
		},
		"illegal character in url": {
			retrievedClaimValue: "foobar" + string(rune(0x7f)),
			errMsg:              fmt.Sprintf("'%s' is not a valid URL", "foobar"+string(rune(0x7f))),
			errTypes:            []error{joseerror.MalformedClaim},
		},
		"empty string": {
			retrievedClaimValue: "",
			errMsg:              "'' is not a valid HTTPS URL",
			errTypes:            []error{joseerror.MalformedClaim},
		},
	}

	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			err := ValidateHttpsUrlClaim(map[string]any{}, test.retrievedClaimValue)
			validateTestError(t, err, test.errMsg, test.errTypes)
		})
	}
}

func Test_validateBase64Url(t *testing.T) {
	tests := map[string]struct {
		retrievedClaimValue string
		errMsg              string
		errTypes            []error
	}{
		"happy path": {
			retrievedClaimValue: "eyJhbGciOiJSUzI1NiIsInR5cCI6Impzb24rc2Qtand0In0",
		},
		"invalid base64url": {
			retrievedClaimValue: "abcde",
			errMsg:              "'abcde' is not valid base64url",
			errTypes:            []error{joseerror.MalformedClaim},
		},
		"padded base64url": {
			retrievedClaimValue: "eyJhbGciOiJSUzI1NiIsInR5cCI6Impzb24rc2Qtand0In0==",
			errMsg:              "'eyJhbGciOiJSUzI1NiIsInR5cCI6Impzb24rc2Qtand0In0==' is not valid base64url",
			errTypes:            []error{joseerror.MalformedClaim},
		},
		"empty string": {
			retrievedClaimValue: "",
			errMsg:              "the claim's value is an empty string",
			errTypes:            []error{joseerror.MalformedClaim},
		},
	}

	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			err := ValidateBase64Url(map[string]any{}, test.retrievedClaimValue)
			validateTestError(t, err, test.errMsg, test.errTypes)
		})
	}
}

func Test_validateNonEmptySlice(t *testing.T) {
	tests := map[string]struct {
		slice    []any
		errMsg   string
		errTypes []error
	}{
		"happy path - string": {
			slice: []any{"foo", "bar"},
		},
		"happy path - int": {
			slice: []any{1, 2},
		},
		"happy path - bool": {
			slice: []any{true, false},
		},
		"empty slice": {
			slice:    []any{},
			errMsg:   "the provided slice is empty",
			errTypes: []error{joseerror.MalformedClaim},
		},
		"nil slice": {
			slice:  nil,
			errMsg: "the provided slice is empty",
		},
	}

	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			err := ValidateNonEmptySlice(map[string]any{}, test.slice)
			validateTestError(t, err, test.errMsg, test.errTypes)
		})
	}
}

func Test_validateNoDuplicateSliceValues(t *testing.T) {
	tests := map[string]struct {
		slice    []any
		errMsg   string
		errTypes []error
	}{
		"happy path - string": {
			slice: []any{"foo", "bar"},
		},
		"happy path - int": {
			slice: []any{1, 2},
		},
		"happy path - bool": {
			slice: []any{true, false},
		},
		"duplicate values - string": {
			slice:    []any{"foo", "bar", "foo"},
			errMsg:   "the array has duplicate values",
			errTypes: []error{joseerror.MalformedClaim},
		},
		"duplicate values - int": {
			slice:    []any{1, 2, 1},
			errMsg:   "the array has duplicate values",
			errTypes: []error{joseerror.MalformedClaim},
		},
		"duplicate values - bool": {
			slice:    []any{true, false, true},
			errMsg:   "the array has duplicate values",
			errTypes: []error{joseerror.MalformedClaim},
		},
		"empty slice": {
			slice: []any{},
		},
		"nil slice": {
			slice: nil,
		},
		"malformed slice element - nil": {
			slice: []any{"foo", nil, "bar"},
		},
		"malformed slice element - empty string": {
			slice: []any{"foo", "", "bar"},
		},
	}

	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			err := ValidateNoDuplicateSliceValues(map[string]any{}, test.slice)
			validateTestError(t, err, test.errMsg, test.errTypes)
		})
	}
}

func Test_validateNoBannedCriticalValues(t *testing.T) {
	tests := map[string]struct {
		critical []any
		errMsg   string
		errTypes []error
	}{
		"happy path": {
			critical: []any{"foo", "bar"},
		},
		"empty slice": {
			critical: []any{},
		},
		"nil slice": {
			critical: nil,
		},
		"single illegal value": {
			critical: []any{"alg"},
			errMsg:   "the 'crit' array contains one or more illegal values",
			errTypes: []error{joseerror.MalformedClaim},
		},
		"multiple illegal values": {
			critical: []any{"alg", "jku", "jwk"},
			errMsg:   "the 'crit' array contains one or more illegal values",
			errTypes: []error{joseerror.MalformedClaim},
		},
		"mixed illegal and legal values": {
			critical: []any{"foo", "alg", "bar", "jwk", "baz"},
			errMsg:   "the 'crit' array contains one or more illegal values",
			errTypes: []error{joseerror.MalformedClaim},
		},
	}

	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			err := ValidateNoBannedCriticalValues(map[string]any{}, test.critical)
			validateTestError(t, err, test.errMsg, test.errTypes)
		})
	}
}

func Test_validateCriticalValuesPresent(t *testing.T) {
	tests := map[string]struct {
		header   map[string]any
		critical []any
		errMsg   string
		errTypes []error
	}{
		"happy path": {
			header: map[string]any{
				"alg": "RS256",
				"jku": "https://example.com/jwks.json",
				"jwk": map[string]any{
					"kty": "RSA",
					"e":   "AQAB",
				},
				"foo": "bar",
				"bin": "baz",
			},
			critical: []any{"foo", "bin"},
		},
		"happy path - single value": {
			header: map[string]any{
				"alg": "RS256",
				"jku": "https://example.com/jwks.json",
				"jwk": map[string]any{
					"kty": "RSA",
					"e":   "AQAB",
				},
				"foo": "bar",
				"bin": "baz",
			},
			critical: []any{"foo"},
		},
		"no critical values": {
			header: map[string]any{
				"alg": "RS256",
				"jku": "https://example.com/jwks.json",
				"jwk": map[string]any{
					"kty": "RSA",
					"e":   "AQAB",
				},
			},
			critical: []any{},
		},
		"nil critical slice": {
			header: map[string]any{
				"alg": "RS256",
				"jku": "https://example.com/jwks.json",
				"jwk": map[string]any{
					"kty": "RSA",
					"e":   "AQAB",
				},
			},
			critical: nil,
		},
		"single missing value": {
			header: map[string]any{
				"alg": "RS256",
				"jku": "https://example.com/jwks.json",
				"jwk": map[string]any{
					"kty": "RSA",
					"e":   "AQAB",
				},
				"foo": "bar",
			},
			critical: []any{"foo", "bin"},
			errMsg:   "the 'crit' array contains one or more values not included in the header",
			errTypes: []error{joseerror.MissingCriticalClaim},
		},
		"multiple missing values": {
			header: map[string]any{
				"alg": "RS256",
				"jku": "https://example.com/jwks.json",
				"jwk": map[string]any{
					"kty": "RSA",
					"e":   "AQAB",
				},
			},
			critical: []any{"foo", "bin"},
			errMsg:   "the 'crit' array contains one or more values not included in the header",
			errTypes: []error{joseerror.MissingCriticalClaim},
		},
	}

	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			err := ValidateCriticalValuesPresent(test.header, test.critical)
			validateTestError(t, err, test.errMsg, test.errTypes)
		})
	}
}

func Test_DecodeBase64Map(t *testing.T) {
	tests := map[string]struct {
		input  string
		output map[string]any
		errMsg string
	}{
		"happy path": {
			input: base64.RawURLEncoding.EncodeToString([]byte(`{"foo":"bar"}`)),
			output: map[string]any{
				"foo": "bar",
			},
		},
		"empty string": {
			input:  "",
			errMsg: "unexpected end of JSON input",
		},
		"invalid base64url": {
			input:  "oogabooga",
			errMsg: "illegal base64 data at input byte 6",
		},
	}

	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			output, err := DecodeBase64urlMap(test.input)
			if test.errMsg != "" {
				if err == nil {
					t.Errorf("expected error %q, got none", test.errMsg)
				}
				if output != nil {
					t.Errorf("expected no output, got %v", output)
				}
			} else {
				if err != nil {
					t.Fatalf("expected no error, got %q", err.Error())
				}
				if !reflect.DeepEqual(test.output, output) {
					t.Errorf("expected %v, got %v", test.output, output)
				}
			}
		})
	}
}

func validateTestError(t *testing.T, producedError error, expectedMsg string, expectedTypes []error) {
	if producedError != nil {
		if expectedMsg == "" {
			t.Fatalf("unexpected error: %v", producedError)
		}
		if expectedMsg != producedError.Error() {
			t.Fatalf("expected error text %s, got %s", expectedMsg, producedError.Error())
		}
		for _, errType := range expectedTypes {
			if !errors.Is(producedError, errType) {
				t.Fatalf("thrown error does not have all types expected")
			}
		}
	} else {
		if expectedMsg != "" {
			t.Fatalf("expected error %s, got nil", expectedMsg)
		}
	}
}
