package jsonutils

import (
	"errors"
	"strings"
	"testing"

	"github.com/MichaelFraser99/go-jose/joseerror"
)

var notURICharacters = map[string]string{
	"a trailing space":              "https://issuer.example/jwks.json ",
	"a space in the path":           "https://issuer.example/jw ks.json",
	"a tab":                         "https://issuer.example/jwks.json\t",
	"a no-break space":              "https://issuer.example/jwks.json\u00a0",
	"a line separator":              "https://issuer.example/\u2028jwks.json",
	"a Cyrillic letter in the host": "https://issu\u0435r.example/jwks.json",
	"a zero-width space":            "https://issuer.example\u200b/jwks.json",
	"raw unicode in the path":       "https://issuer.example/cl\u00e9s.json",
	"a double quote":                "https://issuer.example/\"jwks\".json",
	"a backslash":                   "https://issuer.example/jwks\\json",
	"angle brackets":                "https://issuer.example/<jwks>.json",
	"a caret":                       "https://issuer.example/jwks^json",
	"a backtick":                    "https://issuer.example/`jwks`",
	"braces":                        "https://issuer.example/{jwks}",
	"a pipe":                        "https://issuer.example/jwks|json",
	"a DEL in the query":            "https://issuer.example/jwks?v=\x7f",
}

var malformedPercentEncodings = map[string]string{
	"a bare percent in the query":         "https://issuer.example/jwks?v=%",
	"a percent with one digit":            "https://issuer.example/jwks?v=%4",
	"a percent with non-hex digits":       "https://issuer.example/jwks?v=%zz",
	"a percent followed by one hex digit": "https://issuer.example/jwks?v=%4g",
	"a malformed escape in the fragment":  "https://issuer.example/jwks#%g0",
}

func TestValidateHttpsUrlClaim_AValueHoldingANonURICharacterIsRejected(t *testing.T) {
	for name, value := range notURICharacters {
		t.Run(name, func(t *testing.T) {
			if err := ValidateHttpsUrlClaim(nil, value); !errors.Is(err, joseerror.ErrMalformedClaim) {
				t.Errorf("[RFC 3986 2] a URI holds only ASCII unreserved and reserved characters and percent-encodings, so %q must be refused with ErrMalformedClaim, got %v", value, err)
			}
		})
	}
	for name, value := range malformedPercentEncodings {
		t.Run(name, func(t *testing.T) {
			if err := ValidateHttpsUrlClaim(nil, value); !errors.Is(err, joseerror.ErrMalformedClaim) {
				t.Errorf("[RFC 3986 2.1] a percent-encoding is %% followed by two hex digits, so %q must be refused with ErrMalformedClaim, got %v", value, err)
			}
		})
	}
}

func TestValidateHttpsUrlClaim_APercentEncodedFormIsAccepted(t *testing.T) {
	accepted := map[string]string{
		"an encoded trailing space":         "https://issuer.example/jwks.json%20",
		"an encoded tab":                    "https://issuer.example/jwks.json%09",
		"an encoded no-break space":         "https://issuer.example/jwks.json%C2%A0",
		"an encoded line separator":         "https://issuer.example/%E2%80%A8jwks.json",
		"an encoded Cyrillic host letter":   "https://issu%D0%B5r.example/jwks.json",
		"an encoded zero-width space":       "https://issuer.example/%E2%80%8Bjwks.json",
		"encoded unicode in the path":       "https://issuer.example/cl%C3%A9s.json",
		"lower-case hex digits":             "https://issuer.example/cl%c3%a9s.json",
		"every reserved and unreserved set": "https://user@issuer.example:443/a-b._~!$&'()*+,;=:@/c?d=/?#e/?",
		"an IPv6 literal":                   "https://[2001:db8::1]/jwks",
		"an encoded percent":                "https://issuer.example/100%25",
	}
	for name, value := range accepted {
		t.Run(name, func(t *testing.T) {
			if err := ValidateHttpsUrlClaim(nil, value); err != nil {
				t.Errorf("[RFC 3986 2.1] %q holds only URI characters and well-formed percent-encodings, so it must be accepted, got %v", value, err)
			}
		})
	}
}

func TestValidateHttpsUrlClaim_ANonURICharacterRefusalNamesTheClause(t *testing.T) {
	err := ValidateHttpsUrlClaim(nil, "https://issuer.example/jwks.json ")
	if err == nil || !strings.Contains(err.Error(), "RFC 3986 section 2") {
		t.Errorf("[RFC 3986 2] the refusal must name the clause it applies, got %v", err)
	}
	err = ValidateHttpsUrlClaim(nil, "https://issuer.example/jwks?v=%zz")
	if err == nil || !strings.Contains(err.Error(), "RFC 3986 section 2.1") {
		t.Errorf("[RFC 3986 2.1] the refusal must name the clause it applies, got %v", err)
	}
}
