package jsonutils

import (
	"errors"
	"strings"
	"testing"

	"github.com/MichaelFraser99/go-jose/joseerror"
)

func TestValidateHttpsUrlClaim_AnHttpsURLWithAnEmptyHostIsRejected(t *testing.T) {
	emptyHosts := map[string]string{
		"no authority after the scheme":    "https:",
		"an empty authority":               "https://",
		"an opaque reference":              "https:opaque",
		"an empty authority with a path":   "https:///path",
		"a port and no host":               "https://:443/",
		"userinfo and no host":             "https://user@/",
		"userinfo, a port and no host":     "https://user@:443/jwks",
		"an upper-case scheme and no host": "HTTPS:///jwks",
	}
	for name, value := range emptyHosts {
		t.Run(name, func(t *testing.T) {
			err := ValidateHttpsUrlClaim(nil, value)
			if !errors.Is(err, joseerror.ErrMalformedClaim) {
				t.Fatalf("[RFC 9110 4.2.2] a recipient MUST reject an https URI with an empty host identifier, so %q must be refused with ErrMalformedClaim, got %v", value, err)
			}
			if !strings.Contains(err.Error(), "RFC 9110 section 4.2.2") {
				t.Errorf("[RFC 9110 4.2.2] the refusal must name the clause it applies, got %v", err)
			}
		})
	}

	withHosts := map[string]string{
		"a registered name":           "https://keys.example/jwks",
		"a one-letter host":           "https://a",
		"an IPv4 literal":             "https://192.0.2.1/jwks",
		"an IPv6 literal":             "https://[2001:db8::1]/jwks",
		"a host and an explicit port": "https://keys.example:443/jwks",
		"a host and an empty port":    "https://keys.example:/jwks",
		"userinfo and a host":         "https://user@keys.example/jwks",
		"an upper-case scheme":        "HTTPS://keys.example/jwks",
		"a host with no path at all":  "https://keys.example",
		"a unicode registered name":   "https://kеys.example/jwks",
	}
	for name, value := range withHosts {
		t.Run(name, func(t *testing.T) {
			if err := ValidateHttpsUrlClaim(nil, value); err != nil {
				t.Errorf("[RFC 9110 4.2.2] %q names a host, so the empty-host rule must not refuse it, got %v", value, err)
			}
		})
	}
}
