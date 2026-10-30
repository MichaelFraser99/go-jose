package header

import (
	"encoding/base64"
	"errors"
	"testing"

	"github.com/MichaelFraser99/go-jose/joseerror"
	"github.com/MichaelFraser99/go-jose/model"
)

func TestReadHeaderShape_AJWECritMayNameNoParameterRFC7516OrRFC7518DefinesForJWE(t *testing.T) {
	certs, err := generateCertificateChainOnly(t, 1)
	if err != nil {
		t.Fatal(err)
	}
	present := map[string]any{
		"alg":      "dir",
		"enc":      "A128GCM",
		"zip":      "DEF",
		"jku":      "https://example.com/jwks",
		"jwk":      map[string]any{"kty": "oct"},
		"kid":      "k",
		"x5u":      "https://example.com/chain",
		"x5c":      []any{base64.StdEncoding.EncodeToString(certs[0])},
		"x5t":      "AAAA",
		"x5t#S256": "AAAA",
		"typ":      "JOSE",
		"cty":      "JWT",
		"epk":      map[string]any{"kty": "OKP"},
		"apu":      "AAAA",
		"apv":      "AAAA",
		"iv":       "AAAA",
		"tag":      "AAAA",
		"p2s":      "AAAAAAAAAAA",
		"p2c":      1000,
	}
	for _, name := range []string{"alg", "enc", "zip", "jku", "jwk", "kid", "x5u", "x5c", "x5t", "x5t#S256", "typ", "cty", "crit", "epk", "apu", "apv", "iv", "tag", "p2s", "p2c"} {
		t.Run(name, func(t *testing.T) {
			head := map[string]any{"crit": []any{name}}
			for member, value := range present {
				head[member] = value
			}
			if _, err := readHeaderShape(jsonDecodedHeader(t, head), model.JWE); !errors.Is(err, joseerror.ErrMalformedClaim) {
				t.Errorf("[RFC 7516 4.1.13 via RFC 7515 4.1.11] crit must not name %q in a JWE, want ErrMalformedClaim, got %v", name, err)
			}
			delete(head, "crit")
			if _, err := readHeaderShape(jsonDecodedHeader(t, head), model.JWE); err != nil {
				t.Fatalf("without crit the header must be well formed, got %v", err)
			}
		})
	}
}

func TestReadHeaderShape_AJWSCritMayStillNameAJWEOnlyParameter(t *testing.T) {
	for _, name := range []string{"enc", "zip", "epk", "apu", "apv", "iv", "tag", "p2s", "p2c"} {
		t.Run(name, func(t *testing.T) {
			head := map[string]any{"alg": "RS256", name: "AAAA", "crit": []any{name}}
			if _, err := readHeaderShape(jsonDecodedHeader(t, head), model.JWS); err != nil {
				t.Errorf("[RFC 7515 4.1.11] %q is not defined for JWS, so a JWS crit may name it, got %v", name, err)
			}
		})
	}
}
