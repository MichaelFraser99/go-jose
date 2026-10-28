package jwk

import (
	"encoding/base64"
	"errors"
	"fmt"
	"maps"
	"testing"

	"github.com/MichaelFraser99/go-jose/joseerror"
)

func withLeadingZeroOctets(t *testing.T, jwk map[string]any, member string, zeros int) map[string]any {
	t.Helper()
	value, err := base64.RawURLEncoding.DecodeString(jwk[member].(string))
	if err != nil {
		t.Fatal(err)
	}
	altered := maps.Clone(jwk)
	altered[member] = base64.RawURLEncoding.EncodeToString(append(make([]byte, zeros), value...))
	return altered
}

func TestRSAJwk_ABase64urlUIntWithALeadingZeroOctetIsRefused(t *testing.T) {
	example := rfc7517ExampleRSAKey()
	if _, err := PrivateFromJwk(example); err != nil {
		t.Fatalf("[RFC 7517 A.2] the example key must be read as published, got %v", err)
	}

	for _, member := range []string{"n", "e", "d", "p", "q", "dp", "dq", "qi"} {
		for _, zeros := range []int{1, 2} {
			altered := withLeadingZeroOctets(t, example, member, zeros)
			t.Run(fmt.Sprintf("%s with %d leading zero octets", member, zeros), func(t *testing.T) {
				key, err := PrivateFromJwk(altered)
				if !errors.Is(err, joseerror.ErrMalformedClaim) || key != nil {
					t.Errorf("[RFC 7518 2] a Base64urlUInt MUST use the minimum number of octets, so '%s' with %d leading zero octets must be refused with ErrMalformedClaim, got %v", member, zeros, err)
				}
			})
		}
	}

	for name, e := range map[string]string{"3 in two octets": "AAM", "65537 in four octets": "AAEAAQ", "3 in three octets": "AAAD"} {
		t.Run("public e of "+name, func(t *testing.T) {
			key, err := PublicFromJwk(map[string]any{"kty": "RSA", "n": example["n"], "e": e})
			if !errors.Is(err, joseerror.ErrMalformedClaim) || key != nil {
				t.Errorf("[RFC 7518 2] e of %s is not in the minimum number of octets, so it must be refused with ErrMalformedClaim, got %v", name, err)
			}
		})
	}

	for _, member := range []string{"n", "e"} {
		altered := withLeadingZeroOctets(t, example, member, 1)
		delete(altered, "d")
		t.Run("public "+member, func(t *testing.T) {
			key, err := PublicFromJwk(altered)
			if !errors.Is(err, joseerror.ErrMalformedClaim) || key != nil {
				t.Errorf("[RFC 7518 2] '%s' with a leading zero octet must be refused with ErrMalformedClaim, got %v", member, err)
			}
		})
	}
}
