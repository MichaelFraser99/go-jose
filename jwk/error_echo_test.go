package jwk

import (
	"errors"
	"strings"
	"testing"

	"github.com/MichaelFraser99/go-jose/joseerror"
)

func TestFromJwk_AnUnsupportedKtyOrCrvIsNotEchoedIntoTheError(t *testing.T) {
	payload := "\r\nX-Injected: 1\r\n" + strings.Repeat("A", 4096)
	readers := map[string]func(map[string]any) (any, error){
		"PublicFromJwk":  func(j map[string]any) (any, error) { return PublicFromJwk(j) },
		"PrivateFromJwk": func(j map[string]any) (any, error) { return PrivateFromJwk(j) },
	}
	jwks := map[string]map[string]any{
		"kty": {"kty": payload},
		"crv": {"kty": "EC", "crv": payload, "x": "AA", "y": "AA", "d": "AA"},
	}

	for readerName, read := range readers {
		for member, jwk := range jwks {
			t.Run(readerName+" "+member, func(t *testing.T) {
				_, err := read(jwk)
				if err == nil {
					t.Fatalf("[RFC 7517 5] a %s this library does not understand must be refused", member)
				}
				if !errors.Is(err, joseerror.ErrUnsupportedAlgorithm) {
					t.Errorf("[RFC 7517 5] the refusal must carry the unsupported algorithm class, got %v", err)
				}
				if strings.ContainsAny(err.Error(), "\r\n") || strings.Contains(err.Error(), strings.Repeat("A", 65)) {
					t.Errorf("[robustness] the error carries the peer's raw %s: %d bytes, raw CR LF %v", member, len(err.Error()), strings.ContainsAny(err.Error(), "\r\n"))
				}
			})
		}
	}
}
