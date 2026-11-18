package jws

import (
	"errors"
	"testing"

	"github.com/MichaelFraser99/go-jose/joseerror"
	"github.com/MichaelFraser99/go-jose/jwa"
)

func TestGetValidatorFromJwk_EachRefusalCarriesTheDocumentedClass(t *testing.T) {
	for name, tt := range map[string]struct {
		alg    jwa.Algorithm
		jwk    map[string]any
		want   error
		clause string
	}{
		"an RSA jwk with no n":             {alg: jwa.RS256, jwk: map[string]any{"kty": "RSA", "e": "AQAB"}, want: joseerror.ErrInvalidPublicKey, clause: "RFC 7518 6.3.1"},
		"an RSA jwk with a non-minimal e":  {alg: jwa.RS256, jwk: map[string]any{"kty": "RSA", "n": "AQAB", "e": "AAEAAQ"}, want: joseerror.ErrInvalidPublicKey, clause: "RFC 7518 2"},
		"an OKP jwk with no x":             {alg: jwa.Ed25519, jwk: map[string]any{"kty": "OKP", "crv": "Ed25519"}, want: joseerror.ErrInvalidPublicKey, clause: "RFC 8037 2"},
		"a kid that is not a string":       {alg: jwa.Ed25519, jwk: map[string]any{"kty": "OKP", "crv": "Ed25519", "kid": 7}, want: joseerror.ErrInvalidPublicKey, clause: "RFC 7517 4.5"},
		"a kty this library does not read": {alg: jwa.ES256, jwk: map[string]any{"kty": "XYZ"}, want: joseerror.ErrUnsupportedAlgorithm, clause: "RFC 7517 4.1"},
		"a crv this library does not read": {alg: jwa.ES256, jwk: map[string]any{"kty": "EC", "crv": "secp256k1", "x": "AA", "y": "AA"}, want: joseerror.ErrUnsupportedAlgorithm, clause: "RFC 7518 6.2.1.1"},
		"a JWE alg":                        {alg: jwa.A128KW, jwk: map[string]any{"kty": "oct", "k": "AAAAAAAAAAAAAAAAAAAAAA"}, want: joseerror.ErrUnsupportedAlgorithm, clause: "RFC 7518 4.1"},
	} {
		t.Run(name, func(t *testing.T) {
			if validator, err := GetValidatorFromJwk(tt.alg, tt.jwk, nil); !errors.Is(err, tt.want) || validator != nil {
				t.Errorf("[%s] GetValidatorFromJwk's godoc gives %s %v, got %v", tt.clause, name, tt.want, err)
			}
		})
	}
}
