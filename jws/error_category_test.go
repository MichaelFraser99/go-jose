package jws_test

import (
	"context"
	"crypto"
	"encoding/base64"
	"encoding/json"
	"errors"
	"testing"

	"github.com/MichaelFraser99/go-jose/joseerror"
	"github.com/MichaelFraser99/go-jose/jwa"
	"github.com/MichaelFraser99/go-jose/jws"
	"github.com/MichaelFraser99/go-jose/model"
)

func tokenWithHeader(t *testing.T, header map[string]any) string {
	t.Helper()
	head, err := json.Marshal(header)
	if err != nil {
		t.Fatal(err)
	}
	return base64.RawURLEncoding.EncodeToString(head) + "." + base64.RawURLEncoding.EncodeToString([]byte(`{}`)) + ".AAAA"
}

func TestVerify_ErrMalformedTokenMarksOnlyAHeaderThatBreaksTheSpecification(t *testing.T) {
	signer, err := jws.GetSigner(jwa.ES256, nil)
	if err != nil {
		t.Fatal(err)
	}
	retriever := func() ([]crypto.PublicKey, error) { return []crypto.PublicKey{signer.Public()}, nil }
	tests := []struct {
		name      string
		header    map[string]any
		opts      *model.JoseOptions
		want      error
		malformed bool
		clause    string
	}{
		{name: "no alg", header: map[string]any{}, want: joseerror.ErrMissingClaim, malformed: true, clause: "RFC 7515 4.1.1"},
		{name: "an alg that is not a string", header: map[string]any{"alg": 7}, want: joseerror.ErrMalformedClaim, malformed: true, clause: "RFC 7515 4.1.1"},
		{name: "a kid that is not a string", header: map[string]any{"alg": "ES256", "kid": 7}, want: joseerror.ErrMalformedClaim, malformed: true, clause: "RFC 7515 4.1.4"},
		{name: "a jku that is not https", header: map[string]any{"alg": "ES256", "jku": "http://example.com"}, want: joseerror.ErrMalformedClaim, malformed: true, clause: "RFC 7515 4.1.2"},
		{name: "an empty crit", header: map[string]any{"alg": "ES256", "crit": []any{}}, want: joseerror.ErrMalformedClaim, malformed: true, clause: "RFC 7515 4.1.11"},
		{name: "a crit naming an absent parameter", header: map[string]any{"alg": "ES256", "crit": []any{"exp"}}, opts: &model.JoseOptions{UnderstoodCriticalHeaders: []string{"exp"}}, want: joseerror.ErrMissingCriticalClaim, malformed: true, clause: "RFC 7515 4.1.11"},
		{name: "a kid that is not a string with an alg outside the allow-list", header: map[string]any{"alg": "ES256", "kid": 7}, opts: &model.JoseOptions{AllowedSigningAlgorithms: []jwa.Algorithm{jwa.RS256}}, want: joseerror.ErrMalformedClaim, malformed: true, clause: "RFC 7515 4.1.4"},
		{name: "a kid that is not a string with a JWE alg, which has no validator", header: map[string]any{"alg": "dir", "kid": 5}, want: joseerror.ErrMalformedClaim, malformed: true, clause: "RFC 7515 4.1.4"},
		{name: "a jku that is not https with a JWE alg", header: map[string]any{"alg": "RSA-OAEP", "jku": "http://x"}, want: joseerror.ErrMalformedClaim, malformed: true, clause: "RFC 7515 4.1.2"},
		{name: "a b64 that is not a boolean", header: map[string]any{"alg": "ES256", "b64": "no", "crit": []any{"b64"}}, want: joseerror.ErrMalformedClaim, malformed: true, clause: "RFC 7797 3"},

		{name: "an alg this library does not know", header: map[string]any{"alg": "foobar"}, want: joseerror.ErrUnsupportedAlgorithm, clause: "RFC 7515 5.2"},
		{name: "a JWE alg, which has no validator", header: map[string]any{"alg": "RSA-OAEP"}, want: joseerror.ErrUnsupportedAlgorithm, clause: "RFC 7515 5.2"},
		{name: "an alg outside the allow-list", header: map[string]any{"alg": "ES256"}, opts: &model.JoseOptions{AllowedSigningAlgorithms: []jwa.Algorithm{jwa.RS256}}, want: joseerror.ErrUnsupportedAlgorithm, clause: "RFC 8725 3.1"},
		{name: "a typ outside AcceptedTypes", header: map[string]any{"alg": "ES256", "typ": "JWT"}, opts: &model.JoseOptions{AcceptedTypes: []string{"secevent+jwt"}}, want: joseerror.ErrMalformedClaim, clause: "RFC 8725 3.11"},
		{name: "no typ when AcceptedTypes is set", header: map[string]any{"alg": "ES256"}, opts: &model.JoseOptions{AcceptedTypes: []string{"secevent+jwt"}}, want: joseerror.ErrMissingClaim, clause: "RFC 8725 3.11"},
		{name: "no kid when one is required", header: map[string]any{"alg": "ES256"}, opts: &model.JoseOptions{RequireKeyIdentifier: true}, want: joseerror.ErrMissingClaim, clause: "RFC 7515 4.1.4"},
		{name: "an empty kid when one is required", header: map[string]any{"alg": "ES256", "kid": ""}, opts: &model.JoseOptions{RequireKeyIdentifier: true}, want: joseerror.ErrMalformedClaim, clause: "RFC 7515 4.1.4"},
		{name: "a crit naming an extension not understood", header: map[string]any{"alg": "ES256", "exp": 1, "crit": []any{"exp"}}, want: joseerror.ErrMissingCriticalClaim, clause: "RFC 7515 4.1.11"},
		{name: "a b64 of false", header: map[string]any{"alg": "ES256", "b64": false, "crit": []any{"b64"}}, opts: &model.JoseOptions{UnderstoodCriticalHeaders: []string{"b64"}}, want: joseerror.ErrMissingCriticalClaim, clause: "RFC 7797 3"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, payload, err := jws.Verify(context.Background(), tokenWithHeader(t, tt.header), retriever, tt.opts)
			if !errors.Is(err, tt.want) || payload != nil {
				t.Fatalf("[%s] want %v, got %v", tt.clause, tt.want, err)
			}
			if errors.Is(err, joseerror.ErrMalformedToken) != tt.malformed {
				t.Errorf("[%s] ErrMalformedToken marks a header that breaks the specification and nothing else; want it %v, got %v", tt.clause, tt.malformed, err)
			}
		})
	}
}
