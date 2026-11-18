package jws_test

import (
	"context"
	"errors"
	"net/http"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/MichaelFraser99/go-jose/joseerror"
	"github.com/MichaelFraser99/go-jose/jws"
	"github.com/MichaelFraser99/go-jose/model"
)

func TestVerifyCompactSerialization_AJkuOrX5uHoldingANonURICharacterIsMalformed(t *testing.T) {
	keys := newRemoteKeys(t)
	values := map[string]string{
		"a trailing space":              "https://issuer.example/jwks.json ",
		"a tab":                         "https://issuer.example/jwks.json\t",
		"a no-break space":              "https://issuer.example/jwks.json\u00a0",
		"a line separator":              "https://issuer.example/\u2028jwks.json",
		"a Cyrillic letter in the host": "https://issu\u0435r.example/jwks.json",
		"a zero-width space":            "https://issuer.example\u200b/jwks.json",
		"raw unicode in the path":       "https://issuer.example/cl\u00e9s.json",
		"a malformed percent-encoding":  "https://issuer.example/jwks?v=%zz",
	}
	for _, source := range []string{"jku", "x5u"} {
		for name, value := range values {
			t.Run(source+" "+name, func(t *testing.T) {
				transport := &recordingTransport{}
				opts := &model.JoseOptions{UseTokenProvidedKeys: true, X509Roots: roots(keys.root), HttpClient: &http.Client{Transport: transport}}
				token := es256Token(t, keys.signingKey, map[string]any{source: value})
				_, _, err := jws.VerifyCompactSerialization(context.Background(), token, retrieving(&keys.signingKey.PublicKey), opts)
				if !errors.Is(err, joseerror.ErrMalformedToken) || !errors.Is(err, joseerror.ErrMalformedClaim) {
					t.Errorf("[RFC 3986 2] a %s is a URI, and %q holds a character no URI holds, so the token must be refused with ErrMalformedToken and ErrMalformedClaim, got %v", source, value, err)
				}
				if got := transport.requests(); len(got) != 0 {
					t.Errorf("[RFC 3986 2] a malformed %s must not be fetched, got %q", source, got)
				}

				if err := jws.CheckOptions(&model.JoseOptions{AllowedKeyURLs: []string{value}}); !errors.Is(err, joseerror.ErrInvalidOptions) {
					t.Errorf("[RFC 3986 2] no %s can equal %q, so as an AllowedKeyURLs entry it must be refused with ErrInvalidOptions, got %v", source, value, err)
				}
			})
		}
	}

	encoded := "https://issuer.example/cl%C3%A9s.json%20"
	transport := &recordingTransport{}
	opts := &model.JoseOptions{UseTokenProvidedKeys: true, HttpClient: &http.Client{Transport: transport}, AllowedKeyURLs: []string{encoded}}
	token := es256Token(t, keys.signingKey, map[string]any{"jku": encoded})
	_, _, _ = jws.VerifyCompactSerialization(context.Background(), token, nil, opts)
	if got := transport.requests(); len(got) != 1 {
		t.Errorf("[RFC 3986 2.1] the percent-encoded form holds only URI characters, so a listed jku of it must be fetched, got %q", got)
	}
}

func TestVerifyCompactSerialization_AllowedKeyURLsComparesARedirectHopAsTheRequestSent(t *testing.T) {
	keys := newRemoteKeys(t)
	tests := map[string]struct {
		location func(targetURL string) string
		listed   func(targetURL string) string
	}{
		"a hop with a fragment, against an entry without one": {
			location: func(target string) string { return target + "/jwks#keys" },
			listed:   func(target string) string { return target + "/jwks" },
		},
		"a hop without a fragment, against an entry with one": {
			location: func(target string) string { return target + "/jwks" },
			listed:   func(target string) string { return target + "/jwks#keys" },
		},
		"a hop whose dot-segments the client removes": {
			location: func(target string) string { return target + "/x/../jwks" },
			listed:   func(target string) string { return target + "/jwks" },
		},
		"a hop whose scheme is upper case": {
			location: func(target string) string { return "HTTPS" + strings.TrimPrefix(target, "https") + "/jwks" },
			listed:   func(target string) string { return target + "/jwks" },
		},
	}
	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			var targetHits atomic.Int64
			target := countingBody(t, &targetHits, keys.jwks)
			start := serving(t, func(w http.ResponseWriter, r *http.Request) {
				http.Redirect(w, r, tc.location(target.URL), http.StatusFound)
			})
			token := es256Token(t, keys.signingKey, map[string]any{"jku": start.URL})
			opts := &model.JoseOptions{UseTokenProvidedKeys: true, HttpClient: start.Client(), AllowedKeyURLs: []string{start.URL, tc.listed(target.URL)}}

			if _, _, err := jws.VerifyCompactSerialization(context.Background(), token, nil, opts); err != nil {
				t.Errorf("[RFC 3986 3.5, 5.2.4] the hop sends the request the listed entry %q makes, so it must be followed and the token verify, got %v", tc.listed(target.URL), err)
			}
			if got := targetHits.Load(); got != 1 {
				t.Errorf("[RFC 3986 3.5, 5.2.4] the hop must be sent once, got %d requests", got)
			}
		})
	}
}
