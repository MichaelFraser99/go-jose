package jws_test

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"errors"
	"maps"
	"testing"

	"github.com/MichaelFraser99/go-jose/joseerror"
	"github.com/MichaelFraser99/go-jose/jwa"
	"github.com/MichaelFraser99/go-jose/jwk"
	"github.com/MichaelFraser99/go-jose/jws"
	"github.com/MichaelFraser99/go-jose/model"
)

func TestVerify_RefusesAJwkHeaderThatHoldsAPrivateKeyMember(t *testing.T) {
	ecKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	_, edKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	keys := map[string]struct {
		alg jwa.Algorithm
		key crypto.Signer
	}{
		"EC":  {jwa.ES256, ecKey},
		"RSA": {jwa.RS256, rsaKey},
		"OKP": {jwa.Ed25519, edKey},
	}
	opts := &model.JoseOptions{UseTokenProvidedKeys: true}

	for kty, k := range keys {
		public, err := jwk.PublicJwk(k.key.Public())
		if err != nil {
			t.Fatal(err)
		}
		private, err := jwk.PrivateJwk(k.key)
		if err != nil {
			t.Fatal(err)
		}
		t.Run(kty+" public", func(t *testing.T) {
			token := signWithHeader(t, k.alg, k.key, map[string]any{"jwk": maps.Clone(*public)})
			if _, _, err := jws.Verify(context.Background(), token, nil, opts); err != nil {
				t.Fatalf("the public jwk of the signing key must verify the token, got %v", err)
			}
		})
		t.Run(kty+" private", func(t *testing.T) {
			token := signWithHeader(t, k.alg, k.key, map[string]any{"jwk": maps.Clone(*private)})
			if _, _, err := jws.Verify(context.Background(), token, nil, opts); !errors.Is(err, joseerror.ErrMalformedToken) {
				t.Errorf("[RFC 7515 4.1.3] the jwk header is the public key, so a %s private jwk whose public half verifies the token must be refused with ErrMalformedToken, got %v", kty, err)
			}
		})
		for _, member := range []string{"d", "p", "q", "dp", "dq", "qi", "oth", "k", "priv"} {
			t.Run(kty+" public with "+member, func(t *testing.T) {
				withMember := maps.Clone(*public)
				withMember[member] = "AQAB"
				token := signWithHeader(t, k.alg, k.key, map[string]any{"jwk": withMember})
				if _, _, err := jws.Verify(context.Background(), token, nil, opts); !errors.Is(err, joseerror.ErrMalformedToken) {
					t.Errorf("[RFC 7515 4.1.3] %q is a private key member, so a jwk header holding it must be refused with ErrMalformedToken, got %v", member, err)
				}
			})
		}
	}
}

func TestVerify_IgnoresAnEpkInAJWSHeader(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	epk := map[string]any{"kty": "OKP", "crv": "X25519", "x": "AQAB", "d": "AQAB"}
	token := signWithHeader(t, jwa.ES256, key, map[string]any{"epk": epk})
	retriever := func() ([]crypto.PublicKey, error) { return []crypto.PublicKey{key.Public()}, nil }
	if _, _, err := jws.Verify(context.Background(), token, retriever, nil); err != nil {
		t.Errorf("[RFC 7515 4.1, RFC 7518 4.6.1.1] epk is a JWE header parameter, so a JWS carrying one must still verify, got %v", err)
	}
}
