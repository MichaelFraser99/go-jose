package jwk

import (
	"crypto"
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"errors"
	"maps"
	"testing"

	"github.com/MichaelFraser99/go-jose/joseerror"
)

func TestPrivateFromJwk_AJwkWithoutItsPrivateMemberIsAnInvalidPrivateKey(t *testing.T) {
	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	ecKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	_, edKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	xKey, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	privateJwkOf := func(key crypto.PrivateKey) map[string]any {
		written, err := PrivateJwk(key)
		if err != nil {
			t.Fatal(err)
		}
		return *written
	}
	replacing := func(jwk map[string]any, name string, value any) map[string]any {
		changed := maps.Clone(jwk)
		if value == nil {
			delete(changed, name)
		} else {
			changed[name] = value
		}
		return changed
	}
	rsaJwk, ecJwk, edJwk, xJwk := privateJwkOf(rsaKey), privateJwkOf(ecKey), privateJwkOf(edKey), privateJwkOf(xKey)

	tests := map[string]struct {
		jwk    map[string]any
		also   error
		clause string
	}{
		"an RSA jwk without d":                   {jwk: replacing(rsaJwk, "d", nil), also: joseerror.ErrMissingClaim, clause: "RFC 7518 6.3.2.1"},
		"an RSA jwk whose d is 7":                {jwk: replacing(rsaJwk, "d", 7), also: joseerror.ErrMalformedClaim, clause: "RFC 7518 6.3.2.1"},
		"an RSA jwk whose d is empty":            {jwk: replacing(rsaJwk, "d", ""), also: joseerror.ErrMalformedClaim, clause: "RFC 7518 2"},
		"an Ed25519 jwk without d":               {jwk: replacing(edJwk, "d", nil), also: joseerror.ErrMissingClaim, clause: "RFC 8037 2"},
		"an Ed25519 jwk whose d is 7":            {jwk: replacing(edJwk, "d", 7), also: joseerror.ErrMalformedClaim, clause: "RFC 8037 2"},
		"an X25519 jwk without d":                {jwk: replacing(xJwk, "d", nil), also: joseerror.ErrMissingClaim, clause: "RFC 8037 2"},
		"an X25519 jwk whose d is not base64url": {jwk: replacing(xJwk, "d", "!!"), also: joseerror.ErrMalformedClaim, clause: "RFC 8037 2"},
		"an EC jwk without d":                    {jwk: replacing(ecJwk, "d", nil), clause: "RFC 7518 6.2.2.1"},
		"an oct jwk without k":                   {jwk: map[string]any{"kty": "oct"}, clause: "RFC 7518 6.4.1"},
	}
	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			key, err := PrivateFromJwk(tc.jwk)
			if !errors.Is(err, joseerror.ErrInvalidPrivateKey) {
				t.Errorf("[%s] %s holds no private key, so it must be refused with ErrInvalidPrivateKey, got %v", tc.clause, name, err)
			}
			if tc.also != nil && !errors.Is(err, tc.also) {
				t.Errorf("[%s] the refusal must still carry %v, got %v", tc.clause, tc.also, err)
			}
			if key != nil {
				t.Errorf("[%s] no key may be returned alongside the refusal, got %T", tc.clause, key)
			}
		})
	}
}
