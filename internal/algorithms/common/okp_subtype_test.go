package common

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"testing"

	jose_errors "github.com/MichaelFraser99/go-jose/joseerror"
)

func TestOKPReaders_RefuseAJwkOfTheOtherSubtype(t *testing.T) {
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	jwk := func(crv string) map[string]any {
		return map[string]any{
			"kty": "OKP",
			"crv": crv,
			"x":   base64.RawURLEncoding.EncodeToString(public),
			"d":   base64.RawURLEncoding.EncodeToString(private.Seed()),
		}
	}

	tests := map[string]func() (any, error){
		"an X25519 jwk read as an Ed25519 public key":  func() (any, error) { return EdDSAPublicKeyFromJwk(jwk("X25519")) },
		"an X25519 jwk read as an Ed25519 private key": func() (any, error) { return EdDSAPrivateKeyFromJwk(jwk("X25519")) },
		"an Ed25519 jwk read as an X25519 public key":  func() (any, error) { return X25519PublicKeyFromJwk(jwk("Ed25519")) },
		"an Ed25519 jwk read as an X25519 private key": func() (any, error) { return X25519PrivateKeyFromJwk(jwk("Ed25519")) },
	}
	for name, read := range tests {
		t.Run(name, func(t *testing.T) {
			key, err := read()
			if !errors.Is(err, jose_errors.ErrUnsupportedAlgorithm) {
				t.Errorf("[RFC 8037 3.1, 3.2] Ed25519 is for signing and X25519 for key agreement, so %s must be refused with ErrUnsupportedAlgorithm, got %v", name, err)
			}
			if !IsNil(key) {
				t.Errorf("[RFC 8037 3.2] no key may be returned alongside the refusal, got %#v", key)
			}
		})
	}
}

func TestOKPReaders_ARefusedEd25519JwkReturnsAnUntypedNilKey(t *testing.T) {
	short := base64.RawURLEncoding.EncodeToString(make([]byte, ed25519.PublicKeySize-1))
	jwk := map[string]any{"kty": "OKP", "crv": "Ed25519", "x": short, "d": short}

	tests := map[string]func() (any, error){
		"OKPPublicKeyFromJwk":  func() (any, error) { return OKPPublicKeyFromJwk(jwk) },
		"OKPPrivateKeyFromJwk": func() (any, error) { return OKPPrivateKeyFromJwk(jwk) },
	}
	for name, read := range tests {
		t.Run(name, func(t *testing.T) {
			key, err := read()
			if err == nil {
				t.Fatalf("[RFC 8032 5.1.5] a 31 octet key must be refused, got %T", key)
			}
			if key != nil {
				t.Errorf("a refused read must return a nil interface, not one holding a typed nil key, got %#v", key)
			}
		})
	}
}
