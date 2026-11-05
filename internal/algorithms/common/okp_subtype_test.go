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
