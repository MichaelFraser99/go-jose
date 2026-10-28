package jwk

import (
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"testing"

	"github.com/MichaelFraser99/go-jose/joseerror"
)

func TestPublicJwk_RefusesAnEd25519KeyOfTheWrongLength(t *testing.T) {
	conforming, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	tests := map[string]struct {
		key    ed25519.PublicKey
		accept bool
	}{
		"exactly 32 bytes": {key: conforming, accept: true},
		"empty":            {key: ed25519.PublicKey{}},
		"one byte":         {key: make(ed25519.PublicKey, 1)},
		"one byte short":   {key: make(ed25519.PublicKey, ed25519.PublicKeySize-1)},
		"one byte over":    {key: make(ed25519.PublicKey, ed25519.PublicKeySize+1)},
		"double":           {key: make(ed25519.PublicKey, ed25519.PublicKeySize*2)},
	}

	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			key := test.key
			built, err := PublicJwk(&key)
			if test.accept {
				if err != nil {
					t.Fatalf("[RFC 8037 2] a 32 byte Ed25519 key must be accepted, got %v", err)
				}
				return
			}
			if err == nil {
				t.Fatalf("[RFC 8037 2] 'x' is 32 octets, so a %d byte key must be refused, got %v", len(test.key), *built)
			}
			if !errors.Is(err, joseerror.ErrInvalidPublicKey) {
				t.Errorf("[RFC 8037 2] the refusal must carry the key error class, got %v", err)
			}
			if built != nil {
				t.Error("no jwk may be returned alongside the refusal")
			}
		})
	}
}

func TestPrivateJwk_RefusesAnEd25519KeyOfTheWrongLength(t *testing.T) {
	_, conforming, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	tests := map[string]struct {
		key    ed25519.PrivateKey
		accept bool
	}{
		"exactly 64 bytes":    {key: conforming, accept: true},
		"empty":               {key: ed25519.PrivateKey{}},
		"a 32 byte seed only": {key: make(ed25519.PrivateKey, ed25519.SeedSize)},
		"one byte short":      {key: make(ed25519.PrivateKey, ed25519.PrivateKeySize-1)},
		"one byte over":       {key: make(ed25519.PrivateKey, ed25519.PrivateKeySize+1)},
	}

	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			key := test.key
			built, err := PrivateJwk(&key)
			if test.accept {
				if err != nil {
					t.Fatalf("[RFC 8037 2] a 64 byte Ed25519 private key must be accepted, got %v", err)
				}
				return
			}
			if err == nil {
				t.Fatalf("[RFC 8037 2] a %d byte private key must be refused, got %v", len(test.key), *built)
			}
			if !errors.Is(err, joseerror.ErrInvalidPrivateKey) {
				t.Errorf("[RFC 8037 2] the refusal must carry the key error class, got %v", err)
			}
			if built != nil {
				t.Error("no jwk may be returned alongside the refusal")
			}
		})
	}
}

func TestPrivateJwk_DistinctMalformedKeysDoNotShareAnIdentifier(t *testing.T) {
	seen := map[string]bool{}
	for i := 0; i < 3; i++ {
		seed := make([]byte, ed25519.SeedSize)
		if _, err := rand.Read(seed); err != nil {
			t.Fatal(err)
		}
		key := ed25519.PrivateKey(seed)
		built, err := PrivateJwk(&key)
		if err == nil {
			kid, _ := (*built)["kid"].(string)
			if seen[kid] {
				t.Fatalf("[RFC 8037 2] two distinct keys were given the same kid %q, so a key set cannot tell them apart", kid)
			}
			seen[kid] = true
		}
	}
}
