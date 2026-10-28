package jwk

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"testing"

	"github.com/MichaelFraser99/go-jose/joseerror"
)

func ed25519Jwk(t *testing.T, xLen int, dLen int) map[string]any {
	t.Helper()
	jwk := map[string]any{"kty": "OKP", "crv": "Ed25519"}
	x := make([]byte, xLen)
	if _, err := rand.Read(x); err != nil {
		t.Fatal(err)
	}
	jwk["x"] = base64.RawURLEncoding.EncodeToString(x)
	if dLen >= 0 {
		d := make([]byte, dLen)
		if _, err := rand.Read(d); err != nil {
			t.Fatal(err)
		}
		jwk["d"] = base64.RawURLEncoding.EncodeToString(d)
		if dLen == ed25519.SeedSize && xLen == ed25519.PublicKeySize {
			jwk["x"] = base64.RawURLEncoding.EncodeToString(ed25519.NewKeyFromSeed(d)[ed25519.SeedSize:])
		}
	}
	return jwk
}

func TestPublicFromJwk_RefusesAnEd25519KeyOfTheWrongLength(t *testing.T) {
	tests := map[string]struct {
		x      int
		accept bool
	}{
		"exactly 32 bytes":       {x: ed25519.PublicKeySize, accept: true},
		"empty":                  {x: 0},
		"one byte":               {x: 1},
		"one byte short":         {x: ed25519.PublicKeySize - 1},
		"one byte over":          {x: ed25519.PublicKeySize + 1},
		"a private key's length": {x: ed25519.PrivateKeySize},
	}

	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			key, err := PublicFromJwk(ed25519Jwk(t, test.x, -1))
			if test.accept {
				if err != nil {
					t.Fatalf("[RFC 8037 2] a 32 byte 'x' must be accepted, got %v", err)
				}
				return
			}
			if err == nil {
				t.Fatalf("[RFC 8037 2] 'x' is 32 octets, so a %d byte key must be refused, got %T", test.x, key)
			}
			if !errors.Is(err, joseerror.ErrInvalidPublicKey) {
				t.Errorf("[RFC 8037 2] the refusal must carry the key error class, got %v", err)
			}
			if key != nil {
				t.Error("no key may be returned alongside the refusal")
			}
		})
	}
}

func TestPrivateFromJwk_RefusesAnEd25519KeyOfTheWrongLength(t *testing.T) {
	tests := map[string]struct {
		x, d   int
		accept bool
	}{
		"both exactly 32 bytes": {x: ed25519.PublicKeySize, d: ed25519.SeedSize, accept: true},
		"d empty":               {x: ed25519.PublicKeySize, d: 0},
		"d one byte short":      {x: ed25519.PublicKeySize, d: ed25519.SeedSize - 1},
		"d one byte over":       {x: ed25519.PublicKeySize, d: ed25519.SeedSize + 1},
		"d a full private key":  {x: ed25519.PublicKeySize, d: ed25519.PrivateKeySize},
		"x empty":               {x: 0, d: ed25519.SeedSize},
		"x one byte short":      {x: ed25519.PublicKeySize - 1, d: ed25519.SeedSize},
		"x one byte over":       {x: ed25519.PublicKeySize + 1, d: ed25519.SeedSize},
	}

	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			key, err := PrivateFromJwk(ed25519Jwk(t, test.x, test.d))
			if test.accept {
				if err != nil {
					t.Fatalf("[RFC 8037 2] a 32 byte 'x' and 'd' must be accepted, got %v", err)
				}
				return
			}
			if err == nil {
				t.Fatalf("[RFC 8037 2] 'x' and 'd' are 32 octets each, so x=%d d=%d must be refused, got %T", test.x, test.d, key)
			}
			if !errors.Is(err, joseerror.ErrInvalidPrivateKey) {
				t.Errorf("[RFC 8037 2] the refusal must carry the key error class, got %v", err)
			}
			if key != nil {
				t.Error("no key may be returned alongside the refusal")
			}
		})
	}
}

func TestPrivateFromJwk_ProducesAKeyTheStandardLibraryWillUse(t *testing.T) {
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	built, err := PrivateJwk(&private)
	if err != nil {
		t.Fatal(err)
	}

	read, err := PrivateFromJwk(*built)
	if err != nil {
		t.Fatalf("a jwk this library produced must read back: %v", err)
	}
	readKey, ok := read.(*ed25519.PrivateKey)
	if !ok {
		t.Fatalf("expected an *ed25519.PrivateKey, got %T", read)
	}

	signature := ed25519.Sign(*readKey, []byte("the signing input"))
	if !ed25519.Verify(public, []byte("the signing input"), signature) {
		t.Error("[RFC 8037 2] the key read back must sign so that the original public key verifies it")
	}
}

func TestFromJwk_AFailedReadReturnsNoKey(t *testing.T) {
	tests := map[string]map[string]any{
		"an EC jwk with no coordinates": {"kty": "EC", "crv": "P-256"},
		"an EC jwk with a malformed x":  {"kty": "EC", "crv": "P-256", "x": "!!!", "y": "!!!"},
		"an RSA jwk with no modulus":    {"kty": "RSA"},
		"an RSA jwk with a malformed n": {"kty": "RSA", "n": "!!!", "e": "AQAB"},
		"an OKP jwk with no crv":        {"kty": "OKP", "x": "AAAA"},
		"a jwk of an unsupported kty":   {"kty": "nonsense"},
		"a jwk with a non string kty":   {"kty": 7},
		"a jwk with no kty at all":      {"crv": "P-256"},
	}

	for name, body := range tests {
		t.Run(name+", public", func(t *testing.T) {
			key, err := PublicFromJwk(body)
			if err == nil {
				t.Fatalf("expected %s to be refused", name)
			}
			if key != nil {
				t.Errorf("a refused read must return a nil key, not an interface holding a typed nil: calling a method on it panics. Got %#v", key)
			}
		})
		t.Run(name+", private", func(t *testing.T) {
			key, err := PrivateFromJwk(body)
			if err == nil {
				t.Fatalf("expected %s to be refused", name)
			}
			if key != nil {
				t.Errorf("a refused read must return a nil key, not an interface holding a typed nil: calling a method on it panics. Got %#v", key)
			}
		})
	}
}
