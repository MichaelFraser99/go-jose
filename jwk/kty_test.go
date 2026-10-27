package jwk

import (
	"errors"
	"testing"

	"github.com/MichaelFraser99/go-jose/joseerror"
)

func malformedKtyShapes() map[string]any {
	return map[string]any{
		"a number":         7,
		"a float":          7.5,
		"a boolean":        true,
		"null":             nil,
		"an object":        map[string]any{"kty": "EC"},
		"an array":         []any{"EC"},
		"an array of none": []any{},
	}
}

func TestFromJwk_AMalformedKtyIsRefusedNotPanicked(t *testing.T) {
	readers := map[string]func(map[string]any) (any, error){
		"PublicFromJwk": func(j map[string]any) (any, error) {
			key, err := PublicFromJwk(j)
			return key, err
		},
		"PrivateFromJwk": func(j map[string]any) (any, error) {
			key, err := PrivateFromJwk(j)
			return key, err
		},
	}

	for readerName, read := range readers {
		for shapeName, kty := range malformedKtyShapes() {
			t.Run(readerName+" with "+shapeName, func(t *testing.T) {
				defer func() {
					if r := recover(); r != nil {
						t.Fatalf("[RFC 7517 4.1] kty comes from a peer's key set, so a %s must be refused rather than panicking, got %v", shapeName, r)
					}
				}()

				key, err := read(map[string]any{"kty": kty, "crv": "P-256", "x": "AA", "y": "AA"})
				if err == nil {
					t.Fatalf("[RFC 7517 4.1] kty is a case-sensitive string, so a %s names no key type and must be refused, got %T", shapeName, key)
				}
				if !errors.Is(err, joseerror.ErrInvalidPublicKey) && !errors.Is(err, joseerror.ErrInvalidPrivateKey) && !errors.Is(err, joseerror.ErrUnsupportedAlgorithm) {
					t.Errorf("the refusal must carry a key or algorithm error class, got %v", err)
				}
			})
		}
	}
}

func TestFromJwk_AnEcKeyWithAMalformedCrvIsRefusedNotPanicked(t *testing.T) {
	shapes := map[string]any{
		"a number":  7,
		"a boolean": true,
		"null":      nil,
		"an object": map[string]any{},
		"an array":  []any{"P-256"},
	}

	readers := map[string]func(map[string]any) (any, error){
		"PublicFromJwk":  func(j map[string]any) (any, error) { return PublicFromJwk(j) },
		"PrivateFromJwk": func(j map[string]any) (any, error) { return PrivateFromJwk(j) },
	}

	for readerName, read := range readers {
		for shapeName, crv := range shapes {
			t.Run(readerName+" with "+shapeName, func(t *testing.T) {
				defer func() {
					if r := recover(); r != nil {
						t.Fatalf("[RFC 7518 6.2.1.1] crv comes from a peer's key set, so a %s must be refused rather than panicking, got %v", shapeName, r)
					}
				}()

				key, err := read(map[string]any{"kty": "EC", "crv": crv, "x": "AA", "y": "AA", "d": "AA"})
				if err == nil {
					t.Fatalf("[RFC 7518 6.2.1.1] crv is a string naming a registered curve, so a %s must be refused, got %T", shapeName, key)
				}
			})
		}
	}
}

func TestFromJwk_AnAbsentCrvOnAnEcKeyIsRefusedNotPanicked(t *testing.T) {
	readers := map[string]func(map[string]any) (any, error){
		"PublicFromJwk":  func(j map[string]any) (any, error) { return PublicFromJwk(j) },
		"PrivateFromJwk": func(j map[string]any) (any, error) { return PrivateFromJwk(j) },
	}

	for readerName, read := range readers {
		t.Run(readerName, func(t *testing.T) {
			defer func() {
				if r := recover(); r != nil {
					t.Fatalf("[RFC 7518 6.2.1.1] crv is REQUIRED for an EC key, so its absence must be refused rather than panicking, got %v", r)
				}
			}()

			key, err := read(map[string]any{"kty": "EC", "x": "AA", "y": "AA", "d": "AA"})
			if err == nil {
				t.Fatalf("an EC key with no crv must be refused, got %T", key)
			}
		})
	}
}
