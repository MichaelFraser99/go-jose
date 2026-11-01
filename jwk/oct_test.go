package jwk

import (
	"bytes"
	"encoding/base64"
	"errors"
	"reflect"
	"strings"
	"testing"

	"github.com/MichaelFraser99/go-jose/internal/algorithms/common"
	"github.com/MichaelFraser99/go-jose/joseerror"
)

const rfc7517A3K = "GawgguFyGrWKav7AX4VKUg"

func TestPrivateFromJwk_AnOctJwkIsTheKeyValueOfK(t *testing.T) {
	want, err := base64.RawURLEncoding.Strict().DecodeString(rfc7517A3K)
	if err != nil {
		t.Fatal(err)
	}
	key, err := PrivateFromJwk(map[string]any{"kty": "oct", "alg": "A128KW", "k": rfc7517A3K})
	if err != nil {
		t.Fatalf("[RFC 7517 A.3] the published symmetric key must be read, got %v", err)
	}
	got, ok := key.([]byte)
	if !ok {
		t.Fatalf("[RFC 7518 6.4.1] an oct key is read as a []byte, got %T", key)
	}
	if !bytes.Equal(got, want) {
		t.Errorf("[RFC 7518 6.4.1] k is the base64url encoding of the key value, want %x, got %x", want, got)
	}
}

func TestPrivateFromJwk_RefusesAMalformedOctJwk(t *testing.T) {
	tests := map[string]map[string]any{
		"no k":                            {"kty": "oct"},
		"a k that is a number":            {"kty": "oct", "k": 16},
		"a k that is null":                {"kty": "oct", "k": nil},
		"a k that is an array":            {"kty": "oct", "k": []any{rfc7517A3K}},
		"a k that is an object":           {"kty": "oct", "k": map[string]any{"k": rfc7517A3K}},
		"an empty k":                      {"kty": "oct", "k": ""},
		"a padded k":                      {"kty": "oct", "k": rfc7517A3K + "=="},
		"a k holding a plus":              {"kty": "oct", "k": "+" + rfc7517A3K[1:]},
		"a k holding a slash":             {"kty": "oct", "k": "/" + rfc7517A3K[1:]},
		"a k holding a space":             {"kty": "oct", "k": rfc7517A3K[:11] + " " + rfc7517A3K[11:]},
		"a k of impossible length":        {"kty": "oct", "k": rfc7517A3K[:21]},
		"a k with non-zero trailing bits": {"kty": "oct", "k": rfc7517A3K[:21] + "h"},
	}
	for name, jwk := range tests {
		t.Run(name, func(t *testing.T) {
			defer func() {
				if r := recover(); r != nil {
					t.Fatalf("[RFC 7518 6.4.1] %s must be refused, not panic: %v", name, r)
				}
			}()
			key, err := PrivateFromJwk(jwk)
			if !errors.Is(err, joseerror.ErrInvalidPrivateKey) {
				t.Errorf("[RFC 7518 6.4.1] %s is not a symmetric key, want ErrInvalidPrivateKey, got %v", name, err)
			}
			if key != nil {
				t.Errorf("[RFC 7518 6.4.1] no key may be returned alongside the refusal, got %#v", key)
			}
		})
	}
}

func TestPrivateJwk_ASymmetricKeyIsAnOctJwkWithNoKid(t *testing.T) {
	secret := []byte{0x19, 0xac, 0x20, 0x82, 0xe1, 0x72, 0x1a, 0xb5, 0x8a, 0x6a, 0xfe, 0xc0, 0x5f, 0x85, 0x4a, 0x52}
	want := map[string]any{"kty": "oct", "k": rfc7517A3K}
	for name, key := range map[string]any{"a []byte": secret, "a common.SecretKey": common.SecretKey(secret)} {
		t.Run(name, func(t *testing.T) {
			got, err := PrivateJwk(key)
			if err != nil {
				t.Fatalf("[RFC 7518 6.4] a symmetric key must produce an oct jwk, got %v", err)
			}
			if !reflect.DeepEqual(*got, want) {
				t.Errorf("[RFC 7518 6.4] want %v, got %v; a kid would publish the key's hash, which RFC 7638 7 says to conceal", want, *got)
			}
			back, err := PrivateFromJwk(*got)
			if err != nil || !bytes.Equal(back.([]byte), secret) {
				t.Errorf("[RFC 7518 6.4.1] the produced jwk must read back as the key, got %v and %v", back, err)
			}
		})
	}
}

func TestPrivateJwk_RefusesASymmetricKeyOfNoOctets(t *testing.T) {
	for name, key := range map[string]any{"a nil []byte": []byte(nil), "an empty []byte": []byte{}, "an empty common.SecretKey": common.SecretKey{}} {
		t.Run(name, func(t *testing.T) {
			got, err := PrivateJwk(key)
			if !errors.Is(err, joseerror.ErrInvalidPrivateKey) || got != nil {
				t.Errorf("[RFC 7518 6.4.1] a key of no octets has no k, want ErrInvalidPrivateKey and no jwk, got %v and %v", err, got)
			}
		})
	}
}

func TestPublicFromJwkAndPublicJwk_RefuseASymmetricKey(t *testing.T) {
	key, err := PublicFromJwk(map[string]any{"kty": "oct", "k": rfc7517A3K})
	if !errors.Is(err, joseerror.ErrInvalidPublicKey) || key != nil {
		t.Errorf("[RFC 7518 6.4] a symmetric key has no public half, want ErrInvalidPublicKey and no key, got %v and %#v", err, key)
	}
	if err != nil && (!strings.Contains(err.Error(), "symmetric") || strings.Contains(err.Error(), rfc7517A3K)) {
		t.Errorf("[RFC 7518 6.4] the refusal must name the symmetric key and not echo k, got %q", err)
	}

	secret := []byte(strings.Repeat("s", 32))
	for name, k := range map[string]any{"a []byte": secret, "a common.SecretKey": common.SecretKey(secret)} {
		t.Run(name, func(t *testing.T) {
			got, err := PublicJwk(k)
			if !errors.Is(err, joseerror.ErrInvalidPublicKey) || got != nil {
				t.Errorf("[RFC 7518 6.4] a symmetric key has no public jwk, want ErrInvalidPublicKey and no jwk, got %v and %v", err, got)
			}
			if err != nil && !strings.Contains(err.Error(), "symmetric") {
				t.Errorf("[RFC 7518 6.4] the refusal must name the symmetric key, got %q", err)
			}
		})
	}
}
