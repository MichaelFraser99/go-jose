package jwk

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"testing"

	"github.com/MichaelFraser99/go-jose/joseerror"
)

func okpJwk(t *testing.T, crv any, withPrivate bool) map[string]any {
	t.Helper()
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	jwk := map[string]any{"kty": "OKP", "x": base64.RawURLEncoding.EncodeToString(public)}
	if crv != nil {
		jwk["crv"] = crv
	}
	if withPrivate {
		jwk["d"] = base64.RawURLEncoding.EncodeToString(private.Seed())
	}
	return jwk
}

func TestFromJwk_AnOKPKeyMustNameTheEd25519Subtype(t *testing.T) {
	tests := map[string]struct {
		crv       any
		reference string
		public    error
		private   error
	}{
		"Ed25519":           {crv: "Ed25519", reference: "RFC 8037 3.1"},
		"Ed448":             {crv: "Ed448", reference: "RFC 8037 3.1", public: joseerror.ErrUnsupportedAlgorithm, private: joseerror.ErrUnsupportedAlgorithm},
		"X25519":            {crv: "X25519", reference: "RFC 8037 3.2", public: joseerror.ErrUnsupportedAlgorithm, private: joseerror.ErrUnsupportedAlgorithm},
		"X448":              {crv: "X448", reference: "RFC 8037 3.2", public: joseerror.ErrUnsupportedAlgorithm, private: joseerror.ErrUnsupportedAlgorithm},
		"a lower case name": {crv: "ed25519", reference: "RFC 8037 2", public: joseerror.ErrUnsupportedAlgorithm, private: joseerror.ErrUnsupportedAlgorithm},
		"absent":            {crv: nil, reference: "RFC 8037 2", public: joseerror.ErrInvalidPublicKey, private: joseerror.ErrInvalidPrivateKey},
		"a number":          {crv: 25519, reference: "RFC 8037 2", public: joseerror.ErrInvalidPublicKey, private: joseerror.ErrInvalidPrivateKey},
		"an empty string":   {crv: "", reference: "RFC 8037 2", public: joseerror.ErrUnsupportedAlgorithm, private: joseerror.ErrUnsupportedAlgorithm},
	}

	for name, test := range tests {
		t.Run(name+", public", func(t *testing.T) {
			key, err := PublicFromJwk(okpJwk(t, test.crv, false))
			if test.public == nil {
				if err != nil {
					t.Fatalf("[%s] an Ed25519 key must be read, got %v", test.reference, err)
				}
				return
			}
			if !errors.Is(err, test.public) {
				t.Errorf("[%s] crv %v must be refused with %v, got %v", test.reference, test.crv, test.public, err)
			}
			if key != nil {
				t.Error("no key may be returned alongside the refusal")
			}
		})
		t.Run(name+", private", func(t *testing.T) {
			key, err := PrivateFromJwk(okpJwk(t, test.crv, true))
			if test.private == nil {
				if err != nil {
					t.Fatalf("[%s] an Ed25519 key must be read, got %v", test.reference, err)
				}
				return
			}
			if !errors.Is(err, test.private) {
				t.Errorf("[%s] crv %v must be refused with %v, got %v", test.reference, test.crv, test.private, err)
			}
			if key != nil {
				t.Error("no key may be returned alongside the refusal")
			}
		})
	}
}

func TestPrivateFromJwk_RefusesAnXThatIsNotThePublicKeyOfD(t *testing.T) {
	_, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	otherPublic, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	jwk := map[string]any{
		"kty": "OKP",
		"crv": "Ed25519",
		"d":   base64.RawURLEncoding.EncodeToString(private.Seed()),
		"x":   base64.RawURLEncoding.EncodeToString(otherPublic),
	}

	key, err := PrivateFromJwk(jwk)
	if err == nil {
		t.Fatalf("[RFC 8037 2] 'x' is the public key of the pair, so an 'x' belonging to a different key must be refused, got %T", key)
	}
	if !errors.Is(err, joseerror.ErrInvalidPrivateKey) {
		t.Errorf("[RFC 8037 2] the refusal must carry the private key error class, got %v", err)
	}
	if key != nil {
		t.Error("no key may be returned alongside the refusal")
	}
}
