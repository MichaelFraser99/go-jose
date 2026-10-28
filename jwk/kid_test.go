package jwk

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"testing"
)

func keyPairs(t *testing.T) map[string]struct {
	public  crypto.PublicKey
	private crypto.PrivateKey
} {
	t.Helper()
	pairs := map[string]struct {
		public  crypto.PublicKey
		private crypto.PrivateKey
	}{}

	for name, curve := range map[string]elliptic.Curve{"EC P-256": elliptic.P256(), "EC P-384": elliptic.P384(), "EC P-521": elliptic.P521()} {
		key, err := ecdsa.GenerateKey(curve, rand.Reader)
		if err != nil {
			t.Fatalf("failed to generate %s: %v", name, err)
		}
		pairs[name] = struct {
			public  crypto.PublicKey
			private crypto.PrivateKey
		}{public: &key.PublicKey, private: key}
	}

	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("failed to generate RSA: %v", err)
	}
	pairs["RSA"] = struct {
		public  crypto.PublicKey
		private crypto.PrivateKey
	}{public: &rsaKey.PublicKey, private: rsaKey}

	edPub, edPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate Ed25519: %v", err)
	}
	pairs["Ed25519"] = struct {
		public  crypto.PublicKey
		private crypto.PrivateKey
	}{public: &edPub, private: &edPriv}

	return pairs
}

func TestJwk_EveryShapeCarriesAKeyIdentifier(t *testing.T) {
	for name, pair := range keyPairs(t) {
		t.Run(name+" public", func(t *testing.T) {
			built, err := PublicJwk(pair.public)
			if err != nil {
				t.Fatalf("failed to build the jwk: %v", err)
			}
			assertUsableKid(t, *built, name+" public")
		})

		t.Run(name+" private", func(t *testing.T) {
			built, err := PrivateJwk(pair.private)
			if err != nil {
				t.Fatalf("failed to build the jwk: %v", err)
			}
			assertUsableKid(t, *built, name+" private")
		})
	}
}

func assertUsableKid(t *testing.T, built map[string]any, shape string) {
	t.Helper()

	raw, present := built["kid"]
	if !present {
		t.Fatalf("[RFC 7517 4.5] a %s jwk this library publishes must carry a kid, or a consumer cannot select it from a key set by identifier", shape)
	}
	kid, ok := raw.(string)
	if !ok {
		t.Fatalf("[RFC 7517 4.5] a kid is a string, got %T for a %s jwk", raw, shape)
	}
	if kid == "" {
		t.Fatalf("[RFC 7517 4.5] a %s jwk carries an empty kid", shape)
	}
	if _, err := base64.RawURLEncoding.DecodeString(kid); err != nil {
		t.Errorf("the kid this library produces is a base64url digest, so it must decode: %v", err)
	}
}

func TestJwk_APublicAndPrivateJwkOfOneKeyShareTheirIdentifier(t *testing.T) {
	for name, pair := range keyPairs(t) {
		t.Run(name, func(t *testing.T) {
			public, err := PublicJwk(pair.public)
			if err != nil {
				t.Fatalf("failed to build the public jwk: %v", err)
			}
			private, err := PrivateJwk(pair.private)
			if err != nil {
				t.Fatalf("failed to build the private jwk: %v", err)
			}

			publicKid, publicPresent := (*public)["kid"].(string)
			privateKid, privatePresent := (*private)["kid"].(string)
			if !publicPresent || !privatePresent {
				t.Fatalf("[RFC 7517 4.5] both jwks must carry a kid before they can share one: public present=%t, private present=%t", publicPresent, privatePresent)
			}
			if publicKid != privateKid {
				t.Errorf("[RFC 7517 4.5] one key is one key, so its public and private jwk must carry the same kid, got %q and %q", publicKid, privateKid)
			}
		})
	}
}

func TestJwk_DistinctKeysGetDistinctIdentifiers(t *testing.T) {
	seen := map[string]string{}
	for name, pair := range keyPairs(t) {
		built, err := PublicJwk(pair.public)
		if err != nil {
			t.Fatalf("failed to build the jwk: %v", err)
		}
		kid, ok := (*built)["kid"].(string)
		if !ok {
			t.Fatalf("%s has no usable kid", name)
		}
		if previous, clash := seen[kid]; clash {
			t.Errorf("%s and %s produced the same kid %q, so a key set holding both cannot distinguish them", name, previous, kid)
		}
		seen[kid] = name
	}
}

func TestJwk_TheIdentifierCoversEveryPublicParameter(t *testing.T) {
	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("failed to generate RSA: %v", err)
	}
	ecKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate EC: %v", err)
	}
	edPublic, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate Ed25519: %v", err)
	}
	flipped := append(ed25519.PublicKey(nil), edPublic...)
	flipped[0] ^= 0xff

	tests := map[string]struct {
		parameter string
		a, b      crypto.PublicKey
	}{
		"RSA, the same modulus under a different exponent": {
			parameter: "e",
			a:         &rsa.PublicKey{N: rsaKey.N, E: 65537},
			b:         &rsa.PublicKey{N: rsaKey.N, E: 3},
		},
		"EC, the same coordinates in the other order": {
			parameter: "x and y",
			a:         &ecdsa.PublicKey{Curve: elliptic.P256(), X: ecKey.X, Y: ecKey.Y},
			b:         &ecdsa.PublicKey{Curve: elliptic.P256(), X: ecKey.Y, Y: ecKey.X},
		},
		"Ed25519, one byte of the key changed": {
			parameter: "x",
			a:         &edPublic,
			b:         &flipped,
		},
	}

	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			first, err := PublicJwk(test.a)
			if err != nil {
				t.Fatalf("failed to build the first jwk: %v", err)
			}
			second, err := PublicJwk(test.b)
			if err != nil {
				t.Fatalf("failed to build the second jwk: %v", err)
			}
			if (*first)["kid"] == (*second)["kid"] {
				t.Errorf("a kid identifies a key, so changing %s must change it: two keys differing there share the kid %v", test.parameter, (*first)["kid"])
			}
		})
	}
}
