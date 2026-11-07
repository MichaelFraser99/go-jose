package jwk

import (
	"bytes"
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"maps"
	"testing"

	"github.com/MichaelFraser99/go-jose/joseerror"
)

const (
	rfc8037A6RecipientX       = "3p7bfXt9wbTTW2HC7OQ1Nz-DQ8hbeGdNrfx-FG-IK08"
	rfc8037A6RecipientHex     = "de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f"
	rfc8037A6EphemeralHex     = "77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a"
	rfc8037A6EphemeralPubHex  = "8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a"
	rfc8037A6EphemeralX       = "hSDwCYkwp1R0i33ctD73Wg2_Og0mOBr066SpjqqbTmo"
	rfc8037A6SharedSecretHex  = "4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742"
	rfc8037A1Ed25519PublicHex = "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a"
)

func x25519Hex(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func rfc8037A6RecipientJwk() map[string]any {
	return map[string]any{"kty": "OKP", "crv": "X25519", "kid": "Bob", "x": rfc8037A6RecipientX}
}

func rfc8037A6EphemeralJwk(t *testing.T) map[string]any {
	t.Helper()
	return map[string]any{
		"kty": "OKP",
		"crv": "X25519",
		"x":   base64.RawURLEncoding.EncodeToString(x25519Hex(t, rfc8037A6EphemeralPubHex)),
		"d":   base64.RawURLEncoding.EncodeToString(x25519Hex(t, rfc8037A6EphemeralHex)),
	}
}

func TestPublicFromJwk_ReadsTheRFC8037X25519RecipientKey(t *testing.T) {
	read, err := PublicFromJwk(rfc8037A6RecipientJwk())
	if err != nil {
		t.Fatalf("[RFC 8037 A.6] the example's recipient key must read, got %v", err)
	}
	key, ok := read.(*ecdh.PublicKey)
	if !ok {
		t.Fatalf("[RFC 8037 3.2] an X25519 jwk must read as an *ecdh.PublicKey, got %T", read)
	}
	if key.Curve() != ecdh.X25519() {
		t.Errorf("[RFC 8037 3.2] the key must be on X25519, got %v", key.Curve())
	}
	if want := x25519Hex(t, rfc8037A6RecipientHex); !bytes.Equal(key.Bytes(), want) {
		t.Errorf("[RFC 8037 A.6] the recipient key must be the octets the appendix prints\n got %x\nwant %x", key.Bytes(), want)
	}
}

func TestPrivateJwk_RoundTripsTheRFC8037X25519EphemeralKey(t *testing.T) {
	secret := x25519Hex(t, rfc8037A6EphemeralHex)
	stdlibKey, err := ecdh.X25519().NewPrivateKey(secret)
	if err != nil {
		t.Fatal(err)
	}

	built, err := PrivateJwk(stdlibKey)
	if err != nil {
		t.Fatalf("[RFC 8037 2] an X25519 private key must build a jwk, got %v", err)
	}
	want := map[string]string{"kty": "OKP", "crv": "X25519", "x": rfc8037A6EphemeralX, "d": base64.RawURLEncoding.EncodeToString(secret)}
	for member, value := range want {
		if (*built)[member] != value {
			t.Errorf("[RFC 8037 A.6] the ephemeral key's jwk must carry %s %q, got %v", member, value, (*built)[member])
		}
	}

	publicBuilt, err := PublicJwk(stdlibKey.PublicKey())
	if err != nil {
		t.Fatalf("[RFC 8037 2] an X25519 public key must build a jwk, got %v", err)
	}
	if (*publicBuilt)["x"] != rfc8037A6EphemeralX || (*publicBuilt)["crv"] != "X25519" || (*publicBuilt)["kty"] != "OKP" {
		t.Errorf("[RFC 8037 A.6] the ephemeral public key's jwk must be the appendix's, got %v", *publicBuilt)
	}
	if _, present := (*publicBuilt)["d"]; present {
		t.Error("[RFC 8037 2] 'd' MUST NOT be present for public keys")
	}

	for name, source := range map[string]map[string]any{"built by PrivateJwk": *built, "built from the appendix": rfc8037A6EphemeralJwk(t)} {
		t.Run(name, func(t *testing.T) {
			read, err := PrivateFromJwk(source)
			if err != nil {
				t.Fatalf("[RFC 8037 2] the ephemeral key's jwk must read back, got %v", err)
			}
			key, ok := read.(*ecdh.PrivateKey)
			if !ok {
				t.Fatalf("[RFC 8037 3.2] an X25519 private jwk must read as an *ecdh.PrivateKey, got %T", read)
			}
			if !key.Equal(stdlibKey) {
				t.Errorf("[RFC 8037 A.6] the key read back must be the appendix's ephemeral secret, got %x", key.Bytes())
			}
		})
	}
}

func TestX25519_KeysReadFromJwksAgreeOnTheRFC8037SharedSecret(t *testing.T) {
	ephemeral, err := PrivateFromJwk(rfc8037A6EphemeralJwk(t))
	if err != nil {
		t.Fatal(err)
	}
	recipient, err := PublicFromJwk(rfc8037A6RecipientJwk())
	if err != nil {
		t.Fatal(err)
	}
	private, ok := ephemeral.(*ecdh.PrivateKey)
	if !ok {
		t.Fatalf("[RFC 8037 3.2] expected an *ecdh.PrivateKey, got %T", ephemeral)
	}
	public, ok := recipient.(*ecdh.PublicKey)
	if !ok {
		t.Fatalf("[RFC 8037 3.2] expected an *ecdh.PublicKey, got %T", recipient)
	}
	z, err := private.ECDH(public)
	if err != nil {
		t.Fatalf("[RFC 8037 3.2.1] X25519 of the keys read must succeed, got %v", err)
	}
	if want := x25519Hex(t, rfc8037A6SharedSecretHex); !bytes.Equal(z, want) {
		t.Errorf("[RFC 8037 A.6] Z must be the appendix's\n got %x\nwant %x", z, want)
	}
}

func TestPublicFromJwk_AcceptsANonCanonicalX25519Key(t *testing.T) {
	x := x25519Hex(t, rfc8037A6RecipientHex)
	x[31] |= 0x80
	jwk := rfc8037A6RecipientJwk()
	jwk["x"] = base64.RawURLEncoding.EncodeToString(x)

	read, err := PublicFromJwk(jwk)
	if err != nil {
		t.Fatalf("[RFC 7748 5] the most significant bit of the final byte is masked, so this key must be accepted, got %v", err)
	}
	if key, ok := read.(*ecdh.PublicKey); !ok || !bytes.Equal(key.Bytes(), x) {
		t.Errorf("[RFC 7748 5] the key must be read as given, got %T", read)
	}
}

func TestFromJwk_RefusesAnX25519JwkWithOneFault(t *testing.T) {
	valid := rfc8037A6EphemeralJwk(t)
	x := x25519Hex(t, rfc8037A6EphemeralPubHex)
	d := x25519Hex(t, rfc8037A6EphemeralHex)
	encode := base64.RawURLEncoding.EncodeToString
	other, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	highBitX := bytes.Clone(x)
	highBitX[31] |= 0x80
	slashed := []byte(rfc8037A6EphemeralX)
	slashed[0] = '/'

	with := func(member string, value any) map[string]any {
		jwk := maps.Clone(valid)
		if value == nil {
			delete(jwk, member)
		} else {
			jwk[member] = value
		}
		return jwk
	}

	tests := map[string]struct {
		jwk           map[string]any
		public        error
		private       error
		clause        string
		privateClause string
	}{
		"x of 31 octets":                    {jwk: with("x", encode(x[:31])), public: joseerror.ErrInvalidPublicKey, private: joseerror.ErrInvalidPrivateKey, clause: "RFC 7748 5"},
		"x of 33 octets":                    {jwk: with("x", encode(append(bytes.Clone(x), 0))), public: joseerror.ErrInvalidPublicKey, private: joseerror.ErrInvalidPrivateKey, clause: "RFC 7748 5"},
		"x absent":                          {jwk: with("x", nil), public: joseerror.ErrMissingClaim, private: joseerror.ErrMissingClaim, clause: "RFC 8037 2"},
		"x a number":                        {jwk: with("x", 25519), public: joseerror.ErrMalformedClaim, private: joseerror.ErrMalformedClaim, clause: "RFC 8037 2"},
		"x an object":                       {jwk: with("x", map[string]any{"x": rfc8037A6EphemeralX}), public: joseerror.ErrMalformedClaim, private: joseerror.ErrMalformedClaim, clause: "RFC 8037 2"},
		"x with padding":                    {jwk: with("x", rfc8037A6EphemeralX+"="), public: joseerror.ErrMalformedClaim, private: joseerror.ErrMalformedClaim, clause: "RFC 7515 2"},
		"x with a character of base64 only": {jwk: with("x", string(slashed)), public: joseerror.ErrMalformedClaim, private: joseerror.ErrMalformedClaim, clause: "RFC 7515 2"},
		"x with a line break":               {jwk: with("x", rfc8037A6EphemeralX[:20]+"\n"+rfc8037A6EphemeralX[20:]), public: joseerror.ErrMalformedClaim, private: joseerror.ErrMalformedClaim, clause: "RFC 7515 2"},
		"crv absent":                        {jwk: with("crv", nil), public: joseerror.ErrInvalidPublicKey, private: joseerror.ErrInvalidPrivateKey, clause: "RFC 8037 2"},
		"crv a number":                      {jwk: with("crv", 25519), public: joseerror.ErrInvalidPublicKey, private: joseerror.ErrInvalidPrivateKey, clause: "RFC 8037 2"},
		"crv X448":                          {jwk: with("crv", "X448"), public: joseerror.ErrUnsupportedAlgorithm, private: joseerror.ErrUnsupportedAlgorithm, clause: "RFC 8037 3.2"},
		"d of 31 octets":                    {jwk: with("d", encode(d[:31])), private: joseerror.ErrInvalidPrivateKey, privateClause: "RFC 7748 5"},
		"d of 33 octets":                    {jwk: with("d", encode(append(bytes.Clone(d), 0))), private: joseerror.ErrInvalidPrivateKey, privateClause: "RFC 7748 5"},
		"d a number":                        {jwk: with("d", 7), private: joseerror.ErrMalformedClaim, privateClause: "RFC 8037 2"},
		"d with padding":                    {jwk: with("d", encode(d)+"="), private: joseerror.ErrMalformedClaim, privateClause: "RFC 7515 2"},
		"x the public key of another d":     {jwk: with("x", encode(other.PublicKey().Bytes())), private: joseerror.ErrInvalidPrivateKey, privateClause: "RFC 8037 2"},
		"x a non-canonical encoding of d's": {jwk: with("x", encode(highBitX)), private: joseerror.ErrInvalidPrivateKey, privateClause: "RFC 7748 6.1"},
	}

	for name, test := range tests {
		if test.public != nil {
			t.Run(name+", public", func(t *testing.T) {
				public := maps.Clone(test.jwk)
				delete(public, "d")
				key, err := PublicFromJwk(public)
				if !errors.Is(err, test.public) {
					t.Errorf("[%s] %s must be refused with %v, got %v", test.clause, name, test.public, err)
				}
				if key != nil {
					t.Errorf("[%s] no key may be returned alongside the refusal, got %#v", test.clause, key)
				}
			})
		}
		t.Run(name+", private", func(t *testing.T) {
			clause := test.privateClause
			if clause == "" {
				clause = test.clause
			}
			key, err := PrivateFromJwk(test.jwk)
			if !errors.Is(err, test.private) {
				t.Errorf("[%s] %s must be refused with %v, got %v", clause, name, test.private, err)
			}
			if key != nil {
				t.Errorf("[%s] no key may be returned alongside the refusal, got %#v", clause, key)
			}
		})
	}

	t.Run("the valid fixture", func(t *testing.T) {
		if _, err := PrivateFromJwk(valid); err != nil {
			t.Errorf("[RFC 8037 A.6] every fixture above differs from this one by one member, so it must read, got %v", err)
		}
		public := maps.Clone(valid)
		delete(public, "d")
		if _, err := PublicFromJwk(public); err != nil {
			t.Errorf("[RFC 8037 A.6] every fixture above differs from this one by one member, so it must read, got %v", err)
		}
	})
}

func TestPublicFromJwk_AnEd25519JwkStillReadsAsAnEd25519Key(t *testing.T) {
	want := x25519Hex(t, rfc8037A1Ed25519PublicHex)
	read, err := PublicFromJwk(map[string]any{"kty": "OKP", "crv": "Ed25519", "x": base64.RawURLEncoding.EncodeToString(want)})
	if err != nil {
		t.Fatalf("[RFC 8037 A.2] the Ed25519 example must read, got %v", err)
	}
	key, ok := read.(*ed25519.PublicKey)
	if !ok {
		t.Fatalf("[RFC 8037 3.1] an Ed25519 jwk must read as an *ed25519.PublicKey, got %T", read)
	}
	if !bytes.Equal(*key, want) {
		t.Errorf("[RFC 8037 A.2] got %x, want %x", *key, want)
	}
}

func TestThumbprint_AnX25519KeyHashesCrvKtyAndX(t *testing.T) {
	digest := sha256.Sum256([]byte(`{"crv":"X25519","kty":"OKP","x":"` + rfc8037A6RecipientX + `"}`))
	want := base64.RawURLEncoding.EncodeToString(digest[:])

	got, err := Thumbprint(rfc8037A6RecipientJwk())
	if err != nil {
		t.Fatal(err)
	}
	if got != want {
		t.Errorf("[RFC 8037 2] an OKP thumbprint hashes crv, kty and x in that order, expected %s, got %s", want, got)
	}

	recipient, err := ecdh.X25519().NewPublicKey(x25519Hex(t, rfc8037A6RecipientHex))
	if err != nil {
		t.Fatal(err)
	}
	built, err := PublicJwk(recipient)
	if err != nil {
		t.Fatal(err)
	}
	if (*built)["kid"] != want {
		t.Errorf("[RFC 7638 3.2] the kid PublicJwk gives an X25519 key must be its thumbprint, expected %s, got %v", want, (*built)["kid"])
	}
}

func TestJwk_AnECDHKeyOnANISTCurveIsWrittenAsAnECJwk(t *testing.T) {
	for name, curve := range map[string]elliptic.Curve{"P-256": elliptic.P256(), "P-384": elliptic.P384(), "P-521": elliptic.P521()} {
		t.Run(name, func(t *testing.T) {
			ecdsaKey, err := ecdsa.GenerateKey(curve, rand.Reader)
			if err != nil {
				t.Fatal(err)
			}
			ecdhKey, err := ecdsaKey.ECDH()
			if err != nil {
				t.Fatal(err)
			}
			point, err := ecdsaKey.PublicKey.Bytes()
			if err != nil {
				t.Fatal(err)
			}
			scalar, err := ecdsaKey.Bytes()
			if err != nil {
				t.Fatal(err)
			}
			size := (len(point) - 1) / 2
			want := map[string]string{
				"kty": "EC",
				"crv": name,
				"x":   base64.RawURLEncoding.EncodeToString(point[1 : 1+size]),
				"y":   base64.RawURLEncoding.EncodeToString(point[1+size:]),
			}

			public, err := PublicJwk(ecdhKey.PublicKey())
			if err != nil {
				t.Fatalf("[RFC 7518 6.2.1] an ECDH key on %s must build an EC jwk, got %v", name, err)
			}
			private, err := PrivateJwk(ecdhKey)
			if err != nil {
				t.Fatalf("[RFC 7518 6.2.2] an ECDH key on %s must build an EC jwk, got %v", name, err)
			}
			for member, value := range want {
				if (*public)[member] != value || (*private)[member] != value {
					t.Errorf("[RFC 7518 6.2.1] both jwks must carry %s %q, got %v and %v", member, value, (*public)[member], (*private)[member])
				}
			}
			if (*private)["d"] != base64.RawURLEncoding.EncodeToString(scalar) {
				t.Errorf("[RFC 7518 6.2.2.1] the private jwk must carry the key's scalar as d, got %v", (*private)["d"])
			}
			if _, present := (*public)["d"]; present {
				t.Error("[RFC 7518 6.2.1] a public jwk must not carry d")
			}
		})
	}
}

func TestJwk_RefusesAnECDHKeyWithNoCurve(t *testing.T) {
	publics := map[string]*ecdh.PublicKey{"nil": nil, "the zero value": {}}
	for name, key := range publics {
		t.Run(name+" public", func(t *testing.T) {
			built, err := PublicJwk(key)
			if !errors.Is(err, joseerror.ErrInvalidPublicKey) || built != nil {
				t.Errorf("[RFC 8037 2] a key with no curve has no crv, so it must be refused with ErrInvalidPublicKey, got %v and %v", built, err)
			}
		})
	}
	privates := map[string]*ecdh.PrivateKey{"nil": nil, "the zero value": {}}
	for name, key := range privates {
		t.Run(name+" private", func(t *testing.T) {
			built, err := PrivateJwk(key)
			if !errors.Is(err, joseerror.ErrInvalidPrivateKey) || built != nil {
				t.Errorf("[RFC 8037 2] a key with no curve has no crv, so it must be refused with ErrInvalidPrivateKey, got %v and %v", built, err)
			}
		})
	}
}
