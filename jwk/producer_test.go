package jwk

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"errors"
	"math/big"
	"testing"

	"github.com/MichaelFraser99/go-jose/joseerror"
)

func produce(t *testing.T, produce func() (*map[string]any, error)) (*map[string]any, error) {
	t.Helper()
	var jwk *map[string]any
	var err error
	func() {
		defer func() {
			if r := recover(); r != nil {
				t.Fatalf("the producer panicked rather than returning an error: %v", r)
			}
		}()
		jwk, err = produce()
	}()
	return jwk, err
}

func TestPublicJwk_RefusesAKeyItCannotEncode(t *testing.T) {
	tests := map[string]crypto.PublicKey{
		"a nil *ecdsa.PublicKey":          (*ecdsa.PublicKey)(nil),
		"a nil *rsa.PublicKey":            (*rsa.PublicKey)(nil),
		"a nil *ed25519.PublicKey":        (*ed25519.PublicKey)(nil),
		"a zero ecdsa.PublicKey":          &ecdsa.PublicKey{},
		"an ecdsa key with no point":      &ecdsa.PublicKey{Curve: elliptic.P256()},
		"an ecdsa key with no curve":      &ecdsa.PublicKey{X: elliptic.P256().Params().Gx, Y: elliptic.P256().Params().Gy},
		"an rsa key with a zero modulus":  &rsa.PublicKey{N: big.NewInt(0), E: 65537},
		"a zero rsa.PublicKey":            &rsa.PublicKey{},
		"an rsa key with no modulus":      &rsa.PublicKey{E: 65537},
		"an rsa key with a zero exponent": &rsa.PublicKey{N: big.NewInt(3233), E: 0},
		"a nil ed25519.PublicKey":         ed25519.PublicKey(nil),
	}

	for name, key := range tests {
		t.Run(name, func(t *testing.T) {
			jwk, err := produce(t, func() (*map[string]any, error) { return PublicJwk(key) })
			if !errors.Is(err, joseerror.ErrInvalidPublicKey) {
				t.Errorf("a key that cannot be encoded must be refused with ErrInvalidPublicKey, got %v", err)
			}
			if jwk != nil {
				t.Errorf("no jwk may be returned alongside the refusal, got %v", *jwk)
			}
		})
	}
}

func TestPrivateJwk_RefusesAKeyItCannotEncode(t *testing.T) {
	tests := map[string]crypto.PrivateKey{
		"a nil *ecdsa.PrivateKey":   (*ecdsa.PrivateKey)(nil),
		"a nil *rsa.PrivateKey":     (*rsa.PrivateKey)(nil),
		"a nil *ed25519.PrivateKey": (*ed25519.PrivateKey)(nil),
		"a zero ecdsa.PrivateKey":   &ecdsa.PrivateKey{},
		"an ecdsa key with no d":    &ecdsa.PrivateKey{PublicKey: ecdsa.PublicKey{Curve: elliptic.P256(), X: elliptic.P256().Params().Gx, Y: elliptic.P256().Params().Gy}},
		"a zero rsa.PrivateKey":     &rsa.PrivateKey{},
		"an rsa key with no d":      &rsa.PrivateKey{PublicKey: rsa.PublicKey{N: big.NewInt(3233), E: 17}, Primes: []*big.Int{big.NewInt(61), big.NewInt(53)}},
		"an rsa key with one prime": &rsa.PrivateKey{PublicKey: rsa.PublicKey{N: big.NewInt(3233), E: 17}, D: big.NewInt(413), Primes: []*big.Int{big.NewInt(3233)}},
		"a nil ed25519.PrivateKey":  ed25519.PrivateKey(nil),
	}

	for name, key := range tests {
		t.Run(name, func(t *testing.T) {
			jwk, err := produce(t, func() (*map[string]any, error) { return PrivateJwk(key) })
			if !errors.Is(err, joseerror.ErrInvalidPrivateKey) {
				t.Errorf("a key that cannot be encoded must be refused with ErrInvalidPrivateKey, got %v", err)
			}
			if jwk != nil {
				t.Errorf("no jwk may be returned alongside the refusal, got %v", *jwk)
			}
		})
	}
}

func TestJwk_AnEllipticCurveJOSEDoesNotRegisterIsRefused(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P224(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	if _, err := produce(t, func() (*map[string]any, error) { return PublicJwk(&key.PublicKey) }); !errors.Is(err, joseerror.ErrInvalidPublicKey) {
		t.Errorf("[RFC 7518 6.2.1.1] crv is one of P-256, P-384 and P-521, so a P-224 public key must be refused, got %v", err)
	}
	if _, err := produce(t, func() (*map[string]any, error) { return PrivateJwk(key) }); !errors.Is(err, joseerror.ErrInvalidPrivateKey) {
		t.Errorf("[RFC 7518 6.2.1.1] crv is one of P-256, P-384 and P-521, so a P-224 private key must be refused, got %v", err)
	}
}

func TestPrivateJwk_PadsDToTheLengthOfTheCurveOrder(t *testing.T) {
	tests := map[string]struct {
		curve  elliptic.Curve
		octets int
	}{
		"P-256": {curve: elliptic.P256(), octets: 32},
		"P-384": {curve: elliptic.P384(), octets: 48},
		"P-521": {curve: elliptic.P521(), octets: 66},
	}

	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			params := test.curve.Params()
			key := &ecdsa.PrivateKey{
				PublicKey: ecdsa.PublicKey{Curve: test.curve, X: params.Gx, Y: params.Gy},
				D:         big.NewInt(1),
			}

			jwk, err := produce(t, func() (*map[string]any, error) { return PrivateJwk(key) })
			if err != nil {
				t.Fatalf("the key whose d is 1 is a valid key, got %v", err)
			}
			d, err := base64.RawURLEncoding.DecodeString((*jwk)["d"].(string))
			if err != nil {
				t.Fatal(err)
			}
			if len(d) != test.octets {
				t.Errorf("[RFC 7518 6.2.2.1] d MUST be ceiling(log-base-2(n)/8) octets, which is %d for %s, got %d", test.octets, name, len(d))
			}
		})
	}
}

func TestJwk_AnEd25519KeyIsAcceptedInTheFormTheStandardLibraryReturns(t *testing.T) {
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	publics := map[string]crypto.PublicKey{
		"ed25519.PublicKey":  public,
		"private.Public()":   private.Public(),
		"*ed25519.PublicKey": &public,
	}
	for name, key := range publics {
		t.Run("public, "+name, func(t *testing.T) {
			jwk, err := produce(t, func() (*map[string]any, error) { return PublicJwk(key) })
			if err != nil {
				t.Fatalf("an Ed25519 public key must be encoded in the form crypto/ed25519 gives it, got %v", err)
			}
			read, err := PublicFromJwk(*jwk)
			if err != nil {
				t.Fatalf("a jwk this library produced must read back, got %v", err)
			}
			if !public.Equal(*read.(*ed25519.PublicKey)) {
				t.Error("[RFC 8037 2] the jwk must encode the key it was given")
			}
		})
	}

	privates := map[string]crypto.PrivateKey{
		"ed25519.PrivateKey":  private,
		"*ed25519.PrivateKey": &private,
	}
	for name, key := range privates {
		t.Run("private, "+name, func(t *testing.T) {
			jwk, err := produce(t, func() (*map[string]any, error) { return PrivateJwk(key) })
			if err != nil {
				t.Fatalf("an Ed25519 private key must be encoded in the form crypto/ed25519 gives it, got %v", err)
			}
			read, err := PrivateFromJwk(*jwk)
			if err != nil {
				t.Fatalf("a jwk this library produced must read back, got %v", err)
			}
			if !private.Equal(*read.(*ed25519.PrivateKey)) {
				t.Error("[RFC 8037 2] the jwk must encode the key it was given")
			}
		})
	}
}

func TestPrivateJwk_AnRSAKeyRoundTripsWhetherOrNotItIsPrecomputed(t *testing.T) {
	twoPrime, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	notPrecomputed := *twoPrime
	notPrecomputed.Precomputed = rsa.PrecomputedValues{}

	tests := map[string]*rsa.PrivateKey{
		"two primes":                  twoPrime,
		"two primes, not precomputed": &notPrecomputed,
	}

	for name, key := range tests {
		t.Run(name, func(t *testing.T) {
			jwk, err := produce(t, func() (*map[string]any, error) { return PrivateJwk(key) })
			if err != nil {
				t.Fatalf("a valid RSA key must be encoded, got %v", err)
			}
			for member, value := range *jwk {
				if s, ok := value.(string); ok && member != "kty" && member != "kid" {
					if _, err := base64.RawURLEncoding.DecodeString(s); err != nil {
						t.Errorf("[RFC 7518 6.3.2] %s is a Base64urlUInt, got %q", member, s)
					}
				}
			}
			if _, present := (*jwk)["oth"]; present {
				t.Error("[RFC 7518 6.3.2.7] when only two primes have been used, oth MUST be omitted")
			}

			read, err := PrivateFromJwk(*jwk)
			if err != nil {
				t.Fatalf("a jwk this library produced must read back, got %v", err)
			}
			readKey := read.(*rsa.PrivateKey)
			if !key.Equal(readKey) {
				t.Error("[RFC 7518 6.3.2] the jwk must encode the key it was given")
			}
			digest := []byte("the signing input")
			signature, err := rsa.SignPSS(rand.Reader, readKey, crypto.SHA256, sha256Sum(digest), nil)
			if err != nil {
				t.Fatalf("the key read back must sign, got %v", err)
			}
			if err := rsa.VerifyPSS(&key.PublicKey, crypto.SHA256, sha256Sum(digest), signature, nil); err != nil {
				t.Errorf("the original public key must verify a signature made with the key read back, got %v", err)
			}
		})
	}
}

func TestJwk_AnRSAKeyWithMoreThanTwoPrimesIsNeitherProducedNorRead(t *testing.T) {
	threePrime, err := rsa.GenerateMultiPrimeKey(rand.Reader, 3, 2048) //nolint:staticcheck
	if err != nil {
		t.Fatal(err)
	}
	jwk, err := produce(t, func() (*map[string]any, error) { return PrivateJwk(threePrime) })
	if !errors.Is(err, joseerror.ErrInvalidPrivateKey) {
		t.Errorf("[RFC 7518 6.3.2.7] this library cannot read a key carrying oth, so it must not produce one, got %v", err)
	}
	if jwk != nil {
		t.Errorf("no jwk may be returned alongside the refusal, got %v", *jwk)
	}

	twoPrime, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	valid, err := PrivateJwk(twoPrime)
	if err != nil {
		t.Fatal(err)
	}
	withOth := map[string]any{"oth": []any{map[string]any{"r": "AQAB", "d": "AQAB", "t": "AQAB"}}}
	for member, value := range *valid {
		withOth[member] = value
	}
	_, err = PrivateFromJwk(withOth)
	if !errors.Is(err, joseerror.ErrInvalidPrivateKey) {
		t.Errorf("[RFC 7518 6.3.2.7] a consumer that does not support more than two primes MUST NOT use a key carrying oth, got %v", err)
	}
}

func sha256Sum(b []byte) []byte {
	h := crypto.SHA256.New()
	h.Write(b)
	return h.Sum(nil)
}
