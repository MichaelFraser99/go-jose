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
	"reflect"
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
		"an ecdsa key with no x":          &ecdsa.PublicKey{Curve: elliptic.P256(), Y: elliptic.P256().Params().Gy},
		"an ecdsa key with no y":          &ecdsa.PublicKey{Curve: elliptic.P256(), X: elliptic.P256().Params().Gx},
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
		"an ecdsa key with no x":    &ecdsa.PrivateKey{PublicKey: ecdsa.PublicKey{Curve: elliptic.P256(), Y: elliptic.P256().Params().Gy}, D: big.NewInt(1)},
		"an ecdsa key with no y":    &ecdsa.PrivateKey{PublicKey: ecdsa.PublicKey{Curve: elliptic.P256(), X: elliptic.P256().Params().Gx}, D: big.NewInt(1)},
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
	other, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	staleCRT := *twoPrime
	staleCRT.Precomputed = other.Precomputed

	tests := map[string]*rsa.PrivateKey{
		"two primes":                              twoPrime,
		"two primes, not precomputed":             &notPrecomputed,
		"two primes, precomputed for another key": &staleCRT,
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
			crt := map[string]*big.Int{"dp": twoPrime.Precomputed.Dp, "dq": twoPrime.Precomputed.Dq, "qi": twoPrime.Precomputed.Qinv}
			for member, want := range crt {
				if (*jwk)[member] != base64.RawURLEncoding.EncodeToString(want.Bytes()) {
					t.Errorf("[RFC 7518 6.3.2.4] %s is the CRT value crypto/rsa computes for the key, got %v", member, (*jwk)[member])
				}
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

func TestPublicJwk_AnOversizedCoordinateIsRefusedNotPanicked(t *testing.T) {
	big33 := make([]byte, 33)
	big33[0] = 1
	gy := elliptic.P256().Params().Gy.FillBytes(make([]byte, 32))
	key, err := PublicFromJwk(map[string]any{"kty": "EC", "crv": "P-256", "x": base64.RawURLEncoding.EncodeToString(big33), "y": base64.RawURLEncoding.EncodeToString(gy)})
	if err != nil {
		return
	}
	jwk, err := produce(t, func() (*map[string]any, error) { return PublicJwk(key) })
	if !errors.Is(err, joseerror.ErrInvalidPublicKey) {
		t.Errorf("[RFC 7518 6.2.1.2] a 33-octet P-256 x coordinate cannot be encoded in 32 octets, so it must be refused, got %v", err)
	}
	if jwk != nil {
		t.Errorf("no jwk may be returned alongside the refusal, got %v", *jwk)
	}
}

func TestPrivateJwk_AnOversizedScalarIsRefusedNotPanicked(t *testing.T) {
	big33 := make([]byte, 33)
	big33[0] = 1
	params := elliptic.P256().Params()
	key, err := PrivateFromJwk(map[string]any{
		"kty": "EC",
		"crv": "P-256",
		"x":   base64.RawURLEncoding.EncodeToString(params.Gx.FillBytes(make([]byte, 32))),
		"y":   base64.RawURLEncoding.EncodeToString(params.Gy.FillBytes(make([]byte, 32))),
		"d":   base64.RawURLEncoding.EncodeToString(big33),
	})
	if err != nil {
		return
	}
	jwk, err := produce(t, func() (*map[string]any, error) { return PrivateJwk(key) })
	if !errors.Is(err, joseerror.ErrInvalidPrivateKey) {
		t.Errorf("[RFC 7518 6.2.2.1] a 33-octet P-256 d cannot be encoded in 32 octets, so it must be refused, got %v", err)
	}
	if jwk != nil {
		t.Errorf("no jwk may be returned alongside the refusal, got %v", *jwk)
	}
}

func TestJwk_AnECPointNotOnItsCurveIsRefused(t *testing.T) {
	p256 := elliptic.P256().Params()
	impostor := *elliptic.P224().Params()
	impostor.Name = "P-256"

	tests := map[string]ecdsa.PublicKey{
		"a point off the curve":       {Curve: elliptic.P256(), X: p256.Gx, Y: new(big.Int).Add(p256.Gy, big.NewInt(1))},
		"a negative x":                {Curve: elliptic.P256(), X: new(big.Int).Neg(p256.Gx), Y: p256.Gy},
		"a negative y":                {Curve: elliptic.P256(), X: p256.Gx, Y: new(big.Int).Neg(p256.Gy)},
		"an x of 2^300":               {Curve: elliptic.P256(), X: new(big.Int).Lsh(big.NewInt(1), 300), Y: p256.Gy},
		"an x offset by the prime":    {Curve: elliptic.P256(), X: new(big.Int).Add(p256.Gx, p256.P), Y: p256.Gy},
		"the point at infinity (0,0)": {Curve: elliptic.P256(), X: big.NewInt(0), Y: big.NewInt(0)},
		"a P-224 curve named P-256":   {Curve: &impostor, X: impostor.Gx, Y: impostor.Gy},
	}

	for name, public := range tests {
		t.Run(name, func(t *testing.T) {
			public := public
			jwk, err := produce(t, func() (*map[string]any, error) { return PublicJwk(&public) })
			if !errors.Is(err, joseerror.ErrInvalidPublicKey) {
				t.Errorf("[RFC 7518 6.2.1.2] x and y are the coordinates of a point on the curve crv names, so this public key must be refused, got %v", err)
			}
			if jwk != nil {
				t.Errorf("no jwk may be returned alongside the refusal, got %v", *jwk)
			}

			private := &ecdsa.PrivateKey{PublicKey: public, D: big.NewInt(1)}
			jwk, err = produce(t, func() (*map[string]any, error) { return PrivateJwk(private) })
			if !errors.Is(err, joseerror.ErrInvalidPrivateKey) {
				t.Errorf("[RFC 7518 6.2.1.2] x and y are the coordinates of a point on the curve crv names, so this private key must be refused, got %v", err)
			}
			if jwk != nil {
				t.Errorf("no jwk may be returned alongside the refusal, got %v", *jwk)
			}
		})
	}
}

func TestPrivateJwk_AnECScalarOutsideOneToNMinusOneIsRefused(t *testing.T) {
	params := elliptic.P256().Params()
	tests := map[string]*big.Int{
		"zero":     big.NewInt(0),
		"minus 1":  big.NewInt(-1),
		"n":        new(big.Int).Set(params.N),
		"n plus 1": new(big.Int).Add(params.N, big.NewInt(1)),
		"2^300":    new(big.Int).Lsh(big.NewInt(1), 300),
	}

	for name, d := range tests {
		t.Run(name, func(t *testing.T) {
			key := &ecdsa.PrivateKey{PublicKey: ecdsa.PublicKey{Curve: elliptic.P256(), X: params.Gx, Y: params.Gy}, D: d}
			jwk, err := produce(t, func() (*map[string]any, error) { return PrivateJwk(key) })
			if !errors.Is(err, joseerror.ErrInvalidPrivateKey) {
				t.Errorf("[RFC 7518 6.2.2.1] d is a SEC1 private key, an integer in [1, n-1], so %s must be refused, got %v", name, err)
			}
			if jwk != nil {
				t.Errorf("no jwk may be returned alongside the refusal, got %v", *jwk)
			}
		})
	}

	key := &ecdsa.PrivateKey{PublicKey: ecdsa.PublicKey{Curve: elliptic.P256(), X: params.Gx, Y: params.Gy}, D: new(big.Int).Sub(params.N, big.NewInt(1))}
	if _, err := produce(t, func() (*map[string]any, error) { return PrivateJwk(key) }); err != nil {
		t.Errorf("[RFC 7518 6.2.2.1] d is a SEC1 private key, an integer in [1, n-1], so n-1 must be encoded, got %v", err)
	}
}

func TestPrivateJwk_RefusesAnInconsistentRSAKey(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	withD := func(d *big.Int, primes []*big.Int) *rsa.PrivateKey {
		return &rsa.PrivateKey{PublicKey: key.PublicKey, D: d, Primes: primes}
	}

	tests := map[string]*rsa.PrivateKey{
		"primes 1 and n":                    {PublicKey: rsa.PublicKey{N: big.NewInt(3233), E: 17}, D: big.NewInt(413), Primes: []*big.Int{big.NewInt(1), big.NewInt(3233)}},
		"primes whose product is not n":     {PublicKey: rsa.PublicKey{N: big.NewInt(3233), E: 17}, D: big.NewInt(413), Primes: []*big.Int{big.NewInt(61), big.NewInt(59)}},
		"two equal primes":                  {PublicKey: rsa.PublicKey{N: big.NewInt(3721), E: 17}, D: big.NewInt(53), Primes: []*big.Int{big.NewInt(61), big.NewInt(61)}},
		"a nil second prime":                withD(key.D, []*big.Int{key.Primes[0], nil}),
		"a nil first prime":                 withD(key.D, []*big.Int{nil, key.Primes[1]}),
		"a d that does not match the prime": withD(new(big.Int).Add(key.D, big.NewInt(2)), key.Primes),
		"a negative d with primes":          withD(new(big.Int).Neg(key.D), key.Primes),
		"a zero d with no primes":           withD(big.NewInt(0), nil),
		"a negative d with no primes":       withD(new(big.Int).Neg(key.D), nil),
		"a d equal to n with no primes":     withD(new(big.Int).Set(key.N), nil),
		"a d above n with no primes":        withD(new(big.Int).Add(key.N, big.NewInt(1)), nil),
	}

	for name, key := range tests {
		t.Run(name, func(t *testing.T) {
			jwk, err := produce(t, func() (*map[string]any, error) { return PrivateJwk(key) })
			if !errors.Is(err, joseerror.ErrInvalidPrivateKey) {
				t.Errorf("[RFC 7518 6.3.2] d, p, q, dp, dq and qi describe one RSA key, so a key whose members disagree must be refused, got %v", err)
			}
			if jwk != nil {
				t.Errorf("no jwk may be returned alongside the refusal, got %v", *jwk)
			}
		})
	}
}

func TestPrivateJwk_RefusesAnRSAKeyWithANonPositivePrime(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	p, q := key.Primes[0], key.Primes[1]
	negP, negQ := new(big.Int).Neg(p), new(big.Int).Neg(q)

	tests := map[string][]*big.Int{
		"a negative p":       {negP, q},
		"a negative q":       {p, negQ},
		"a negative p and q": {negP, negQ},
		"a zero p and q":     {big.NewInt(0), big.NewInt(0)},
	}

	for name, primes := range tests {
		t.Run(name, func(t *testing.T) {
			jwk, err := produce(t, func() (*map[string]any, error) {
				return PrivateJwk(&rsa.PrivateKey{PublicKey: key.PublicKey, D: key.D, Primes: primes})
			})
			if !errors.Is(err, joseerror.ErrInvalidPrivateKey) {
				t.Errorf("[RFC 8017 3.2] p and q are positive integers, so a key with %s must be refused, got %v", name, err)
			}
			if jwk != nil {
				t.Errorf("no jwk may be returned alongside the refusal, got %v", *jwk)
			}
		})
	}
}

func TestJwk_AnRSAKeyWithOnlyDRoundTrips(t *testing.T) {
	full, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	encode := func(i *big.Int) string { return base64.RawURLEncoding.EncodeToString(i.Bytes()) }
	read, err := PrivateFromJwk(map[string]any{"kty": "RSA", "n": encode(full.N), "e": encode(big.NewInt(int64(full.E))), "d": encode(full.D)})
	if err != nil {
		t.Fatalf("[RFC 7518 6.3.2] d is the only REQUIRED private member, so a jwk of n, e and d must read, got %v", err)
	}

	tests := map[string]*rsa.PrivateKey{
		"built by hand":            {PublicKey: full.PublicKey, D: full.D},
		"read from n, e and d jwk": read.(*rsa.PrivateKey),
	}
	for name, key := range tests {
		t.Run(name, func(t *testing.T) {
			jwk, err := produce(t, func() (*map[string]any, error) { return PrivateJwk(key) })
			if err != nil {
				t.Fatalf("[RFC 7518 6.3.2] d is the only REQUIRED private member, so a key with no primes must be encoded, got %v", err)
			}
			for _, member := range []string{"p", "q", "dp", "dq", "qi", "oth"} {
				if _, present := (*jwk)[member]; present {
					t.Errorf("[RFC 7518 6.3.2] a key with no primes has no %s to encode, got %v", member, (*jwk)[member])
				}
			}
			if (*jwk)["d"] != encode(full.D) {
				t.Errorf("[RFC 7518 6.3.2.1] d is the Base64urlUInt of the private exponent, want %s, got %v", encode(full.D), (*jwk)["d"])
			}

			back, err := PrivateFromJwk(*jwk)
			if err != nil {
				t.Fatalf("a jwk this library produced must read back, got %v", err)
			}
			digest := sha256Sum([]byte("the signing input"))
			signature, err := rsa.SignPKCS1v15(rand.Reader, back.(*rsa.PrivateKey), crypto.SHA256, digest)
			if err != nil {
				t.Fatalf("the key read back must sign, got %v", err)
			}
			if err := rsa.VerifyPKCS1v15(&full.PublicKey, crypto.SHA256, digest, signature); err != nil {
				t.Errorf("[RFC 7518 6.3.2] the original public key must verify a signature made with the key read back, got %v", err)
			}
		})
	}
}

func TestPrivateJwk_LeavesTheCallersRSAKeyUntouched(t *testing.T) {
	generated, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	p, q, d := new(big.Int).Set(generated.Primes[0]), new(big.Int).Set(generated.Primes[1]), new(big.Int).Set(generated.D)
	key := &rsa.PrivateKey{PublicKey: generated.PublicKey, D: generated.D, Primes: generated.Primes}

	if _, err := produce(t, func() (*map[string]any, error) { return PrivateJwk(key) }); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(key.Precomputed, rsa.PrecomputedValues{}) {
		t.Error("[RFC 7518 6.3.2] producing a jwk must not precompute the caller's key")
	}
	if len(key.Primes) != 2 || key.Primes[0].Cmp(p) != 0 || key.Primes[1].Cmp(q) != 0 || key.D.Cmp(d) != 0 {
		t.Error("[RFC 7518 6.3.2] producing a jwk must not change the caller's d or primes")
	}
}

func sha256Sum(b []byte) []byte {
	h := crypto.SHA256.New()
	h.Write(b)
	return h.Sum(nil)
}
