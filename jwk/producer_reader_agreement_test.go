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
	"sync"
	"testing"

	"github.com/MichaelFraser99/go-jose/joseerror"
)

func ecdsaKeyPair(t *testing.T) (*ecdsa.PrivateKey, *ecdsa.PrivateKey) {
	t.Helper()
	a, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	b, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return a, b
}

func ed25519KeyPair(t *testing.T) (ed25519.PrivateKey, ed25519.PrivateKey) {
	t.Helper()
	_, a, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	_, b, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return a, b
}

func TestPrivateJwk_RefusesAKeyWhosePrivateHalfIsNotItsPublicHalf(t *testing.T) {
	ecA, ecB := ecdsaKeyPair(t)
	edA, edB := ed25519KeyPair(t)
	rsaA, _ := rsaReaderKeyPair(t)

	mixedEd25519 := append(append(ed25519.PrivateKey{}, edA[:ed25519.SeedSize]...), edB[ed25519.SeedSize:]...)
	wrongD := new(big.Int).Sub(rsaA.D, big.NewInt(2))

	tests := map[string]struct {
		key    crypto.PrivateKey
		clause string
	}{
		"an EC key with the point of one key and the d of another": {
			key:    &ecdsa.PrivateKey{PublicKey: ecA.PublicKey, D: ecB.D},
			clause: "RFC 7518 6.2.2.1",
		},
		"an Ed25519 key with the seed of one key and the public key of another": {
			key:    mixedEd25519,
			clause: "RFC 8037 2",
		},
		"an RSA key with no primes and a d that does not invert e": {
			key:    &rsa.PrivateKey{PublicKey: rsaA.PublicKey, D: wrongD},
			clause: "RFC 7518 6.3.2.1",
		},
		"an RSA key with both primes and a d that does not invert e": {
			key:    &rsa.PrivateKey{PublicKey: rsaA.PublicKey, D: wrongD, Primes: rsaA.Primes},
			clause: "RFC 7518 6.3.2.1",
		},
	}

	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			jwk, err := produce(t, func() (*map[string]any, error) { return PrivateJwk(test.key) })
			if !errors.Is(err, joseerror.ErrInvalidPrivateKey) {
				t.Fatalf("[%s] the private and public members of a jwk describe one key, so %s must be refused with ErrInvalidPrivateKey, got %v and %v", test.clause, name, err, jwk)
			}
			if jwk != nil {
				t.Errorf("[%s] no jwk may be returned alongside the refusal, got %v", test.clause, *jwk)
			}
		})
	}
}

func TestPrivateJwk_EncodesAKeyWhosePrivateHalfIsItsPublicHalf(t *testing.T) {
	ecA, _ := ecdsaKeyPair(t)
	edA, _ := ed25519KeyPair(t)
	rsaA, _ := rsaReaderKeyPair(t)

	tests := map[string]crypto.PrivateKey{
		"an EC key":                    ecA,
		"an Ed25519 key":               edA,
		"an RSA key with both primes":  rsaA,
		"an RSA key with no primes":    &rsa.PrivateKey{PublicKey: rsaA.PublicKey, D: rsaA.D},
		"an RSA key built from e of 3": rsaKeyWithExponent(t, 3),
	}

	for name, key := range tests {
		t.Run(name, func(t *testing.T) {
			jwk, err := produce(t, func() (*map[string]any, error) { return PrivateJwk(key) })
			if err != nil {
				t.Fatalf("[RFC 7517 4] %s is one consistent key and must be encoded, got %v", name, err)
			}
			if _, err := PrivateFromJwk(*jwk); err != nil {
				t.Errorf("[RFC 7517 4] the jwk produced for %s must read back, got %v", name, err)
			}
		})
	}
}

var rsaExponentKeys sync.Map

func rsaKeyWithExponent(t *testing.T, e int) *rsa.PrivateKey {
	t.Helper()
	if key, ok := rsaExponentKeys.Load(e); ok {
		return key.(*rsa.PrivateKey)
	}
	bigE := big.NewInt(int64(e))
	one := big.NewInt(1)
	for {
		p, err := rand.Prime(rand.Reader, 1024)
		if err != nil {
			t.Fatal(err)
		}
		q, err := rand.Prime(rand.Reader, 1024)
		if err != nil {
			t.Fatal(err)
		}
		pMinus, qMinus := new(big.Int).Sub(p, one), new(big.Int).Sub(q, one)
		lambda := new(big.Int).Div(new(big.Int).Mul(pMinus, qMinus), new(big.Int).GCD(nil, nil, pMinus, qMinus))
		d := new(big.Int).ModInverse(bigE, lambda)
		if d == nil || p.Cmp(q) == 0 {
			continue
		}
		key := &rsa.PrivateKey{PublicKey: rsa.PublicKey{N: new(big.Int).Mul(p, q), E: e}, D: d, Primes: []*big.Int{p, q}}
		key.Precompute()
		rsaExponentKeys.Store(e, key)
		return key
	}
}

func TestJwk_AnRSAExponentTheReaderRefusesIsNotProduced(t *testing.T) {
	a, _ := rsaReaderKeyPair(t)
	tests := map[string]int{
		"one":                        1,
		"two":                        2,
		"65536, an even value":       1 << 16,
		"2^31+1, past what Go reads": 1<<31 + 1,
		"2^32":                       1 << 32,
	}

	for name, e := range tests {
		t.Run(name, func(t *testing.T) {
			public := &rsa.PublicKey{N: a.N, E: e}
			if jwk, err := produce(t, func() (*map[string]any, error) { return PublicJwk(public) }); !errors.Is(err, joseerror.ErrInvalidPublicKey) {
				t.Errorf("[RFC 8017 3.1] e is an odd integer from 3 that PublicFromJwk reads, so %s must be refused with ErrInvalidPublicKey, got %v and %v", name, err, jwk)
			}
			private := &rsa.PrivateKey{PublicKey: *public, D: a.D}
			if jwk, err := produce(t, func() (*map[string]any, error) { return PrivateJwk(private) }); !errors.Is(err, joseerror.ErrInvalidPrivateKey) {
				t.Errorf("[RFC 8017 3.1] e is an odd integer from 3 that PrivateFromJwk reads, so %s must be refused with ErrInvalidPrivateKey, got %v and %v", name, err, jwk)
			}
		})
	}
}

func TestPublicJwk_EncodesTheSmallestAndLargestExponentTheReaderReads(t *testing.T) {
	a, _ := rsaReaderKeyPair(t)
	tests := map[string]struct {
		e    int
		want string
	}{
		"three":  {e: 3, want: "Aw"},
		"2^31-1": {e: 1<<31 - 1, want: "f____w"},
	}

	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			jwk, err := produce(t, func() (*map[string]any, error) { return PublicJwk(&rsa.PublicKey{N: a.N, E: test.e}) })
			if err != nil {
				t.Fatalf("[RFC 8017 3.1] e of %s is odd and in range, so it must be encoded, got %v", name, err)
			}
			if got := (*jwk)["e"]; got != test.want {
				t.Errorf("[RFC 7518 6.3.1.2] e of %s is the Base64urlUInt %q, got %v", name, test.want, got)
			}
			if _, err := PublicFromJwk(*jwk); err != nil {
				t.Errorf("[RFC 8017 3.1] e of %s must read back, got %v", name, err)
			}
		})
	}
}

func TestPublicFromJwk_RefusesAnRSAModulusThatIsNotAPositiveBase64urlUInt(t *testing.T) {
	tests := map[string]string{
		"zero, written as RFC 7518 section 2 writes it": "AA",
		"no octets at all": "",
	}

	for name, n := range tests {
		t.Run(name, func(t *testing.T) {
			key, err := PublicFromJwk(map[string]any{"kty": "RSA", "n": n, "e": "AQAB"})
			if err == nil {
				t.Fatalf("[RFC 8017 3.1] n is a product of primes, so a modulus of %s must be refused, got %#v", name, key)
			}
			if !errors.Is(err, joseerror.ErrInvalidPublicKey) && !errors.Is(err, joseerror.ErrMalformedClaim) {
				t.Errorf("[RFC 8017 3.1] the refusal must carry a key or claim error class, got %v", err)
			}
		})
	}
}

func TestFromJwk_RefusesAZeroLengthBase64urlUInt(t *testing.T) {
	full := rfc7517ExampleRSAKey()
	for _, member := range []string{"n", "e", "d", "p", "q", "dp", "dq", "qi"} {
		t.Run(member, func(t *testing.T) {
			jwk := map[string]any{}
			for k, v := range full {
				jwk[k] = v
			}
			jwk[member] = ""
			key, err := PrivateFromJwk(jwk)
			if err == nil {
				t.Fatalf("[RFC 7518 2] a Base64urlUInt is at least one octet, as zero is \"AA\", so an empty %q must be refused, got %T", member, key)
			}
			if !errors.Is(err, joseerror.ErrMalformedClaim) {
				t.Errorf("[RFC 7518 2] an empty %q is not a Base64urlUInt, so the refusal must carry ErrMalformedClaim, got %v", member, err)
			}
		})
	}
}

var manyPrimeRSAKeys sync.Map

func rsaKeyOfManyPrimesWithNoneListed(t *testing.T, bits int) *rsa.PrivateKey {
	t.Helper()
	if key, ok := manyPrimeRSAKeys.Load(bits); ok {
		return key.(*rsa.PrivateKey)
	}
	e := big.NewInt(65537)
	one := big.NewInt(1)
	coprime := func(p *big.Int) bool {
		return new(big.Int).GCD(nil, nil, e, new(big.Int).Sub(p, one)).Cmp(one) == 0
	}
	n := big.NewInt(1)
	var primes []*big.Int
	for n.BitLen() < bits-1024 {
		p, err := rand.Prime(rand.Reader, 512)
		if err != nil {
			t.Fatal(err)
		}
		if coprime(p) && new(big.Int).Mod(n, p).Sign() != 0 {
			primes = append(primes, p)
			n.Mul(n, p)
		}
	}
	low := new(big.Int).Add(new(big.Int).Div(new(big.Int).Lsh(one, uint(bits-1)), n), one)
	span := new(big.Int).Sub(new(big.Int).Div(new(big.Int).Sub(new(big.Int).Lsh(one, uint(bits)), one), n), low)
	for {
		q, err := rand.Int(rand.Reader, span)
		if err != nil {
			t.Fatal(err)
		}
		q.Add(q, low).SetBit(q, 0, 1)
		if q.ProbablyPrime(32) && coprime(q) && new(big.Int).Mod(n, q).Sign() != 0 {
			primes = append(primes, q)
			n.Mul(n, q)
			break
		}
	}
	lambda := big.NewInt(1)
	for _, p := range primes {
		pMinus := new(big.Int).Sub(p, one)
		lambda.Div(new(big.Int).Mul(lambda, pMinus), new(big.Int).GCD(nil, nil, lambda, pMinus))
	}
	if n.BitLen() != bits {
		t.Fatalf("the fixture must be a %d-bit modulus, got %d", bits, n.BitLen())
	}
	key := &rsa.PrivateKey{PublicKey: rsa.PublicKey{N: n, E: 65537}, D: new(big.Int).ModInverse(e, lambda)}
	manyPrimeRSAKeys.Store(bits, key)
	return key
}

func TestJwk_AnRSAKeyWithNoPrimesIsReadUpToTheModulusCapAndRefusedPastIt(t *testing.T) {
	tests := map[string]struct {
		bits   int
		accept bool
	}{
		"8192 bits, the cap":        {bits: 8192, accept: true},
		"8193 bits, one past it":    {bits: 8193},
		"8256 bits, a word past it": {bits: 8256},
	}

	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			key := rsaKeyOfManyPrimesWithNoneListed(t, test.bits)
			jwk := map[string]any{
				"kty": "RSA",
				"n":   rsaMember(key.N),
				"e":   rsaMember(big.NewInt(int64(key.E))),
				"d":   rsaMember(key.D),
			}
			read, readErr := PrivateFromJwk(jwk)
			if test.accept {
				if readErr != nil {
					t.Errorf("[RFC 7518 6.3.2] a %d-bit key with no primes whose d inverts e is within the cap, so it must be read, got %v", test.bits, readErr)
				}
				return
			}
			produced, produceErr := produce(t, func() (*map[string]any, error) { return PrivateJwk(key) })
			if !errors.Is(readErr, joseerror.ErrInvalidPrivateKey) {
				t.Errorf("[RFC 7518 6.3.2] with no primes d can be checked only by signing, so a %d-bit modulus above the 8192-bit cap must be refused with ErrInvalidPrivateKey even when d inverts e, got %v and %T", test.bits, readErr, read)
			}
			if !errors.Is(produceErr, joseerror.ErrInvalidPrivateKey) {
				t.Errorf("[RFC 7518 6.3.2] PrivateJwk must refuse a %d-bit key with no primes that PrivateFromJwk refuses, got %v and %v", test.bits, produceErr, produced)
			}
		})
	}
}

func ed25519Encoding(y *big.Int, sign bool) string {
	encoded := make([]byte, ed25519.PublicKeySize)
	y.FillBytes(encoded)
	for i, j := 0, len(encoded)-1; i < j; i, j = i+1, j-1 {
		encoded[i], encoded[j] = encoded[j], encoded[i]
	}
	if sign {
		encoded[31] |= 0x80
	}
	return base64.RawURLEncoding.EncodeToString(encoded)
}

func TestJwk_AnEd25519PublicKeyMustBeTheCanonicalEncodingOfAPoint(t *testing.T) {
	p := new(big.Int).Sub(new(big.Int).Lsh(big.NewInt(1), 255), big.NewInt(19))
	pMinusOne := new(big.Int).Sub(p, big.NewInt(1))
	tests := map[string]struct {
		x      string
		accept bool
	}{
		"the RFC 8032 7.1 SHA(abc) key, whose sign bit is set": {x: "7Bcrk61eVjv0kyxw4SRQNMNUZ-8u_U1k6_gZaDRn4r8", accept: true},
		"y of 1, the neutral point":                            {x: ed25519Encoding(big.NewInt(1), false), accept: true},
		"y of p-1, the largest y below p":                      {x: ed25519Encoding(pMinusOne, false), accept: true},
		"y of p, which is y of 0 written again":                {x: ed25519Encoding(p, false)},
		"y of p+1, which is y of 1 written again":              {x: ed25519Encoding(new(big.Int).Add(p, big.NewInt(1)), false)},
		"y of 2^255-1, the largest 255-bit value":              {x: ed25519Encoding(new(big.Int).Add(p, big.NewInt(18)), false)},
		"y of p with the sign bit set":                         {x: ed25519Encoding(p, true)},
		"y of 1 with the sign bit set, where x is 0":           {x: ed25519Encoding(big.NewInt(1), true)},
		"y of p-1 with the sign bit set, where x is 0":         {x: ed25519Encoding(pMinusOne, true)},
	}

	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			jwk := map[string]any{"kty": "OKP", "crv": "Ed25519", "x": test.x}
			key, err := PublicFromJwk(jwk)
			if test.accept {
				if err != nil {
					t.Fatalf("[RFC 8032 5.1.3] %s is a canonical encoding and must be read, got %v", name, err)
				}
				produced, err := produce(t, func() (*map[string]any, error) { return PublicJwk(key) })
				if err != nil {
					t.Fatalf("[RFC 8032 5.1.3] PublicJwk must encode the key PublicFromJwk read for %s, got %v", name, err)
				}
				if (*produced)["x"] != test.x {
					t.Errorf("[RFC 8037 2] the encoded x must be the one read, %q, got %v", test.x, (*produced)["x"])
				}
				return
			}
			if !errors.Is(err, joseerror.ErrInvalidPublicKey) {
				t.Fatalf("[RFC 8032 5.1.3] decoding %s fails, so it must be refused with ErrInvalidPublicKey, got %v and %T", name, err, key)
			}
			raw, decodeErr := base64.RawURLEncoding.DecodeString(test.x)
			if decodeErr != nil {
				t.Fatal(decodeErr)
			}
			for form, public := range map[string]crypto.PublicKey{"ed25519.PublicKey": ed25519.PublicKey(raw), "*ed25519.PublicKey": (*ed25519.PublicKey)(&raw)} {
				if produced, err := produce(t, func() (*map[string]any, error) { return PublicJwk(public) }); !errors.Is(err, joseerror.ErrInvalidPublicKey) {
					t.Errorf("[RFC 8032 5.1.3] PublicJwk must refuse the %s %s that PublicFromJwk refuses, got %v and %v", form, name, err, produced)
				}
			}
		})
	}
}

func TestFromJwk_AJwkWithNoKtyIsRefusedWithTheKeyErrorClass(t *testing.T) {
	jwk := map[string]any{"crv": "P-256", "x": "AA", "y": "AA"}

	if key, err := PublicFromJwk(jwk); !errors.Is(err, joseerror.ErrInvalidPublicKey) {
		t.Errorf("[RFC 7517 4.1] kty is REQUIRED, so a jwk without it must be refused with ErrInvalidPublicKey, got %v and %T", err, key)
	}
	if key, err := PrivateFromJwk(jwk); !errors.Is(err, joseerror.ErrInvalidPrivateKey) {
		t.Errorf("[RFC 7517 4.1] kty is REQUIRED, so a jwk without it must be refused with ErrInvalidPrivateKey, got %v and %T", err, key)
	}
}
