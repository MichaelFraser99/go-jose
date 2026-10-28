package common

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"errors"
	"math/big"
	"testing"
	"testing/iotest"

	"github.com/MichaelFraser99/go-jose/joseerror"
)

func TestCheckECDSAPrivateKey_RefusesADWhosePointIsNotTheKeys(t *testing.T) {
	a, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	b, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	params := elliptic.P256().Params()

	tests := map[string]struct {
		key    *ecdsa.PrivateKey
		accept bool
	}{
		"a generated key":                    {key: a, accept: true},
		"d of 1 with the point G":            {key: &ecdsa.PrivateKey{PublicKey: ecdsa.PublicKey{Curve: elliptic.P256(), X: params.Gx, Y: params.Gy}, D: big.NewInt(1)}, accept: true},
		"the point of one key, d of another": {key: &ecdsa.PrivateKey{PublicKey: a.PublicKey, D: b.D}},
		"d of 2 with the point G":            {key: &ecdsa.PrivateKey{PublicKey: ecdsa.PublicKey{Curve: elliptic.P256(), X: params.Gx, Y: params.Gy}, D: big.NewInt(2)}},
		"d of 1 with the point -G":           {key: &ecdsa.PrivateKey{PublicKey: ecdsa.PublicKey{Curve: elliptic.P256(), X: params.Gx, Y: new(big.Int).Sub(params.P, params.Gy)}, D: big.NewInt(1)}},
	}

	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			err := CheckECDSAPrivateKey(test.key, elliptic.P256())
			if test.accept {
				if err != nil {
					t.Errorf("[RFC 7518 6.2.2.1] %s is one consistent key and must be accepted, got %v", name, err)
				}
				return
			}
			if !errors.Is(err, joseerror.ErrInvalidPrivateKey) {
				t.Errorf("[RFC 7518 6.2.2.1] d is the private key value of the point, so a signer must refuse %s with ErrInvalidPrivateKey, got %v", name, err)
			}
		})
	}
}

func TestCheckRSAPrivateKey_RefusesADThatDoesNotInvertE(t *testing.T) {
	a, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	b, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	wrongD := new(big.Int).Sub(a.D, big.NewInt(2))

	tests := map[string]struct {
		key    *rsa.PrivateKey
		accept bool
	}{
		"a generated key":                            {key: a, accept: true},
		"a generated key's n, e and d alone":         {key: &rsa.PrivateKey{PublicKey: a.PublicKey, D: a.D}, accept: true},
		"no primes and a d that does not invert e":   {key: &rsa.PrivateKey{PublicKey: a.PublicKey, D: wrongD}},
		"both primes and a d that does not invert e": {key: &rsa.PrivateKey{PublicKey: a.PublicKey, D: wrongD, Primes: a.Primes}},
		"the primes of another key":                  {key: &rsa.PrivateKey{PublicKey: a.PublicKey, D: a.D, Primes: b.Primes}},
		"a nil prime":                                {key: &rsa.PrivateKey{PublicKey: a.PublicKey, D: a.D, Primes: []*big.Int{a.Primes[0], nil}}},
		"a zero prime":                               {key: &rsa.PrivateKey{PublicKey: a.PublicKey, D: a.D, Primes: []*big.Int{big.NewInt(0), a.Primes[1]}}},
		"a negative prime":                           {key: &rsa.PrivateKey{PublicKey: a.PublicKey, D: a.D, Primes: []*big.Int{a.Primes[0], new(big.Int).Neg(a.Primes[1])}}},
	}

	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			var err error
			func() {
				defer func() {
					if r := recover(); r != nil {
						t.Fatalf("[RFC 8017 3.2] CheckRSAPrivateKey must refuse %s rather than panic, got %v", name, r)
					}
				}()
				err = CheckRSAPrivateKey(test.key)
			}()
			if test.accept {
				if err != nil {
					t.Errorf("[RFC 8017 3.2] %s is one consistent key and must be accepted, got %v", name, err)
				}
				return
			}
			if !errors.Is(err, joseerror.ErrInvalidPrivateKey) {
				t.Errorf("[RFC 8017 3.2] e*d is 1 mod lambda(n) and n is the product of the primes, so a signer must refuse %s with ErrInvalidPrivateKey, got %v", name, err)
			}
		})
	}
}

func TestCheckEd25519PrivateKey_RefusesASeedWhosePublicKeyIsNotTheKeys(t *testing.T) {
	_, a, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	_, b, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	mixed := append(append([]byte{}, a[:ed25519.SeedSize]...), b[ed25519.SeedSize:]...)

	tests := map[string]struct {
		key    []byte
		accept bool
	}{
		"a generated key": {key: a, accept: true},
		"the seed of one key, the public of another": {key: mixed},
		"a seed alone":   {key: a[:ed25519.SeedSize]},
		"one octet over": {key: append(append([]byte{}, a...), 0)},
		"none":           {key: nil},
	}

	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			err := CheckEd25519PrivateKey(test.key)
			if test.accept {
				if err != nil {
					t.Errorf("[RFC 8032 5.1.5] %s is a seed and the public key derived from it, so it must be accepted, got %v", name, err)
				}
				return
			}
			if !errors.Is(err, joseerror.ErrInvalidPrivateKey) {
				t.Errorf("[RFC 8032 5.1.5] the public key is derived from the seed, so %s must be refused with ErrInvalidPrivateKey, got %v", name, err)
			}
		})
	}
}

func sameRSAPrimes(got, want []*big.Int) bool {
	if len(got) != 2 || len(want) != 2 || got[0] == nil || got[1] == nil {
		return false
	}
	return got[0].Cmp(want[0]) == 0 && got[1].Cmp(want[1]) == 0 || got[0].Cmp(want[1]) == 0 && got[1].Cmp(want[0]) == 0
}

func TestCompleteRSAPrivateKey_RecoversThePrimesOfAKeyWithNone(t *testing.T) {
	for _, bits := range []int{2048, 3072} {
		generated, err := rsa.GenerateKey(rand.Reader, bits)
		if err != nil {
			t.Fatal(err)
		}
		t.Run(big.NewInt(int64(bits)).String()+" bits", func(t *testing.T) {
			dOnly := &rsa.PrivateKey{PublicKey: generated.PublicKey, D: generated.D}
			completed, err := CompleteRSAPrivateKey(dOnly)
			if err != nil {
				t.Fatalf("[SP 800-56B Rev. 2 C.1 step 6] a two-prime key whose d inverts e must have its primes recovered, got %v", err)
			}
			if !sameRSAPrimes(completed.Primes, generated.Primes) {
				t.Errorf("[SP 800-56B Rev. 2 C.1 step 5] the recovered primes must be the ones crypto/rsa generated, in either order (note 3), got %v", completed.Primes)
			}
			if completed.Precomputed.Dp == nil || completed.Precomputed.Dq == nil || completed.Precomputed.Qinv == nil {
				t.Errorf("[RFC 8017 3.2] the completed key must carry its CRT values so it signs with them, got %+v", completed.Precomputed)
			}
			if completed.D == dOnly.D || completed.N == dOnly.N {
				t.Error("[robustness] the completed key must share no memory with the caller's key")
			}
			if dOnly.Primes != nil {
				t.Errorf("[robustness] the caller's key must not be changed, got primes %v", dOnly.Primes)
			}
		})
	}
}

func TestCompleteRSAPrivateKey_KeepsTheCallersPrimesWhenItHasThem(t *testing.T) {
	generated, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	completed, err := CompleteRSAPrivateKey(generated)
	if err != nil {
		t.Fatalf("[RFC 8017 3.2] a generated key must be accepted, got %v", err)
	}
	if !sameRSAPrimes(completed.Primes, generated.Primes) || completed.Primes[0] == generated.Primes[0] {
		t.Errorf("[RFC 8017 3.2] the completed key must hold copies of the caller's own primes, got %v", completed.Primes)
	}
}

func TestCompleteRSAPrivateKey_AcceptsDModuloLambdaAndModuloPhi(t *testing.T) {
	generated, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	one := big.NewInt(1)
	pMinus, qMinus := new(big.Int).Sub(generated.Primes[0], one), new(big.Int).Sub(generated.Primes[1], one)
	phi := new(big.Int).Mul(pMinus, qMinus)
	lambda := new(big.Int).Div(phi, new(big.Int).GCD(nil, nil, pMinus, qMinus))
	e := big.NewInt(int64(generated.E))

	dLambda := new(big.Int).ModInverse(e, lambda)
	tests := map[string]*big.Int{
		"d = e^-1 mod lambda(n)":                 dLambda,
		"d = e^-1 mod phi(n)":                    new(big.Int).ModInverse(e, phi),
		"d = e^-1 mod lambda(n), plus lambda(n)": new(big.Int).Add(dLambda, lambda),
	}

	for name, d := range tests {
		t.Run(name, func(t *testing.T) {
			completed, err := CompleteRSAPrivateKey(&rsa.PrivateKey{PublicKey: generated.PublicKey, D: d})
			if err != nil {
				t.Fatalf("[SP 800-56B Rev. 2 C.1 assumptions] de is 1 mod lambda(n) for %s, so its primes must be recovered, got %v", name, err)
			}
			if !sameRSAPrimes(completed.Primes, generated.Primes) {
				t.Errorf("[SP 800-56B Rev. 2 C.1 step 5] the recovered primes must be the generated ones, got %v", completed.Primes)
			}
			if completed.D.Cmp(d) != 0 {
				t.Errorf("[RFC 8017 3.2] the completed key must keep the caller's d, got %v", completed.D)
			}
		})
	}
}

func TestCompleteRSAPrivateKey_RefusesAKeyWithNoPrimesWhoseModulusIsNotTwoPrimes(t *testing.T) {
	threePrime, err := rsa.GenerateMultiPrimeKey(rand.Reader, 3, 2048) //nolint:staticcheck
	if err != nil {
		t.Fatal(err)
	}
	dOnly := &rsa.PrivateKey{PublicKey: threePrime.PublicKey, D: threePrime.D}
	if completed, err := CompleteRSAPrivateKey(dOnly); !errors.Is(err, joseerror.ErrInvalidPrivateKey) {
		t.Errorf("[SP 800-56B Rev. 2 C.1 assumptions] n must be the product of two primes, so a three-prime modulus with no primes listed must be refused with ErrInvalidPrivateKey, got %v and %v", err, completed)
	}
	if err := CheckRSAPrivateKey(dOnly); !errors.Is(err, joseerror.ErrInvalidPrivateKey) {
		t.Errorf("[SP 800-56B Rev. 2 C.1 assumptions] CheckRSAPrivateKey must refuse what CompleteRSAPrivateKey refuses, got %v", err)
	}
}

func TestCompleteRSAPrivateKey_RefusesWhatCheckRSAPrivateKeyRefuses(t *testing.T) {
	generated, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	tests := map[string]*rsa.PrivateKey{
		"a nil key": {},
		"no primes and a d that does not invert e": {PublicKey: generated.PublicKey, D: new(big.Int).Sub(generated.D, big.NewInt(2))},
		"no primes and a d of one":                 {PublicKey: generated.PublicKey, D: big.NewInt(1)},
		"an exponent of one":                       {PublicKey: rsa.PublicKey{N: generated.N, E: 1}, D: generated.D},
	}
	tests["a nil key"] = nil

	for name, key := range tests {
		t.Run(name, func(t *testing.T) {
			completed, err := CompleteRSAPrivateKey(key)
			if !errors.Is(err, joseerror.ErrInvalidPrivateKey) {
				t.Errorf("[SP 800-56B Rev. 2 C.1 step 4] %s is not a key whose primes can be recovered, so it must be refused with ErrInvalidPrivateKey, got %v", name, err)
			}
			if completed != nil {
				t.Errorf("[SP 800-56B Rev. 2 C.1 step 4] no key may be returned alongside the refusal, got %v", completed)
			}
		})
	}
}

type chosenRandom struct {
	values []byte
	then   byte
	reads  int
}

func (c *chosenRandom) Read(b []byte) (int, error) {
	for i := range b {
		c.reads++
		if len(c.values) > 0 {
			b[i] = c.values[0]
			c.values = c.values[1:]
			continue
		}
		b[i] = c.then
	}
	return len(b), nil
}

func TestRecoverRSAPrimes_FollowsSP80056BAppendixC1(t *testing.T) {
	n := big.NewInt(85)
	tests := map[string]struct {
		d         int64
		random    *chosenRandom
		found     bool
		wantReads int
		clause    string
	}{
		"a g whose y is 1 or n-1 moves to the next g":               {d: 7, random: &chosenRandom{values: []byte{1, 84, 16}}, found: true, clause: "SP 800-56B Rev. 2 C.1 step 3c"},
		"a g whose square is n-1 moves to the next g":               {d: 7, random: &chosenRandom{values: []byte{13, 16}}, found: true, clause: "SP 800-56B Rev. 2 C.1 step 3d.iii"},
		"a g whose root of 1 shows only at the last square is used": {d: 7, random: &chosenRandom{values: []byte{3}, then: 1}, found: true, clause: "SP 800-56B Rev. 2 C.1 steps 3e and 3f"},
		"100 values of g that reveal nothing find no primes":        {d: 7, random: &chosenRandom{then: 1}, wantReads: 100, clause: "SP 800-56B Rev. 2 C.1 steps 3 and 4"},
		"an odd de-1 finds no primes and draws no g":                {d: 6, random: &chosenRandom{then: 16}, wantReads: 0, clause: "SP 800-56B Rev. 2 C.1 step 1"},
	}

	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			primes, err := recoverRSAPrimes(test.random, n, 7, big.NewInt(test.d))
			if !test.found {
				if !errors.Is(err, joseerror.ErrInvalidPrivateKey) || primes != nil {
					t.Errorf("[%s] %s, so the output must be \"prime factors not found\", got %v and %v", test.clause, name, primes, err)
				}
				if test.random.reads != test.wantReads {
					t.Errorf("[%s] %s after %d draws of g, got %d", test.clause, name, test.wantReads, test.random.reads)
				}
				return
			}
			if err != nil {
				t.Fatalf("[%s] 85 is 5 times 17 and 7 times 7 is 1 mod lambda(85) = 16, so the primes must be found, got %v", test.clause, err)
			}
			if !sameRSAPrimes(primes, []*big.Int{big.NewInt(5), big.NewInt(17)}) {
				t.Errorf("[%s] the primes of 85 are 5 and 17, got %v", test.clause, primes)
			}
		})
	}
}

func TestRecoverRSAPrimes_RefusesWhenNoRandomGCanBeDrawn(t *testing.T) {
	primes, err := recoverRSAPrimes(iotest.ErrReader(errors.New("no randomness")), big.NewInt(85), 7, big.NewInt(7))
	if !errors.Is(err, joseerror.ErrInvalidPrivateKey) || primes != nil {
		t.Errorf("[SP 800-56B Rev. 2 C.1 step 3a] each try generates a random g, so a failed draw must refuse the key with ErrInvalidPrivateKey, got %v and %v", primes, err)
	}
}
