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
