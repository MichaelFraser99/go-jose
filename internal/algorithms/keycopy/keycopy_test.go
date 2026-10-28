package keycopy

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"math/big"
	"testing"
)

func TestECDSAPrivateKey_SharesNoMemoryWithTheOriginal(t *testing.T) {
	original, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	encoded, err := x509.MarshalECPrivateKey(original)
	if err != nil {
		t.Fatal(err)
	}
	want, err := x509.ParseECPrivateKey(encoded)
	if err != nil {
		t.Fatal(err)
	}
	copied := ECDSAPrivateKey(original)
	original.D.SetInt64(1) //nolint:staticcheck
	original.X.SetInt64(2) //nolint:staticcheck
	original.Y.SetInt64(3) //nolint:staticcheck
	if !copied.Equal(want) {
		t.Error("[RFC 7518 3.4] changing the original key in place must leave its copy as it was")
	}
}

func TestRSAPrivateKey_SharesNoMemoryWithTheOriginal(t *testing.T) {
	original, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	want, err := x509.ParsePKCS1PrivateKey(x509.MarshalPKCS1PrivateKey(original))
	if err != nil {
		t.Fatal(err)
	}
	copied := RSAPrivateKey(original)
	original.N.SetInt64(1)
	original.D.SetInt64(2)
	original.Primes[0].SetInt64(3)
	original.Primes[1].SetInt64(5)
	if !copied.Equal(want) {
		t.Error("[RFC 7518 3.3] changing the original key in place must leave its copy as it was")
	}
	if copied.Precomputed.Dp == nil || copied.Precomputed.Dp.Cmp(want.Precomputed.Dp) != 0 || copied.Precomputed.Qinv.Cmp(want.Precomputed.Qinv) != 0 {
		t.Error("[RFC 8017 3.2] the copy carries the CRT values of its own primes, ready to sign with")
	}
	if copied.Validate() != nil {
		t.Errorf("[RFC 8017 3.2] the copy of a valid key must be a valid key, got %v", copied.Validate())
	}
}

func TestRSAPrivateKey_CopiesAKeyWithoutPrimesOrWithANilPrime(t *testing.T) {
	generated, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256([]byte("eyJhbGciOiJSUzI1NiJ9.e30"))
	tests := map[string]struct {
		primes []*big.Int
		signs  bool
	}{
		"no primes":   {nil, true},
		"a nil prime": {[]*big.Int{nil, generated.Primes[1]}, false},
	}
	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			primes := tc.primes
			original := &rsa.PrivateKey{PublicKey: generated.PublicKey, D: generated.D, Primes: primes}
			copied := RSAPrivateKey(original)
			if copied.N.Cmp(generated.N) != 0 || copied.D.Cmp(generated.D) != 0 || len(copied.Primes) != len(primes) {
				t.Fatal("[RFC 7518 6.3.2] the copy keeps the modulus, the private exponent and the number of primes")
			}
			for i := range primes {
				if (copied.Primes[i] == nil) != (primes[i] == nil) {
					t.Errorf("[RFC 7518 6.3.2] the copy keeps a nil prime nil and a set prime set, prime %d", i)
				}
			}
			signature, err := rsa.SignPKCS1v15(nil, copied, crypto.SHA256, digest[:])
			signs := err == nil && rsa.VerifyPKCS1v15(&generated.PublicKey, crypto.SHA256, digest[:], signature) == nil
			if signs != tc.signs {
				t.Errorf("[RFC 7518 6.3.2] d is the only required private member, so a copy without primes signs and one with a nil prime cannot, want %v, got %v (%v)", tc.signs, signs, err)
			}
		})
	}
}
