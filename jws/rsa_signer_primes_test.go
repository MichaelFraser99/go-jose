package jws

import (
	"crypto/rand"
	"crypto/rsa"
	"reflect"
	"testing"
)

func TestGetSignerFromPrivateKey_AnRSAKeyWithNoPrimesSignsWithItsRecoveredPrimes(t *testing.T) {
	generated, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	dOnly := &rsa.PrivateKey{PublicKey: generated.PublicKey, D: generated.D}

	for _, alg := range rsaAlgorithms {
		t.Run(alg.String(), func(t *testing.T) {
			signer, err := GetSignerFromPrivateKey(alg, dOnly)
			if err != nil {
				t.Fatalf("[RFC 7518 6.3.2] d is the only REQUIRED private member, so a two-prime key with no primes listed must build a signer, got %v", err)
			}
			held := reflect.ValueOf(signer).Elem().FieldByName("privateKey")
			if !held.IsValid() || held.IsNil() {
				t.Fatalf("the %s signer must hold its private key in a privateKey field", alg)
			}
			if primes := held.Elem().FieldByName("Primes").Len(); primes != 2 {
				t.Errorf("[SP 800-56B Rev. 2 C.1 step 6] the %s signer must keep the two primes recovered from n, e and d, so it signs with the CRT, got %d", alg, primes)
			}
			if dOnly.Primes != nil {
				t.Errorf("[robustness] building a signer must not change the caller's key, got primes %v", dOnly.Primes)
			}
			input := []byte("the signing input")
			signature, err := signer.Sign(rand.Reader, input, nil)
			if err != nil {
				t.Fatalf("the %s signer must sign, got %v", alg, err)
			}
			validator, err := GetValidator(alg, &generated.PublicKey)
			if err != nil {
				t.Fatal(err)
			}
			if valid, err := validator.ValidateSignature(input, signature); err != nil || !valid {
				t.Errorf("[RFC 7518 3.3] the generated key's public half must verify what the %s signer signs, got %t and %v", alg, valid, err)
			}
		})
	}
}
