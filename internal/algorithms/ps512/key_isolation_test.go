package ps512

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"sync"
	"testing"
)

const isolationHash = crypto.SHA512

var isolationKeys = sync.OnceValues(func() ([]*rsa.PrivateKey, error) {
	var keys []*rsa.PrivateKey
	for _, bits := range []int{2048, 2048, 1536} {
		key, err := rsa.GenerateKey(rand.Reader, bits)
		if err != nil {
			return nil, err
		}
		keys = append(keys, key)
	}
	return keys, nil
})

func isolationKey(t *testing.T, index int) *rsa.PrivateKey {
	t.Helper()
	keys, err := isolationKeys()
	if err != nil {
		t.Fatal(err)
	}
	key, err := x509.ParsePKCS1PrivateKey(x509.MarshalPKCS1PrivateKey(keys[index]))
	if err != nil {
		t.Fatal(err)
	}
	return key
}

func isolationDigest(message []byte) []byte {
	h := isolationHash.New()
	h.Write(message)
	return h.Sum(nil)
}

func isolationSignature(t *testing.T, key *rsa.PrivateKey, message []byte) []byte {
	t.Helper()
	signature, err := rsa.SignPSS(rand.Reader, key, isolationHash, isolationDigest(message), &rsa.PSSOptions{SaltLength: isolationHash.Size()})
	if err != nil {
		t.Fatal(err)
	}
	return signature
}

func isolationVerifies(public *rsa.PublicKey, message, signature []byte) bool {
	return rsa.VerifyPSS(public, isolationHash, isolationDigest(message), signature, &rsa.PSSOptions{SaltLength: isolationHash.Size()}) == nil
}

func TestSigner_KeepsItsOwnCopyOfTheKey(t *testing.T) {
	message := []byte("eyJhbGciOiJSUzI1NiJ9.e30")
	tests := map[string]func(given *rsa.PrivateKey, signer *Signer, other *rsa.PrivateKey){
		"the caller's key overwritten": func(given *rsa.PrivateKey, _ *Signer, other *rsa.PrivateKey) {
			*given = *other
		},
		"the caller's modulus changed in place": func(given *rsa.PrivateKey, _ *Signer, other *rsa.PrivateKey) {
			given.N.Set(other.N)
		},
		"the caller's private exponent and primes changed in place": func(given *rsa.PrivateKey, _ *Signer, other *rsa.PrivateKey) {
			given.D.Set(other.D)
			given.Primes[0].Set(other.Primes[0])
			given.Primes[1].Set(other.Primes[1])
			given.Precomputed = rsa.PrecomputedValues{}
		},
		"the key Public returned overwritten": func(_ *rsa.PrivateKey, signer *Signer, other *rsa.PrivateKey) {
			*signer.Public().(*rsa.PublicKey) = other.PublicKey
		},
		"the modulus Public returned changed in place": func(_ *rsa.PrivateKey, signer *Signer, other *rsa.PrivateKey) {
			signer.Public().(*rsa.PublicKey).N.Set(other.N)
		},
	}
	for name, mutate := range tests {
		t.Run(name, func(t *testing.T) {
			given := isolationKey(t, 0)
			original := isolationKey(t, 0)
			signer, err := NewSignerFromPrivateKey(given)
			if err != nil {
				t.Fatal(err)
			}
			mutate(given, signer, isolationKey(t, 1))
			if !signer.Public().(*rsa.PublicKey).Equal(&original.PublicKey) {
				t.Error("[RFC 7518 3.5] a signer reports the public half of the key it was built with")
			}
			signature, err := signer.Sign(rand.Reader, message, nil)
			if err != nil {
				t.Fatal(err)
			}
			if !isolationVerifies(&original.PublicKey, message, signature) {
				t.Error("[RFC 7518 3.5] a signer signs with the key it was built with, not with a key changed after construction")
			}
		})
	}
}

func TestValidator_KeepsItsOwnCopyOfTheKey(t *testing.T) {
	message := []byte("eyJhbGciOiJSUzI1NiJ9.e30")
	tests := map[string]func(given *rsa.PublicKey, validator *Validator, other *rsa.PrivateKey){
		"the caller's key overwritten": func(given *rsa.PublicKey, _ *Validator, other *rsa.PrivateKey) {
			*given = other.PublicKey
		},
		"the caller's modulus changed in place": func(given *rsa.PublicKey, _ *Validator, other *rsa.PrivateKey) {
			given.N.Set(other.N)
		},
		"the key Public returned overwritten": func(_ *rsa.PublicKey, validator *Validator, other *rsa.PrivateKey) {
			*validator.Public().(*rsa.PublicKey) = other.PublicKey
		},
		"the modulus Public returned changed in place": func(_ *rsa.PublicKey, validator *Validator, other *rsa.PrivateKey) {
			validator.Public().(*rsa.PublicKey).N.Set(other.N)
		},
	}
	for name, mutate := range tests {
		t.Run(name, func(t *testing.T) {
			key := isolationKey(t, 0)
			smaller := isolationKey(t, 2)
			given := &isolationKey(t, 0).PublicKey
			validator, err := NewValidator(given)
			if err != nil {
				t.Fatal(err)
			}
			mutate(given, validator, smaller)
			if !validator.Public().(*rsa.PublicKey).Equal(&key.PublicKey) {
				t.Error("[RFC 7518 3.5] a validator reports the key it was built with")
			}
			valid, err := validator.ValidateSignature(message, isolationSignature(t, key, message))
			if err != nil || !valid {
				t.Errorf("[RFC 7518 3.5] a signature by the key the validator was built with must verify, got %v and %v", valid, err)
			}
			valid, _ = validator.ValidateSignature(message, isolationSignature(t, smaller, message))
			if valid {
				t.Error("[RFC 7518 3.5] a signature by a 1536-bit key swapped in after construction must not verify, because a key of 2048 bits or larger MUST be used")
			}
		})
	}
}

func TestSign_AcceptsANilReader(t *testing.T) {
	key := isolationKey(t, 0)
	signer, err := NewSignerFromPrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	message := []byte("eyJhbGciOiJSUzI1NiJ9.e30")
	signature, err := signer.Sign(nil, message, nil)
	if err != nil {
		t.Fatal(err)
	}
	if !isolationVerifies(&key.PublicKey, message, signature) {
		t.Error("[RFC 7518 3.5] a signature made with a nil reader must verify under the signer's key")
	}
}
