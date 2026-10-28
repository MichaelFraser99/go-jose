package es512

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"math/big"
	"testing"
)

var (
	isolationCurve = elliptic.P521()
	isolationHash  = crypto.SHA512
)

func isolationKey(t *testing.T) *ecdsa.PrivateKey {
	t.Helper()
	key, err := ecdsa.GenerateKey(isolationCurve, rand.Reader)
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

func isolationSignature(t *testing.T, key *ecdsa.PrivateKey, message []byte) []byte {
	t.Helper()
	r, s, err := ecdsa.Sign(rand.Reader, key, isolationDigest(message))
	if err != nil {
		t.Fatal(err)
	}
	size := (isolationCurve.Params().BitSize + 7) / 8
	signature := make([]byte, 2*size)
	r.FillBytes(signature[:size])
	s.FillBytes(signature[size:])
	return signature
}

func isolationVerifies(public *ecdsa.PublicKey, message, signature []byte) bool {
	size := len(signature) / 2
	r := new(big.Int).SetBytes(signature[:size])
	s := new(big.Int).SetBytes(signature[size:])
	return ecdsa.Verify(public, isolationDigest(message), r, s)
}

func publicCopy(t *testing.T, key *ecdsa.PublicKey) *ecdsa.PublicKey {
	t.Helper()
	encoded, err := key.Bytes()
	if err != nil {
		t.Fatal(err)
	}
	public, err := ecdsa.ParseUncompressedPublicKey(isolationCurve, encoded)
	if err != nil {
		t.Fatal(err)
	}
	return public
}

func TestSigner_KeepsItsOwnCopyOfTheKey(t *testing.T) {
	message := []byte("eyJhbGciOiJFUzI1NiJ9.e30")
	tests := map[string]func(given *ecdsa.PrivateKey, signer *Signer, other *ecdsa.PrivateKey){
		"the caller's key overwritten": func(given *ecdsa.PrivateKey, _ *Signer, other *ecdsa.PrivateKey) {
			*given = *other
		},
		"the caller's scalar changed in place": func(given *ecdsa.PrivateKey, _ *Signer, other *ecdsa.PrivateKey) {
			given.D.Set(other.D) //nolint:staticcheck
		},
		"the key Public returned overwritten": func(_ *ecdsa.PrivateKey, signer *Signer, other *ecdsa.PrivateKey) {
			*signer.Public().(*ecdsa.PublicKey) = other.PublicKey
		},
		"the point Public returned changed in place": func(_ *ecdsa.PrivateKey, signer *Signer, other *ecdsa.PrivateKey) {
			signer.Public().(*ecdsa.PublicKey).X.Set(other.X) //nolint:staticcheck
		},
	}
	for name, mutate := range tests {
		t.Run(name, func(t *testing.T) {
			given := isolationKey(t)
			original := publicCopy(t, &given.PublicKey)
			signer, err := NewSignerFromPrivateKey(given)
			if err != nil {
				t.Fatal(err)
			}
			mutate(given, signer, isolationKey(t))
			if !signer.Public().(*ecdsa.PublicKey).Equal(original) {
				t.Errorf("[RFC 7518 3.4] a signer reports the public half of the key it was built with, got %v", signer.Public())
			}
			signature, err := signer.Sign(rand.Reader, message, nil)
			if err != nil {
				t.Fatal(err)
			}
			if !isolationVerifies(original, message, signature) {
				t.Error("[RFC 7518 3.4] a signer signs with the key it was built with, not with a key changed after construction")
			}
		})
	}
}

func TestValidator_KeepsItsOwnCopyOfTheKey(t *testing.T) {
	message := []byte("eyJhbGciOiJFUzI1NiJ9.e30")
	tests := map[string]func(given *ecdsa.PublicKey, validator *Validator, other *ecdsa.PrivateKey){
		"the caller's key overwritten": func(given *ecdsa.PublicKey, _ *Validator, other *ecdsa.PrivateKey) {
			*given = other.PublicKey
		},
		"the caller's point changed in place": func(given *ecdsa.PublicKey, _ *Validator, other *ecdsa.PrivateKey) {
			given.X.Set(other.X) //nolint:staticcheck
			given.Y.Set(other.Y) //nolint:staticcheck
		},
		"the key Public returned overwritten": func(_ *ecdsa.PublicKey, validator *Validator, other *ecdsa.PrivateKey) {
			*validator.Public().(*ecdsa.PublicKey) = other.PublicKey
		},
		"the point Public returned changed in place": func(_ *ecdsa.PublicKey, validator *Validator, other *ecdsa.PrivateKey) {
			public := validator.Public().(*ecdsa.PublicKey)
			public.X.Set(other.X) //nolint:staticcheck
			public.Y.Set(other.Y) //nolint:staticcheck
		},
	}
	for name, mutate := range tests {
		t.Run(name, func(t *testing.T) {
			key := isolationKey(t)
			other := isolationKey(t)
			given := publicCopy(t, &key.PublicKey)
			validator, err := NewValidator(given)
			if err != nil {
				t.Fatal(err)
			}
			mutate(given, validator, other)
			if !validator.Public().(*ecdsa.PublicKey).Equal(&key.PublicKey) {
				t.Errorf("[RFC 7518 3.4] a validator reports the key it was built with, got %v", validator.Public())
			}
			valid, err := validator.ValidateSignature(message, isolationSignature(t, key, message))
			if err != nil || !valid {
				t.Errorf("[RFC 7518 3.4] a signature by the key the validator was built with must verify, got %v and %v", valid, err)
			}
			valid, err = validator.ValidateSignature(message, isolationSignature(t, other, message))
			if err != nil || valid {
				t.Errorf("[RFC 7518 3.4] a signature by a key swapped in after construction must not verify, got %v and %v", valid, err)
			}
		})
	}
}

func TestSign_AcceptsANilReader(t *testing.T) {
	key := isolationKey(t)
	signer, err := NewSignerFromPrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	message := []byte("eyJhbGciOiJFUzI1NiJ9.e30")
	signature, err := signer.Sign(nil, message, nil)
	if err != nil {
		t.Fatal(err)
	}
	if !isolationVerifies(&key.PublicKey, message, signature) {
		t.Error("[RFC 7518 3.4] a signature made with a nil reader must verify under the signer's key")
	}
}
