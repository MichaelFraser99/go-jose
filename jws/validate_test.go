package jws

import (
	"crypto"
	"crypto/rand"
	"encoding/json"
	"github.com/MichaelFraser99/go-jose/internal/algorithms/es256"
	"github.com/MichaelFraser99/go-jose/internal/algorithms/es384"
	"github.com/MichaelFraser99/go-jose/internal/algorithms/es512"
	"github.com/MichaelFraser99/go-jose/internal/algorithms/ps256"
	"github.com/MichaelFraser99/go-jose/internal/algorithms/ps384"
	"github.com/MichaelFraser99/go-jose/internal/algorithms/ps512"
	"github.com/MichaelFraser99/go-jose/internal/algorithms/rs256"
	"github.com/MichaelFraser99/go-jose/internal/algorithms/rs384"
	"github.com/MichaelFraser99/go-jose/internal/algorithms/rs512"
	"github.com/MichaelFraser99/go-jose/jwk"
	"github.com/MichaelFraser99/go-jose/model"
	"testing"
)

const (
	signedString = "test-input"
)

func TestGetValidator(t *testing.T) {
	tests := []struct {
		algorithm model.Algorithm
		publicKey func() (crypto.PublicKey, []byte)
		verify    func(t *testing.T, validator model.Validator, signature []byte, err error)
	}{
		{
			algorithm: model.ES256,
			publicKey: func() (crypto.PublicKey, []byte) {
				signer, _ := es256.NewSigner()
				digest, _ := signer.Sign(rand.Reader, []byte(signedString), nil)
				return signer.Public(), digest
			},
			verify: func(t *testing.T, validator model.Validator, signature []byte, err error) {
				if err != nil {
					t.Fatalf("no error expected: %s", err.Error())
				}
				if validator == nil {
					t.Error("validator must not be nil")
				}
				valid, err := validator.ValidateSignature([]byte(signedString), signature)
				if err != nil {
					t.Fatalf("failed to validate signature: %s", err.Error())
				}
				if !valid {
					t.Error("failed to validate signature")
				}
			},
		},
		{
			algorithm: model.ES384,
			publicKey: func() (crypto.PublicKey, []byte) {
				signer, _ := es384.NewSigner()
				digest, _ := signer.Sign(rand.Reader, []byte(signedString), nil)
				return signer.Public(), digest
			},
			verify: func(t *testing.T, validator model.Validator, signature []byte, err error) {
				if err != nil {
					t.Fatalf("no error expected: %s", err.Error())
				}
				if validator == nil {
					t.Error("validator must not be nil")
				}
				valid, err := validator.ValidateSignature([]byte(signedString), signature)
				if err != nil {
					t.Fatalf("failed to validate signature: %s", err.Error())
				}
				if !valid {
					t.Error("failed to validate signature")
				}
			},
		},
		{
			algorithm: model.ES512,
			publicKey: func() (crypto.PublicKey, []byte) {
				signer, _ := es512.NewSigner()
				digest, _ := signer.Sign(rand.Reader, []byte(signedString), nil)
				return signer.Public(), digest
			},
			verify: func(t *testing.T, validator model.Validator, signature []byte, err error) {
				if err != nil {
					t.Fatalf("no error expected: %s", err.Error())
				}
				if validator == nil {
					t.Error("validator must not be nil")
				}
				valid, err := validator.ValidateSignature([]byte(signedString), signature)
				if err != nil {
					t.Fatalf("failed to validate signature: %s", err.Error())
				}
				if !valid {
					t.Error("failed to validate signature")
				}
			},
		},
		{
			algorithm: model.RS256,
			publicKey: func() (crypto.PublicKey, []byte) {
				signer, _ := rs256.NewSigner(2048)
				digest, _ := signer.Sign(rand.Reader, []byte(signedString), nil)
				return signer.Public(), digest
			},
			verify: func(t *testing.T, validator model.Validator, signature []byte, err error) {
				if err != nil {
					t.Fatalf("no error expected: %s", err.Error())
				}
				if validator == nil {
					t.Error("validator must not be nil")
				}
				valid, err := validator.ValidateSignature([]byte(signedString), signature)
				if err != nil {
					t.Fatalf("failed to validate signature: %s", err.Error())
				}
				if !valid {
					t.Error("failed to validate signature")
				}
			},
		},
		{
			algorithm: model.RS384,
			publicKey: func() (crypto.PublicKey, []byte) {
				signer, _ := rs384.NewSigner(2048)
				digest, _ := signer.Sign(rand.Reader, []byte(signedString), nil)
				return signer.Public(), digest
			},
			verify: func(t *testing.T, validator model.Validator, signature []byte, err error) {
				if err != nil {
					t.Fatalf("no error expected: %s", err.Error())
				}
				if validator == nil {
					t.Error("validator must not be nil")
				}
				valid, err := validator.ValidateSignature([]byte(signedString), signature)
				if err != nil {
					t.Fatalf("failed to validate signature: %s", err.Error())
				}
				if !valid {
					t.Error("failed to validate signature")
				}
			},
		},
		{
			algorithm: model.RS512,
			publicKey: func() (crypto.PublicKey, []byte) {
				signer, _ := rs512.NewSigner(2048)
				digest, _ := signer.Sign(rand.Reader, []byte(signedString), nil)
				return signer.Public(), digest
			},
			verify: func(t *testing.T, validator model.Validator, signature []byte, err error) {
				if err != nil {
					t.Fatalf("no error expected: %s", err.Error())
				}
				if validator == nil {
					t.Error("validator must not be nil")
				}
				valid, err := validator.ValidateSignature([]byte(signedString), signature)
				if err != nil {
					t.Fatalf("failed to validate signature: %s", err.Error())
				}
				if !valid {
					t.Error("failed to validate signature")
				}
			},
		},
		{
			algorithm: model.PS256,
			publicKey: func() (crypto.PublicKey, []byte) {
				signer, _ := ps256.NewSigner(2048)
				digest, _ := signer.Sign(rand.Reader, []byte(signedString), nil)
				return signer.Public(), digest
			},
			verify: func(t *testing.T, validator model.Validator, signature []byte, err error) {
				if err != nil {
					t.Fatalf("no error expected: %s", err.Error())
				}
				if validator == nil {
					t.Error("validator must not be nil")
				}
				valid, err := validator.ValidateSignature([]byte(signedString), signature)
				if err != nil {
					t.Fatalf("failed to validate signature: %s", err.Error())
				}
				if !valid {
					t.Error("failed to validate signature")
				}
			},
		},
		{
			algorithm: model.PS384,
			publicKey: func() (crypto.PublicKey, []byte) {
				signer, _ := ps384.NewSigner(2048)
				digest, _ := signer.Sign(rand.Reader, []byte(signedString), nil)
				return signer.Public(), digest
			},
			verify: func(t *testing.T, validator model.Validator, signature []byte, err error) {
				if err != nil {
					t.Fatalf("no error expected: %s", err.Error())
				}
				if validator == nil {
					t.Error("validator must not be nil")
				}
				valid, err := validator.ValidateSignature([]byte(signedString), signature)
				if err != nil {
					t.Fatalf("failed to validate signature: %s", err.Error())
				}
				if !valid {
					t.Error("failed to validate signature")
				}
			},
		},
		{
			algorithm: model.PS512,
			publicKey: func() (crypto.PublicKey, []byte) {
				signer, _ := ps512.NewSigner(2048)
				digest, _ := signer.Sign(rand.Reader, []byte(signedString), nil)
				return signer.Public(), digest
			},
			verify: func(t *testing.T, validator model.Validator, signature []byte, err error) {
				if err != nil {
					t.Fatalf("no error expected: %s", err.Error())
				}
				if validator == nil {
					t.Error("validator must not be nil")
				}
				valid, err := validator.ValidateSignature([]byte(signedString), signature)
				if err != nil {
					t.Fatalf("failed to validate signature: %s", err.Error())
				}
				if !valid {
					t.Error("failed to validate signature")
				}
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.algorithm.String(), func(t *testing.T) {
			pk, sig := tt.publicKey()
			validator, err := GetValidator(tt.algorithm, pk)
			tt.verify(t, validator, sig, err)
		})
	}
}

func TestGetValidatorFromJwk(t *testing.T) {
	tests := []struct {
		algorithm model.Algorithm
		jwk       func() (map[string]any, []byte)
		verify    func(t *testing.T, validator model.Validator, signature []byte, err error)
	}{
		{
			algorithm: model.ES256,
			jwk: func() (map[string]any, []byte) {
				signer, _ := es256.NewSigner()
				key, _ := jwk.PublicJwk(signer.Public())
				digest, _ := signer.Sign(rand.Reader, []byte(signedString), nil)
				return *key, digest
			},
			verify: func(t *testing.T, validator model.Validator, signature []byte, err error) {
				if err != nil {
					t.Fatalf("no error expected: %s", err.Error())
				}
				if validator == nil {
					t.Error("validator must not be nil")
				}
				valid, err := validator.ValidateSignature([]byte(signedString), signature)
				if err != nil {
					t.Fatalf("failed to validate signature: %s", err.Error())
				}
				if !valid {
					t.Error("failed to validate signature")
				}
			},
		},
		{
			algorithm: model.ES384,
			jwk: func() (map[string]any, []byte) {
				signer, _ := es384.NewSigner()
				key, _ := jwk.PublicJwk(signer.Public())
				digest, _ := signer.Sign(rand.Reader, []byte(signedString), nil)
				return *key, digest
			},
			verify: func(t *testing.T, validator model.Validator, signature []byte, err error) {
				if err != nil {
					t.Fatalf("no error expected: %s", err.Error())
				}
				if validator == nil {
					t.Error("validator must not be nil")
				}
				valid, err := validator.ValidateSignature([]byte(signedString), signature)
				if err != nil {
					t.Fatalf("failed to validate signature: %s", err.Error())
				}
				if !valid {
					t.Error("failed to validate signature")
				}
			},
		},
		{
			algorithm: model.ES512,
			jwk: func() (map[string]any, []byte) {
				signer, _ := es512.NewSigner()
				key, _ := jwk.PublicJwk(signer.Public())
				digest, _ := signer.Sign(rand.Reader, []byte(signedString), nil)
				return *key, digest
			},
			verify: func(t *testing.T, validator model.Validator, signature []byte, err error) {
				if err != nil {
					t.Fatalf("no error expected: %s", err.Error())
				}
				if validator == nil {
					t.Error("validator must not be nil")
				}
				valid, err := validator.ValidateSignature([]byte(signedString), signature)
				if err != nil {
					t.Fatalf("failed to validate signature: %s", err.Error())
				}
				if !valid {
					t.Error("failed to validate signature")
				}
			},
		},
		{
			algorithm: model.RS256,
			jwk: func() (map[string]any, []byte) {
				signer, _ := rs256.NewSigner(2048)
				key, _ := jwk.PublicJwk(signer.Public())
				digest, _ := signer.Sign(rand.Reader, []byte(signedString), nil)
				return *key, digest
			},
			verify: func(t *testing.T, validator model.Validator, signature []byte, err error) {
				if err != nil {
					t.Fatalf("no error expected: %s", err.Error())
				}
				if validator == nil {
					t.Error("validator must not be nil")
				}
				valid, err := validator.ValidateSignature([]byte(signedString), signature)
				if err != nil {
					t.Fatalf("failed to validate signature: %s", err.Error())
				}
				if !valid {
					t.Error("failed to validate signature")
				}
			},
		},
		{
			algorithm: model.RS384,
			jwk: func() (map[string]any, []byte) {
				signer, _ := rs384.NewSigner(2048)
				key, _ := jwk.PublicJwk(signer.Public())
				digest, _ := signer.Sign(rand.Reader, []byte(signedString), nil)
				return *key, digest
			},
			verify: func(t *testing.T, validator model.Validator, signature []byte, err error) {
				if err != nil {
					t.Fatalf("no error expected: %s", err.Error())
				}
				if validator == nil {
					t.Error("validator must not be nil")
				}
				valid, err := validator.ValidateSignature([]byte(signedString), signature)
				if err != nil {
					t.Fatalf("failed to validate signature: %s", err.Error())
				}
				if !valid {
					t.Error("failed to validate signature")
				}
			},
		},
		{
			algorithm: model.RS512,
			jwk: func() (map[string]any, []byte) {
				signer, _ := rs512.NewSigner(2048)
				key, _ := jwk.PublicJwk(signer.Public())
				digest, _ := signer.Sign(rand.Reader, []byte(signedString), nil)
				return *key, digest
			},
			verify: func(t *testing.T, validator model.Validator, signature []byte, err error) {
				if err != nil {
					t.Fatalf("no error expected: %s", err.Error())
				}
				if validator == nil {
					t.Error("validator must not be nil")
				}
				valid, err := validator.ValidateSignature([]byte(signedString), signature)
				if err != nil {
					t.Fatalf("failed to validate signature: %s", err.Error())
				}
				if !valid {
					t.Error("failed to validate signature")
				}
			},
		},
		{
			algorithm: model.PS256,
			jwk: func() (map[string]any, []byte) {
				signer, _ := ps256.NewSigner(2048)
				key, _ := jwk.PublicJwk(signer.Public())
				digest, _ := signer.Sign(rand.Reader, []byte(signedString), nil)
				return *key, digest
			},
			verify: func(t *testing.T, validator model.Validator, signature []byte, err error) {
				if err != nil {
					t.Fatalf("no error expected: %s", err.Error())
				}
				if validator == nil {
					t.Error("validator must not be nil")
				}
				valid, err := validator.ValidateSignature([]byte(signedString), signature)
				if err != nil {
					t.Fatalf("failed to validate signature: %s", err.Error())
				}
				if !valid {
					t.Error("failed to validate signature")
				}
			},
		},
		{
			algorithm: model.PS384,
			jwk: func() (map[string]any, []byte) {
				signer, _ := ps384.NewSigner(2048)
				key, _ := jwk.PublicJwk(signer.Public())
				digest, _ := signer.Sign(rand.Reader, []byte(signedString), nil)
				return *key, digest
			},
			verify: func(t *testing.T, validator model.Validator, signature []byte, err error) {
				if err != nil {
					t.Fatalf("no error expected: %s", err.Error())
				}
				if validator == nil {
					t.Error("validator must not be nil")
				}
				valid, err := validator.ValidateSignature([]byte(signedString), signature)
				if err != nil {
					t.Fatalf("failed to validate signature: %s", err.Error())
				}
				if !valid {
					t.Error("failed to validate signature")
				}
			},
		},
		{
			algorithm: model.PS512,
			jwk: func() (map[string]any, []byte) {
				signer, _ := ps512.NewSigner(2048)
				key, _ := jwk.PublicJwk(signer.Public())
				digest, _ := signer.Sign(rand.Reader, []byte(signedString), nil)
				return *key, digest
			},
			verify: func(t *testing.T, validator model.Validator, signature []byte, err error) {
				if err != nil {
					t.Fatalf("no error expected: %s", err.Error())
				}
				if validator == nil {
					t.Error("validator must not be nil")
				}
				valid, err := validator.ValidateSignature([]byte(signedString), signature)
				if err != nil {
					t.Fatalf("failed to validate signature: %s", err.Error())
				}
				if !valid {
					t.Error("failed to validate signature")
				}
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.algorithm.String(), func(t *testing.T) {
			jwkMap, sig := tt.jwk()
			jwkBytes, err := json.Marshal(jwkMap)
			if err != nil {
				t.Fatalf("no error should be thrown: %s", err.Error())
			}
			validator, err := GetValidatorFromJwk(tt.algorithm, jwkBytes)
			tt.verify(t, validator, sig, err)
		})
	}
}
