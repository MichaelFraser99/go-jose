package jws

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"errors"
	"testing"

	"github.com/MichaelFraser99/go-jose/joseerror"
	"github.com/MichaelFraser99/go-jose/jwa"
	"github.com/MichaelFraser99/go-jose/jwk"
	"github.com/MichaelFraser99/go-jose/model"
)

func TestGetValidatorFromJwk_RefusesAJwkMarkedAsNotForVerifying(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	public, err := jwk.PublicJwk(&key.PublicKey)
	if err != nil {
		t.Fatal(err)
	}

	tests := map[string]struct {
		members map[string]any
		accept  bool
		clause  string
	}{
		"no use and no key_ops":            {members: map[string]any{}, accept: true, clause: "RFC 7517 4.2"},
		"use of sig":                       {members: map[string]any{"use": "sig"}, accept: true, clause: "RFC 7517 4.2"},
		"key_ops holding verify":           {members: map[string]any{"key_ops": []any{"verify"}}, accept: true, clause: "RFC 7517 4.3"},
		"key_ops holding sign and verify":  {members: map[string]any{"key_ops": []any{"sign", "verify"}}, accept: true, clause: "RFC 7517 4.3"},
		"use of sig and key_ops of verify": {members: map[string]any{"use": "sig", "key_ops": []any{"verify"}}, accept: true, clause: "RFC 7517 4.3"},
		"use of enc":                       {members: map[string]any{"use": "enc"}, clause: "RFC 7517 4.2"},
		"use of SIG, compared exactly":     {members: map[string]any{"use": "SIG"}, clause: "RFC 7517 4.2"},
		"use that is not a string":         {members: map[string]any{"use": 7}, clause: "RFC 7517 4.2"},
		"key_ops holding only sign":        {members: map[string]any{"key_ops": []any{"sign"}}, clause: "RFC 7517 4.3"},
		"key_ops holding none":             {members: map[string]any{"key_ops": []any{}}, clause: "RFC 7517 4.3"},
		"key_ops that is a string":         {members: map[string]any{"key_ops": "verify"}, clause: "RFC 7517 4.3"},
		"key_ops holding a number":         {members: map[string]any{"key_ops": []any{"verify", 7}}, clause: "RFC 7517 4.3"},
		"key_ops listing verify twice":     {members: map[string]any{"key_ops": []any{"verify", "verify"}}, clause: "RFC 7517 4.3"},
		"key_ops listing sign twice":       {members: map[string]any{"key_ops": []any{"sign", "verify", "sign"}}, clause: "RFC 7517 4.3"},
		"use of sig and key_ops of sign":   {members: map[string]any{"use": "sig", "key_ops": []any{"sign"}}, clause: "RFC 7517 4.3"},
		"use of enc and key_ops of verify": {members: map[string]any{"use": "enc", "key_ops": []any{"verify"}}, clause: "RFC 7517 4.2"},
	}

	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			candidate := map[string]any{}
			for k, v := range *public {
				candidate[k] = v
			}
			for k, v := range test.members {
				candidate[k] = v
			}
			validator, err := GetValidatorFromJwk(jwa.ES256, candidate, nil)
			if test.accept {
				if err != nil || validator == nil {
					t.Fatalf("[%s] a jwk with %s permits verifying, so it must build a validator, got %v", test.clause, name, err)
				}
				return
			}
			if !errors.Is(err, joseerror.ErrInvalidPublicKey) {
				t.Errorf("[%s] a jwk with %s is not marked for verifying signatures, so it must be refused with ErrInvalidPublicKey, got %v", test.clause, name, err)
			}
			if errors.Is(err, joseerror.ErrNoKeyIdentifierMatch) {
				t.Errorf("[%s] GetValidatorFromJwk matches no key identifier, so its refusal must not carry ErrNoKeyIdentifierMatch, got %v", test.clause, err)
			}
			if validator != nil {
				t.Errorf("[%s] no validator may be returned alongside the refusal, got %#v", test.clause, validator)
			}
		})
	}
}

func TestGetValidatorFromJwk_StrictKeyOperationsRefusesWhatSection43SaysShouldNotBePublished(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	public, err := jwk.PublicJwk(&key.PublicKey)
	if err != nil {
		t.Fatal(err)
	}

	tests := map[string]struct {
		members map[string]any
		refused bool
	}{
		"no use and no key_ops":                  {members: map[string]any{}},
		"use of sig alone":                       {members: map[string]any{"use": "sig"}},
		"key_ops of verify":                      {members: map[string]any{"key_ops": []any{"verify"}}},
		"key_ops of verify and sign":             {members: map[string]any{"key_ops": []any{"verify", "sign"}}},
		"use of sig and key_ops of verify":       {members: map[string]any{"use": "sig", "key_ops": []any{"verify"}}, refused: true},
		"key_ops of verify and encrypt":          {members: map[string]any{"key_ops": []any{"verify", "encrypt"}}, refused: true},
		"key_ops of sign, verify and deriveBits": {members: map[string]any{"key_ops": []any{"sign", "verify", "deriveBits"}}, refused: true},
		"key_ops of verify and an unknown value": {members: map[string]any{"key_ops": []any{"verify", "x-custom"}}, refused: true},
	}

	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			candidate := map[string]any{}
			for k, v := range *public {
				candidate[k] = v
			}
			for k, v := range test.members {
				candidate[k] = v
			}
			if validator, err := GetValidatorFromJwk(jwa.ES256, candidate, nil); err != nil || validator == nil {
				t.Fatalf("[RFC 7517 4.3] no MUST forbids a jwk with %s, so it must build a validator by default, got %v", name, err)
			}
			if validator, err := GetValidatorFromJwk(jwa.ES256, candidate, &model.JoseOptions{IgnoreKeyUse: true}); err != nil || validator == nil {
				t.Fatalf("[RFC 7517 4.3] a jwk with %s must build a validator when only IgnoreKeyUse is set, got %v", name, err)
			}
			validator, err := GetValidatorFromJwk(jwa.ES256, candidate, &model.JoseOptions{StrictKeyOperations: true, IgnoreKeyUse: true})
			if !test.refused {
				if err != nil || validator == nil {
					t.Errorf("[RFC 7517 4.3] section 4.3 discourages nothing in a jwk with %s, so StrictKeyOperations must accept it, got %v", name, err)
				}
				return
			}
			if !errors.Is(err, joseerror.ErrInvalidPublicKey) || validator != nil {
				t.Errorf("[RFC 7517 4.3] a jwk with %s SHOULD NOT be published, so StrictKeyOperations must refuse it with ErrInvalidPublicKey and no validator, whatever IgnoreKeyUse says, got %v", name, err)
			}
		})
	}
}

func TestGetValidator_VerifiesWithAJwkMarkedForEncryptionWhenTheCallerReadsItFirst(t *testing.T) {
	signer, err := GetSigner(jwa.ES256, nil)
	if err != nil {
		t.Fatal(err)
	}
	public, err := jwk.PublicJwk(signer.Public())
	if err != nil {
		t.Fatal(err)
	}
	(*public)["use"] = "enc"

	if validator, err := GetValidatorFromJwk(jwa.ES256, *public, nil); !errors.Is(err, joseerror.ErrInvalidPublicKey) {
		t.Fatalf("[RFC 7517 4.2] GetValidatorFromJwk must refuse a jwk whose use is enc, got %v and %#v", err, validator)
	}

	key, err := jwk.PublicFromJwk(*public)
	if err != nil {
		t.Fatalf("[RFC 7517 4.2] PublicFromJwk reads a key whatever its use, got %v", err)
	}
	validator, err := GetValidator(jwa.ES256, key)
	if err != nil {
		t.Fatalf("[RFC 7517 4.2] GetValidator carries no key-use rule, so the key read from a jwk whose use is enc must build a validator, got %v", err)
	}
	input := []byte("the signing input")
	signature, err := signer.Sign(rand.Reader, input, nil)
	if err != nil {
		t.Fatal(err)
	}
	if valid, err := validator.ValidateSignature(input, signature); err != nil || !valid {
		t.Errorf("[RFC 7518 3.4] the validator built from the key read must verify its signer's signature, got %t and %v", valid, err)
	}
}
