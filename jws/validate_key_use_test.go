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
			validator, err := GetValidatorFromJwk(jwa.ES256, candidate)
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
