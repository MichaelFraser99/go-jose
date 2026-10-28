package jws

import (
	"bytes"
	"testing"

	"github.com/MichaelFraser99/go-jose/jwa"
	"github.com/MichaelFraser99/go-jose/model"
)

var constructableAlgorithms = []jwa.Algorithm{
	jwa.ES256, jwa.ES384, jwa.ES512,
	jwa.RS256, jwa.RS384, jwa.RS512,
	jwa.PS256, jwa.PS384, jwa.PS512,
	jwa.HS256, jwa.HS384, jwa.HS512,
}

func TestGetSigner_AFailedConstructionReturnsNoSigner(t *testing.T) {
	tooShort := bytes.Repeat([]byte("k"), 1)
	for _, alg := range []jwa.Algorithm{jwa.HS256, jwa.HS384, jwa.HS512} {
		t.Run(alg.String(), func(t *testing.T) {
			signer, err := GetSigner(alg, &model.Opts{SecretKey: &tooShort})
			if err == nil {
				t.Fatal("expected a one-byte secret to be refused")
			}
			if signer != nil {
				t.Errorf("a refused construction must return a nil Signer, not an interface holding a typed nil: calling a method on it panics. Got %#v", signer)
			}
		})
	}
}

func TestGetSignerFromPrivateKey_AFailedConstructionReturnsNoSigner(t *testing.T) {
	for _, alg := range constructableAlgorithms {
		t.Run(alg.String(), func(t *testing.T) {
			signer, err := GetSignerFromPrivateKey(alg, "not a private key")
			if err == nil {
				t.Fatal("expected a string to be refused as a private key")
			}
			if signer != nil {
				t.Errorf("a refused construction must return a nil Signer, not an interface holding a typed nil: calling a method on it panics. Got %#v", signer)
			}
		})
	}
}

func TestGetValidator_AFailedConstructionReturnsNoValidator(t *testing.T) {
	for _, alg := range constructableAlgorithms {
		t.Run(alg.String(), func(t *testing.T) {
			validator, err := GetValidator(alg, "not a public key")
			if err == nil {
				t.Fatal("expected a string to be refused as a public key")
			}
			if validator != nil {
				t.Errorf("a refused construction must return a nil Validator, not an interface holding a typed nil: calling a method on it panics. Got %#v", validator)
			}
		})
	}
}

func TestGetValidatorFromJwk_AFailedConstructionReturnsNoValidator(t *testing.T) {
	for _, alg := range constructableAlgorithms {
		t.Run(alg.String(), func(t *testing.T) {
			validator, err := GetValidatorFromJwk(alg, map[string]any{"kty": "nonsense"})
			if err == nil {
				t.Fatal("expected a jwk with an unknown kty to be refused")
			}
			if validator != nil {
				t.Errorf("a refused construction must return a nil Validator, not an interface holding a typed nil: calling a method on it panics. Got %#v", validator)
			}
		})
	}
}
