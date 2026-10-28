package jws

import (
	"bytes"
	"crypto"
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"testing"

	"github.com/MichaelFraser99/go-jose/joseerror"
	"github.com/MichaelFraser99/go-jose/jwa"
	"github.com/MichaelFraser99/go-jose/model"
)

func contractSigner(t *testing.T, alg jwa.Algorithm) model.Signer {
	t.Helper()
	opts := &model.Opts{}
	if alg == jwa.HS256 || alg == jwa.HS384 || alg == jwa.HS512 {
		secret := bytes.Repeat([]byte("k"), 64)
		opts.SecretKey = &secret
	}
	signer, err := GetSigner(alg, opts)
	if err != nil {
		t.Fatalf("expected no error creating a %s signer, got %q", alg, err.Error())
	}
	return signer
}

func TestSign_EveryAlgorithmHonoursTheDocumentedSigningContract(t *testing.T) {
	input := []byte("the jws signing input")

	tests := map[jwa.Algorithm]struct {
		hash          crypto.Hash
		preHashedMode bool
	}{
		jwa.ES256: {hash: crypto.SHA256, preHashedMode: true},
		jwa.ES384: {hash: crypto.SHA384, preHashedMode: true},
		jwa.ES512: {hash: crypto.SHA512, preHashedMode: true},
		jwa.RS256: {hash: crypto.SHA256, preHashedMode: true},
		jwa.RS384: {hash: crypto.SHA384, preHashedMode: true},
		jwa.RS512: {hash: crypto.SHA512, preHashedMode: true},
		jwa.PS256: {hash: crypto.SHA256, preHashedMode: true},
		jwa.PS384: {hash: crypto.SHA384, preHashedMode: true},
		jwa.PS512: {hash: crypto.SHA512, preHashedMode: true},
		jwa.HS256: {hash: crypto.SHA256},
		jwa.HS384: {hash: crypto.SHA384},
		jwa.HS512: {hash: crypto.SHA512},
	}

	for alg, test := range tests {
		t.Run(alg.String()+", JOSE mode with nil opts", func(t *testing.T) {
			signer := contractSigner(t, alg)
			validator, err := GetValidator(signer.Alg(), signer.Public())
			if err != nil {
				t.Fatalf("expected no error creating a validator, got %q", err.Error())
			}
			signature, err := signer.Sign(rand.Reader, input, nil)
			if err != nil {
				t.Fatalf("[RFC 7518] JOSE mode takes the signing input whole, got %q", err.Error())
			}
			valid, err := validator.ValidateSignature(input, signature)
			if err != nil || !valid {
				t.Errorf("[RFC 7518] a signature made in JOSE mode must verify, got valid=%t err=%v", valid, err)
			}
		})

		t.Run(alg.String()+", pre-hashed mode", func(t *testing.T) {
			signer := contractSigner(t, alg)
			validator, err := GetValidator(signer.Alg(), signer.Public())
			if err != nil {
				t.Fatalf("expected no error creating a validator, got %q", err.Error())
			}

			hashed := test.hash.New()
			hashed.Write(input)
			signature, err := signer.Sign(rand.Reader, hashed.Sum(nil), model.SignerOpts{Hash: test.hash})

			if !test.preHashedMode {
				if err == nil {
					valid, _ := validator.ValidateSignature(input, signature)
					t.Fatalf("[#69] an hmac algorithm has no pre-hashed mode, so it must refuse rather than produce a signature that verifies=%t", valid)
				}
				if !errors.Is(err, joseerror.ErrSigningError) {
					t.Errorf("[#69] the refusal must carry the signing error class, got %v", err)
				}
				return
			}
			if err != nil {
				t.Fatalf("[RFC 7518] %s implements pre-hashed mode, got %q", alg, err.Error())
			}
			valid, err := validator.ValidateSignature(input, signature)
			if err != nil || !valid {
				t.Errorf("[RFC 7518] a signature made in pre-hashed mode must verify, got valid=%t err=%v", valid, err)
			}
		})

		if !test.preHashedMode {
			continue
		}

		t.Run(alg.String()+", a hash that is not the algorithm's own", func(t *testing.T) {
			signer := contractSigner(t, alg)
			other := crypto.SHA512
			if test.hash == crypto.SHA512 {
				other = crypto.SHA256
			}
			digest := sha256.Sum256(input)
			if _, err := signer.Sign(rand.Reader, digest[:], model.SignerOpts{Hash: other}); err == nil {
				t.Errorf("[RFC 7518] %s must refuse a %s digest rather than sign it", alg, other)
			}
		})
	}
}
