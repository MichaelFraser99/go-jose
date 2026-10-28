package jws

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"errors"
	"math/big"
	"testing"

	"github.com/MichaelFraser99/go-jose/joseerror"
	"github.com/MichaelFraser99/go-jose/jwa"
	"github.com/MichaelFraser99/go-jose/jwk"
)

func TestValidateSignature_ASignatureThatDoesNotVerifyIsFalseWithANilError(t *testing.T) {
	input := []byte("the jws signing input")

	for _, alg := range constructableAlgorithms {
		signer := contractSigner(t, alg)
		validator, err := GetValidator(signer.Alg(), signer.Public())
		if err != nil {
			t.Fatalf("expected no error creating a %s validator, got %v", alg, err)
		}
		signature, err := signer.Sign(rand.Reader, input, nil)
		if err != nil {
			t.Fatalf("expected no error signing with %s, got %v", alg, err)
		}

		flipped := append([]byte{}, signature...)
		flipped[len(flipped)-1] ^= 0x01
		forgeries := map[string][]byte{
			"the last bit flipped": flipped,
			"one byte short":       signature[:len(signature)-1],
			"one byte long":        append(append([]byte{}, signature...), 0x00),
			"an empty signature":   {},
			"all zeros":            make([]byte, len(signature)),
		}
		for name, forgery := range forgeries {
			t.Run(alg.String()+" with "+name, func(t *testing.T) {
				valid, err := validator.ValidateSignature(input, forgery)
				if valid || err != nil {
					t.Errorf("[RFC 7518 3.4] a signature that fails validation reports false with a nil error, got valid=%t err=%v", valid, err)
				}
			})
		}
	}
}

func TestRSAValidators_AnErrorMeansCryptoRSACouldNotCheckTheSignature(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("failed to generate an RSA key: %v", err)
	}
	evenModulus := &rsa.PublicKey{N: new(big.Int).Add(key.N, big.NewInt(1)), E: key.E}
	input := []byte("the jws signing input")
	signature := make([]byte, 256)
	signature[255] = 0x07
	digest := func(hash crypto.Hash) []byte {
		h := hash.New()
		h.Write(input)
		return h.Sum(nil)
	}
	pkcs1 := func(hash crypto.Hash) error {
		return rsa.VerifyPKCS1v15(evenModulus, hash, digest(hash), signature)
	}
	pss := func(hash crypto.Hash) error {
		return rsa.VerifyPSS(evenModulus, hash, digest(hash), signature, &rsa.PSSOptions{SaltLength: hash.Size(), Hash: hash})
	}
	standardLibrary := map[jwa.Algorithm]error{
		jwa.RS256: pkcs1(crypto.SHA256),
		jwa.RS384: pkcs1(crypto.SHA384),
		jwa.RS512: pkcs1(crypto.SHA512),
		jwa.PS256: pss(crypto.SHA256),
		jwa.PS384: pss(crypto.SHA384),
		jwa.PS512: pss(crypto.SHA512),
	}

	for alg, verifyErr := range standardLibrary {
		t.Run(alg.String(), func(t *testing.T) {
			validator, err := GetValidator(alg, evenModulus)
			if err != nil {
				t.Fatalf("expected no error creating a validator, got %v", err)
			}
			valid, err := validator.ValidateSignature(input, signature)
			if valid {
				t.Fatal("[README Validators] a signature crypto/rsa did not accept must not verify")
			}
			if errors.Is(verifyErr, rsa.ErrVerification) {
				if err != nil {
					t.Errorf("[README Validators] crypto/rsa reports %q, so the signature does not verify and the error must be nil, got %v", verifyErr, err)
				}
				return
			}
			if !errors.Is(err, joseerror.ErrInvalidSignature) {
				t.Errorf("[README Validators] crypto/rsa could not check the signature (%q), so the error must be non-nil and carry ErrInvalidSignature, got %v", verifyErr, err)
			}
		})
	}
}

func TestGetValidatorFromJwk_BindsTheKeyToItsAlgAndKty(t *testing.T) {
	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("failed to generate an RSA key: %v", err)
	}
	ecKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate an EC key: %v", err)
	}
	rsaJwk := func(members map[string]any) map[string]any {
		out := map[string]any{
			"kty": "RSA",
			"n":   base64.RawURLEncoding.EncodeToString(rsaKey.N.Bytes()),
			"e":   base64.RawURLEncoding.EncodeToString(big.NewInt(int64(rsaKey.E)).Bytes()),
		}
		for k, v := range members {
			if v == nil {
				delete(out, k)
				continue
			}
			out[k] = v
		}
		return out
	}
	ecJwk := func(members map[string]any) map[string]any {
		out := map[string]any{
			"kty": "EC",
			"crv": "P-256",
			"x":   base64.RawURLEncoding.EncodeToString(ecKey.X.FillBytes(make([]byte, 32))),
			"y":   base64.RawURLEncoding.EncodeToString(ecKey.Y.FillBytes(make([]byte, 32))),
		}
		for k, v := range members {
			if v == nil {
				delete(out, k)
				continue
			}
			out[k] = v
		}
		return out
	}

	tests := map[string]struct {
		alg    jwa.Algorithm
		jwk    map[string]any
		accept bool
		clause string
	}{
		"an RSA jwk with no alg":                  {alg: jwa.RS256, jwk: rsaJwk(nil), accept: true, clause: "RFC 7517 4.4"},
		"an RSA jwk whose alg is RS256":           {alg: jwa.RS256, jwk: rsaJwk(map[string]any{"alg": "RS256"}), accept: true, clause: "RFC 8725 3.1"},
		"an RSA jwk published for PS256":          {alg: jwa.RS256, jwk: rsaJwk(map[string]any{"alg": "PS256"}), clause: "RFC 8725 3.1"},
		"an RSA jwk published for RS512":          {alg: jwa.RS256, jwk: rsaJwk(map[string]any{"alg": "RS512"}), clause: "RFC 8725 3.1"},
		"an RSA jwk whose alg differs in case":    {alg: jwa.RS256, jwk: rsaJwk(map[string]any{"alg": "rs256"}), clause: "RFC 7517 4.4"},
		"an RSA jwk whose alg is a number":        {alg: jwa.RS256, jwk: rsaJwk(map[string]any{"alg": 256}), clause: "RFC 7517 4.4"},
		"an RSA jwk whose alg is an empty string": {alg: jwa.RS256, jwk: rsaJwk(map[string]any{"alg": ""}), clause: "RFC 8725 3.1"},
		"an EC jwk published for ES384":           {alg: jwa.ES256, jwk: ecJwk(map[string]any{"alg": "ES384"}), clause: "RFC 8725 3.1"},
		"an EC jwk whose alg is ES256":            {alg: jwa.ES256, jwk: ecJwk(map[string]any{"alg": "ES256"}), accept: true, clause: "RFC 8725 3.1"},
		"EC members with no kty":                  {alg: jwa.ES256, jwk: ecJwk(map[string]any{"kty": nil}), clause: "RFC 7517 4.1"},
		"EC members labelled RSA":                 {alg: jwa.ES256, jwk: ecJwk(map[string]any{"kty": "RSA"}), clause: "RFC 7517 4.1"},
		"EC members labelled oct":                 {alg: jwa.ES256, jwk: ecJwk(map[string]any{"kty": "oct"}), clause: "RFC 7517 4.1"},
		"EC members whose kty is a number":        {alg: jwa.ES256, jwk: ecJwk(map[string]any{"kty": 2}), clause: "RFC 7517 4.1"},
		"RSA members with no kty":                 {alg: jwa.RS256, jwk: rsaJwk(map[string]any{"kty": nil}), clause: "RFC 7517 4.1"},
		"RSA members labelled EC":                 {alg: jwa.RS256, jwk: rsaJwk(map[string]any{"kty": "EC"}), clause: "RFC 7518 6.1"},
		"an EC jwk for an RSA algorithm":          {alg: jwa.PS256, jwk: ecJwk(nil), clause: "RFC 7518 6.1"},
		"an RSA jwk for an EC algorithm":          {alg: jwa.ES256, jwk: rsaJwk(nil), clause: "RFC 7518 6.1"},
	}

	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			validator, err := GetValidatorFromJwk(test.alg, test.jwk)
			if test.accept {
				if err != nil || validator == nil {
					t.Errorf("[%s] %s must build a %s validator, got err=%v", test.clause, name, test.alg, err)
				}
				return
			}
			if err == nil {
				t.Errorf("[%s] %s must not build a %s validator", test.clause, name, test.alg)
			}
			if validator != nil {
				t.Errorf("[%s] a refused construction must return a nil Validator, got %#v", test.clause, validator)
			}
		})
	}
}

func TestGetValidatorFromJwk_AnAlgMismatchIsAnInvalidPublicKey(t *testing.T) {
	signer := contractSigner(t, jwa.RS256)
	publicJwk, err := jwk.PublicJwk(signer.Public())
	if err != nil {
		t.Fatalf("failed to build a jwk: %v", err)
	}
	for _, alg := range []any{"PS256", 256} {
		(*publicJwk)["alg"] = alg
		_, err := GetValidatorFromJwk(jwa.RS256, *publicJwk)
		if !errors.Is(err, joseerror.ErrInvalidPublicKey) {
			t.Errorf("[RFC 8725 3.1] a jwk whose alg is %#v cannot be used for RS256, so it must be refused with ErrInvalidPublicKey, got %v", alg, err)
		}
	}
}

func TestGetValidatorFromJwk_RefusesAnUnsupportedAlgorithmBeforeReadingTheJwk(t *testing.T) {
	for _, alg := range []jwa.Algorithm{jwa.Unknown, jwa.EdDSA, jwa.Algorithm(-1), jwa.HS256, jwa.HS384, jwa.HS512} {
		t.Run(alg.String(), func(t *testing.T) {
			validator, err := GetValidatorFromJwk(alg, map[string]any{})
			if !errors.Is(err, joseerror.ErrUnsupportedAlgorithm) {
				t.Errorf("[RFC 8725 3.1] GetValidatorFromJwk builds no validator for %s, so it must refuse it as an unsupported algorithm whatever the jwk holds, got %v", alg, err)
			}
			if validator != nil {
				t.Errorf("[RFC 8725 3.1] a refused construction must return a nil Validator, got %#v", validator)
			}
		})
	}
}
