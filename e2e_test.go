package jose_test

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"github.com/MichaelFraser99/go-jose/jws"
	"github.com/MichaelFraser99/go-jose/model"
	"testing"
)

func Test_Sign(t *testing.T) {
	signer, err := jws.GetSigner(model.ES256, nil)
	if err != nil {
		t.Fatal(err)
	}

	input := []byte("hello world")

	signature, err := signer.Sign(rand.Reader, input, nil)
	if err != nil {
		t.Fatal(err)
	}

	validator, err := jws.GetValidator(signer.Alg(), signer.Public())
	if err != nil {
		t.Fatal(err)
	}

	valid, err := validator.ValidateSignature(input, signature)
	if err != nil {
		t.Fatal(err)
	}

	if !valid {
		t.Fatal("signature is not valid")
	}
}

func Test_SignPreHashed(t *testing.T) {
	signer, err := jws.GetSigner(model.ES256, nil)
	if err != nil {
		t.Fatal(err)
	}

	input := []byte("hello world")

	signature, err := signer.Sign(rand.Reader, input, model.SignerOpts{
		Hash: crypto.SHA256,
	})
	if err != nil {
		t.Fatal(err)
	}

	validator, err := jws.GetValidator(signer.Alg(), signer.Public())
	if err != nil {
		t.Fatal(err)
	}

	valid, err := validator.ValidateSignature(input, signature)
	if err != nil {
		t.Fatal(err)
	}

	if valid {
		t.Fatal("signature should not be valid")
	}

	hashedInput := sha256.Sum256(input)

	signature, err = signer.Sign(rand.Reader, hashedInput[:], model.SignerOpts{
		Hash: crypto.SHA256,
	})
	if err != nil {
		t.Fatal(err)
	}

	validator, err = jws.GetValidator(signer.Alg(), signer.Public())
	if err != nil {
		t.Fatal(err)
	}

	valid, err = validator.ValidateSignature(input, signature)
	if err != nil {
		t.Fatal(err)
	}

	if !valid {
		t.Fatal("signature should be valid")
	}

}

func TestGetSignerFromPrivateKey(t *testing.T) {
	rsaPk, err := rsa.GenerateKey(rand.Reader, 2048)
	ec256Pk, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	ec384Pk, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	ec521Pk, err := ecdsa.GenerateKey(elliptic.P521(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	tests := []struct {
		name      string
		algorithm model.Algorithm
		key       crypto.PrivateKey
		validate  func(t *testing.T, signer model.Signer, err error)
	}{
		{
			"RS256 valid pk",
			model.RS256,
			rsaPk,
			func(t *testing.T, signer model.Signer, err error) {
				if err != nil {
					t.Fatal(err)
				}
				if signer.Alg() != model.RS256 {
					t.Errorf("returned signer should be of algorithm RS256 and is: %s", signer.Alg().String())
				}
				if signer.Public() == nil {
					t.Error("no public key available")
				}
			},
		},
		{
			"RS384 valid pk",
			model.RS384,
			rsaPk,
			func(t *testing.T, signer model.Signer, err error) {
				if err != nil {
					t.Fatal(err)
				}
				if signer.Alg() != model.RS384 {
					t.Errorf("returned signer should be of algorithm RS384 and is: %s", signer.Alg().String())
				}
				if signer.Public() == nil {
					t.Error("no public key available")
				}
			},
		},
		{
			"RS512 valid pk",
			model.RS512,
			rsaPk,
			func(t *testing.T, signer model.Signer, err error) {
				if err != nil {
					t.Fatal(err)
				}
				if signer.Alg() != model.RS512 {
					t.Errorf("returned signer should be of algorithm RS512 and is: %s", signer.Alg().String())
				}
				if signer.Public() == nil {
					t.Error("no public key available")
				}
			},
		},
		{
			"PS256 valid pk",
			model.PS256,
			rsaPk,
			func(t *testing.T, signer model.Signer, err error) {
				if err != nil {
					t.Fatal(err)
				}
				if signer.Alg() != model.PS256 {
					t.Errorf("returned signer should be of algorithm PS256 and is: %s", signer.Alg().String())
				}
				if signer.Public() == nil {
					t.Error("no public key available")
				}
			},
		},
		{
			"PS384 valid pk",
			model.PS384,
			rsaPk,
			func(t *testing.T, signer model.Signer, err error) {
				if err != nil {
					t.Fatal(err)
				}
				if signer.Alg() != model.PS384 {
					t.Errorf("returned signer should be of algorithm PS384 and is: %s", signer.Alg().String())
				}
				if signer.Public() == nil {
					t.Error("no public key available")
				}
			},
		},
		{
			"PS512 valid pk",
			model.PS512,
			rsaPk,
			func(t *testing.T, signer model.Signer, err error) {
				if err != nil {
					t.Fatal(err)
				}
				if signer.Alg() != model.PS512 {
					t.Errorf("returned signer should be of algorithm PS512 and is: %s", signer.Alg().String())
				}
				if signer.Public() == nil {
					t.Error("no public key available")
				}
			},
		},
		{
			"ES256 valid pk",
			model.ES256,
			ec256Pk,
			func(t *testing.T, signer model.Signer, err error) {
				if err != nil {
					t.Fatal(err)
				}
				if signer.Alg() != model.ES256 {
					t.Errorf("returned signer should be of algorithm ES256 and is: %s", signer.Alg().String())
				}
				if signer.Public() == nil {
					t.Error("no public key available")
				}
			},
		},
		{
			"ES384 valid pk",
			model.ES384,
			ec384Pk,
			func(t *testing.T, signer model.Signer, err error) {
				if err != nil {
					t.Fatal(err)
				}
				if signer.Alg() != model.ES384 {
					t.Errorf("returned signer should be of algorithm ES384 and is: %s", signer.Alg().String())
				}
				if signer.Public() == nil {
					t.Error("no public key available")
				}
			},
		},
		{
			"ES512 valid pk",
			model.ES512,
			ec521Pk,
			func(t *testing.T, signer model.Signer, err error) {
				if err != nil {
					t.Fatal(err)
				}
				if signer.Alg() != model.ES512 {
					t.Errorf("returned signer should be of algorithm ES512 and is: %s", signer.Alg().String())
				}
				if signer.Public() == nil {
					t.Error("no public key available")
				}
			},
		},
		{
			"ES256 invalid pk",
			model.ES256,
			rsaPk,
			func(t *testing.T, signer model.Signer, err error) {
				if err == nil {
					t.Fatal("error should be thrown when wrong key provided")
				}
				if err.Error() != "invalid key provided - should be instance of `*ecdsa.Privatekey`" {
					t.Errorf("wrong error returned: %s", err.Error())
				}
			},
		},
		{
			"ES256 invalid pk",
			model.ES256,
			ec521Pk,
			func(t *testing.T, signer model.Signer, err error) {
				if err == nil {
					t.Fatal("error should be thrown when wrong key provided")
				}
				if err.Error() != "invalid key provided - curve should be P-256, was P-521" {
					t.Errorf("wrong error returned: %s", err.Error())
				}
			},
		},
		{
			"ES384 invalid pk",
			model.ES384,
			rsaPk,
			func(t *testing.T, signer model.Signer, err error) {
				if err == nil {
					t.Fatal("error should be thrown when wrong key provided")
				}
				if err.Error() != "invalid key provided - should be instance of `*ecdsa.Privatekey`" {
					t.Errorf("wrong error returned: %s", err.Error())
				}
			},
		},
		{
			"ES384 invalid pk",
			model.ES384,
			ec521Pk,
			func(t *testing.T, signer model.Signer, err error) {
				if err == nil {
					t.Fatal("error should be thrown when wrong key provided")
				}
				if err.Error() != "invalid key provided - curve should be P-384, was P-521" {
					t.Errorf("wrong error returned: %s", err.Error())
				}
			},
		},
		{
			"ES512 invalid pk",
			model.ES512,
			rsaPk,
			func(t *testing.T, signer model.Signer, err error) {
				if err == nil {
					t.Fatal("error should be thrown when wrong key provided")
				}
				if err.Error() != "invalid key provided - should be instance of `*ecdsa.Privatekey`" {
					t.Errorf("wrong error returned: %s", err.Error())
				}
			},
		},
		{
			"ES512 invalid pk",
			model.ES512,
			ec256Pk,
			func(t *testing.T, signer model.Signer, err error) {
				if err == nil {
					t.Fatal("error should be thrown when wrong key provided")
				}
				if err.Error() != "invalid key provided - curve should be P-521, was P-256" {
					t.Errorf("wrong error returned: %s", err.Error())
				}
			},
		},
		{
			"RS256 invalid pk",
			model.RS256,
			ec256Pk,
			func(t *testing.T, signer model.Signer, err error) {
				if err == nil {
					t.Fatal("error should be thrown when wrong key provided")
				}
				if err.Error() != "invalid key provided - should be instance of `*rsa.Privatekey`" {
					t.Errorf("wrong error returned: %s", err.Error())
				}
			},
		},
		{
			"RS384 invalid pk",
			model.RS384,
			ec256Pk,
			func(t *testing.T, signer model.Signer, err error) {
				if err == nil {
					t.Fatal("error should be thrown when wrong key provided")
				}
				if err.Error() != "invalid key provided - should be instance of `*rsa.Privatekey`" {
					t.Errorf("wrong error returned: %s", err.Error())
				}
			},
		},
		{
			"RS512 invalid pk",
			model.RS512,
			ec256Pk,
			func(t *testing.T, signer model.Signer, err error) {
				if err == nil {
					t.Fatal("error should be thrown when wrong key provided")
				}
				if err.Error() != "invalid key provided - should be instance of `*rsa.Privatekey`" {
					t.Errorf("wrong error returned: %s", err.Error())
				}
			},
		},
		{
			"PS256 invalid pk",
			model.PS256,
			ec256Pk,
			func(t *testing.T, signer model.Signer, err error) {
				if err == nil {
					t.Fatal("error should be thrown when wrong key provided")
				}
				if err.Error() != "invalid key provided - should be instance of `*rsa.Privatekey`" {
					t.Errorf("wrong error returned: %s", err.Error())
				}
			},
		},
		{
			"PS384 invalid pk",
			model.PS384,
			ec256Pk,
			func(t *testing.T, signer model.Signer, err error) {
				if err == nil {
					t.Fatal("error should be thrown when wrong key provided")
				}
				if err.Error() != "invalid key provided - should be instance of `*rsa.Privatekey`" {
					t.Errorf("wrong error returned: %s", err.Error())
				}
			},
		},
		{
			"PS512 invalid pk",
			model.PS512,
			ec256Pk,
			func(t *testing.T, signer model.Signer, err error) {
				if err == nil {
					t.Fatal("error should be thrown when wrong key provided")
				}
				if err.Error() != "invalid key provided - should be instance of `*rsa.Privatekey`" {
					t.Errorf("wrong error returned: %s", err.Error())
				}
			},
		},
		{
			"HS256",
			model.HS256,
			ec256Pk,
			func(t *testing.T, signer model.Signer, err error) {
				if err == nil {
					t.Fatal("error should be thrown when wrong key provided")
				}
				if err.Error() != "HMAC Signers cannot be created this way - please use GetSigner and specify the secret key using the Opts function" {
					t.Errorf("wrong error returned: %s", err.Error())
				}
			},
		},
		{
			"HS384",
			model.HS384,
			ec256Pk,
			func(t *testing.T, signer model.Signer, err error) {
				if err == nil {
					t.Fatal("error should be thrown when wrong key provided")
				}
				if err.Error() != "HMAC Signers cannot be created this way - please use GetSigner and specify the secret key using the Opts function" {
					t.Errorf("wrong error returned: %s", err.Error())
				}
			},
		},
		{
			"HS512",
			model.HS512,
			ec256Pk,
			func(t *testing.T, signer model.Signer, err error) {
				if err == nil {
					t.Fatal("error should be thrown when wrong key provided")
				}
				if err.Error() != "HMAC Signers cannot be created this way - please use GetSigner and specify the secret key using the Opts function" {
					t.Errorf("wrong error returned: %s", err.Error())
				}
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			signer, err := jws.GetSignerFromPrivateKey(tt.algorithm, tt.key)
			tt.validate(t, signer, err)
		})
	}
}
