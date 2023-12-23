package jose_test

import (
	"crypto"
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
	pk, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}

	signer, err := jws.GetSignerFromPrivateKey(model.RS256, pk)
	if err != nil {
		t.Fatal(err)
	}
	if signer.Alg() != model.RS256 {
		t.Errorf("returned signer should be of algorithm RS256 and is: %s", signer.Alg().String())
	}
	if signer.Public() == nil {
		t.Error("no public key available")
	}

	signer, err = jws.GetSignerFromPrivateKey(model.RS384, pk)
	if err != nil {
		t.Fatal(err)
	}
	if signer.Alg() != model.RS384 {
		t.Errorf("returned signer should be of algorithm RS384 and is: %s", signer.Alg().String())
	}
	if signer.Public() == nil {
		t.Error("no public key available")
	}

	signer, err = jws.GetSignerFromPrivateKey(model.RS512, pk)
	if err != nil {
		t.Fatal(err)
	}
	if signer.Alg() != model.RS512 {
		t.Errorf("returned signer should be of algorithm RS512 and is: %s", signer.Alg().String())
	}
	if signer.Public() == nil {
		t.Error("no public key available")
	}

	signer, err = jws.GetSignerFromPrivateKey(model.PS256, pk)
	if err != nil {
		t.Fatal(err)
	}
	if signer.Alg() != model.PS256 {
		t.Errorf("returned signer should be of algorithm PS256 and is: %s", signer.Alg().String())
	}
	if signer.Public() == nil {
		t.Error("no public key available")
	}

	signer, err = jws.GetSignerFromPrivateKey(model.PS384, pk)
	if err != nil {
		t.Fatal(err)
	}
	if signer.Alg() != model.PS384 {
		t.Errorf("returned signer should be of algorithm PS384 and is: %s", signer.Alg().String())
	}
	if signer.Public() == nil {
		t.Error("no public key available")
	}

	signer, err = jws.GetSignerFromPrivateKey(model.PS512, pk)
	if err != nil {
		t.Fatal(err)
	}
	if signer.Alg() != model.PS512 {
		t.Errorf("returned signer should be of algorithm PS512 and is: %s", signer.Alg().String())
	}
	if signer.Public() == nil {
		t.Error("no public key available")
	}

	_, err = jws.GetSignerFromPrivateKey(model.ES256, pk)
	if err == nil {
		t.Fatal("error should be thrown when wrong key provided")
	}
	if err.Error() != "invalid key provided - should be instance of `*ecdsa.Privatekey`" {
		t.Errorf("wrong error returned: %s", err.Error())
	}
}
