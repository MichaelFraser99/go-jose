package jose_test

import (
	"crypto"
	"crypto/rand"
	"crypto/sha256"
	"github.com/MichaelFraser99/go-jose/internal/algorithms/es256"
	"github.com/MichaelFraser99/go-jose/model"
	"testing"
)

func Test_Sign(t *testing.T) {
	signer, err := es256.NewSigner()
	if err != nil {
		t.Fatal(err)
	}

	input := []byte("hello world")

	signature, err := signer.Sign(rand.Reader, input, nil)
	if err != nil {
		t.Fatal(err)
	}

	validator, err := es256.NewValidator(signer.Public())
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
	signer, err := es256.NewSigner()
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

	validator, err := es256.NewValidator(signer.Public())
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

	validator, err = es256.NewValidator(signer.Public())
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
