package rs384

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha512"
	"fmt"
	e "github.com/MichaelFraser99/go-jose/error"
	"github.com/MichaelFraser99/go-jose/internal/algorithms/common"
	"github.com/MichaelFraser99/go-jose/model"
	"io"
)

type Signer struct {
	alg        model.Algorithm
	privateKey *rsa.PrivateKey
	validator  *Validator
}

type Validator struct {
	publicKey *rsa.PublicKey
}

func NewSigner(size int) (*Signer, error) {
	if size < 2048 {
		return nil, fmt.Errorf("specified key bit size should be at least 2048")
	}
	pk, err := rsa.GenerateKey(rand.Reader, size)
	if err != nil {
		return nil, &e.SigningError{Message: fmt.Sprintf("failed to generate key: %s", err.Error())}
	}
	validator, err := NewValidator(pk.Public())
	if err != nil {
		return nil, fmt.Errorf("error reading generated public key")
	}
	return &Signer{
		alg:        model.RS384,
		privateKey: pk,
		validator:  validator,
	}, nil
}

func NewValidator(publicKey crypto.PublicKey) (*Validator, error) {
	rsaPublicKey, ok := publicKey.(*rsa.PublicKey)
	if !ok {
		return nil, &e.InvalidPublicKey{Message: "invalid key provided for RS384"}
	}
	return &Validator{
		publicKey: rsaPublicKey,
	}, nil
}

func NewValidatorFromJwk(publicKeyJson []byte) (*Validator, error) {
	publicKey, err := common.NewRSAPublicKeyFromJson(publicKeyJson)
	if err != nil {
		return nil, err
	}
	return NewValidator(publicKey)
}

func (signer *Signer) Alg() model.Algorithm {
	return signer.alg
}

func (signer *Signer) Public() crypto.PublicKey {
	return signer.privateKey.Public()
}

func (signer *Signer) Validator() *Validator {
	return signer.validator
}

func (signer *Signer) Sign(rand io.Reader, digest []byte, opts crypto.SignerOpts) (signature []byte, err error) {
	if opts != nil && opts.HashFunc() > 0 && opts.HashFunc() != crypto.SHA384 {
		return nil, &e.SigningError{Message: "invalid hash function provided for specified signer"}
	}

	var hashedDigest []byte
	if opts == nil || opts.HashFunc() == 0 {
		hash := sha512.Sum384(digest)
		hashedDigest = hash[:]
	} else {
		hashedDigest = make([]byte, len(digest))
		copy(hashedDigest, digest)
	}

	signature, err = common.RsaPkcs1Sign(rand, *signer.privateKey, hashedDigest[:], crypto.SHA384)
	if err != nil {
		return nil, err
	}

	return signature, nil
}

func (validator *Validator) ValidateSignature(digest, signature []byte) (bool, error) {
	hashedDigest := sha512.Sum384(digest)

	err := rsa.VerifyPKCS1v15(validator.publicKey, crypto.SHA384, hashedDigest[:], signature)

	if err != nil {
		return false, &e.InvalidSignature{Message: fmt.Sprintf("invalid signature: %s", err.Error())}
	}

	return true, nil
}

func (validator *Validator) Jwk() map[string]string {
	return common.JwkFromRSAPublicKey(validator.publicKey)
}
