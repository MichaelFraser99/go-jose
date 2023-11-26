package es512

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha512"
	"fmt"
	e "github.com/MichaelFraser99/go-jose/error"
	"github.com/MichaelFraser99/go-jose/internal/algorithms/common"
	"github.com/MichaelFraser99/go-jose/model"
	"io"
)

const keySize = 132

type Signer struct {
	alg        model.Algorithm
	privateKey *ecdsa.PrivateKey
}

type Validator struct {
	publicKey *ecdsa.PublicKey
}

func NewSigner() (*Signer, error) {
	curve := elliptic.P521()
	pk, err := ecdsa.GenerateKey(curve, rand.Reader)
	if err != nil {
		return nil, &e.SigningError{Message: fmt.Sprintf("failed to generate key: %s", err.Error())}
	}
	return &Signer{
		alg:        model.ES512,
		privateKey: pk,
	}, nil
}

func NewSignerFromPrivateKey(privateKey crypto.PrivateKey) (*Signer, error) {
	ecdsaPrivateKey, ok := privateKey.(*ecdsa.PrivateKey)
	if !ok {
		return nil, &e.InvalidPrivateKey{Message: "invalid key provided for .S... should be instance of `*ecdsa.Privatekey`"}
	}
	return &Signer{
		alg:        model.ES512,
		privateKey: ecdsaPrivateKey,
	}, nil
}

func NewValidator(publicKey crypto.PublicKey) (*Validator, error) {
	ecdsaPublicKey, ok := publicKey.(*ecdsa.PublicKey)
	if !ok {
		return nil, &e.InvalidPublicKey{Message: "invalid key provided for .S... should be instance of `*ecdsa.PublicKey`"}
	}
	return &Validator{
		publicKey: ecdsaPublicKey,
	}, nil
}

func NewValidatorFromJwk(publicKeyJson []byte) (*Validator, error) {
	publicKey, err := common.NewECDSAPublicKeyFromJson(publicKeyJson, elliptic.P521())
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

func (signer *Signer) Sign(rand io.Reader, digest []byte, opts crypto.SignerOpts) (signature []byte, err error) {
	if opts != nil && opts.HashFunc() > 0 && opts.HashFunc() != crypto.SHA512 {
		return nil, &e.SigningError{Message: "invalid hash function provided for specified signer"}
	}

	if opts == nil || opts.HashFunc() == 0 {
		hashedDigest := sha512.Sum512(digest)
		digest = hashedDigest[:]
	}

	signature, err = common.EllipticCurveSign(rand, *signer.privateKey, digest[:], keySize)
	if err != nil {
		return nil, err
	}

	return signature, nil
}

func (validator *Validator) ValidateSignature(digest, signature []byte) (bool, error) {
	bodyHash := sha512.Sum512(digest)

	r, s, err := common.ExtractRSFromSignature(signature, keySize)
	if err != nil {
		return false, &e.InvalidSignature{Message: "invalid signature"}
	}

	return ecdsa.Verify(validator.publicKey, bodyHash[:], r, s), nil
}

func (validator *Validator) Jwk() map[string]string {
	jwk := common.JwkFromECDSAPublicKey(validator.publicKey)
	jwk["crv"] = "P-521"
	return jwk
}

func (validator *Validator) Public() crypto.PublicKey {
	return validator.publicKey
}
