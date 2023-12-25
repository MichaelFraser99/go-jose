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
const curveName = "P-521"

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
		return nil, fmt.Errorf("%wfailed to generate key: %s", e.SigningError, err.Error())
	}
	return &Signer{
		alg:        model.ES512,
		privateKey: pk,
	}, nil
}

func NewSignerFromPrivateKey(privateKey crypto.PrivateKey) (*Signer, error) {
	ecdsaPrivateKey, ok := privateKey.(*ecdsa.PrivateKey)
	if !ok {
		return nil, fmt.Errorf("%winvalid key provided - should be instance of `*ecdsa.Privatekey`", e.InvalidPrivateKey)
	}
	if ecdsaPrivateKey.Curve.Params().Name != curveName {
		return nil, fmt.Errorf("%winvalid key provided - curve should be %s, was %s", e.InvalidPrivateKey, curveName, ecdsaPrivateKey.Curve.Params().Name)
	}
	return &Signer{
		alg:        model.ES512,
		privateKey: ecdsaPrivateKey,
	}, nil
}

func NewValidator(publicKey crypto.PublicKey) (*Validator, error) {
	ecdsaPublicKey, ok := publicKey.(*ecdsa.PublicKey)
	if !ok {
		return nil, fmt.Errorf("%winvalid key provided - should be instance of `*ecdsa.PublicKey`", e.InvalidPublicKey)
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
		return nil, fmt.Errorf("%winvalid hash function provided for specified signer", e.SigningError)
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
		return false, fmt.Errorf("%winvalid signature", e.InvalidSignature)
	}

	return ecdsa.Verify(validator.publicKey, bodyHash[:], r, s), nil
}

func (validator *Validator) Public() crypto.PublicKey {
	return validator.publicKey
}
