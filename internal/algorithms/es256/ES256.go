package es256

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"fmt"
	"github.com/MichaelFraser99/go-jose/internal/algorithms/common"
	"github.com/MichaelFraser99/go-jose/joseerror"
	"github.com/MichaelFraser99/go-jose/jwa"
	"io"
)

const keySize = 64

type Signer struct {
	alg        jwa.Algorithm
	privateKey *ecdsa.PrivateKey
}

type Validator struct {
	publicKey *ecdsa.PublicKey
}

func NewSigner() (*Signer, error) {
	curve := elliptic.P256()
	pk, err := ecdsa.GenerateKey(curve, rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("%wfailed to generate key: %s", joseerror.ErrSigningError, err.Error())
	}
	return &Signer{
		alg:        jwa.ES256,
		privateKey: pk,
	}, nil
}

func NewSignerFromPrivateKey(privateKey crypto.PrivateKey) (*Signer, error) {
	ecdsaPrivateKey, ok := privateKey.(*ecdsa.PrivateKey)
	if !ok {
		return nil, fmt.Errorf("%wshould be instance of *ecdsa.PrivateKey", joseerror.ErrInvalidPrivateKey)
	}
	if err := common.CheckECDSAPrivateKey(ecdsaPrivateKey, elliptic.P256()); err != nil {
		return nil, err
	}
	return &Signer{
		alg:        jwa.ES256,
		privateKey: ecdsaPrivateKey,
	}, nil
}

func NewValidator(publicKey crypto.PublicKey) (*Validator, error) {
	ecdsaPublicKey, ok := publicKey.(*ecdsa.PublicKey)
	if !ok {
		return nil, fmt.Errorf("%wshould be instance of *ecdsa.PublicKey", joseerror.ErrInvalidPublicKey)
	}
	if err := common.CheckECDSAPublicKey(ecdsaPublicKey, elliptic.P256(), joseerror.ErrInvalidPublicKey); err != nil {
		return nil, err
	}
	return &Validator{
		publicKey: ecdsaPublicKey,
	}, nil
}

func (signer *Signer) Alg() jwa.Algorithm {
	return signer.alg
}

func (signer *Signer) Public() crypto.PublicKey {
	return signer.privateKey.Public()
}

func (signer *Signer) Sign(rand io.Reader, digest []byte, opts crypto.SignerOpts) (signature []byte, err error) {
	if opts != nil && opts.HashFunc() > 0 && opts.HashFunc() != crypto.SHA256 {
		return nil, fmt.Errorf("%winvalid hash function provided for specified signer", joseerror.ErrSigningError)
	}

	if opts == nil || opts.HashFunc() == 0 {
		hashedDigest := sha256.Sum256(digest)
		digest = hashedDigest[:]
	} else if len(digest) != crypto.SHA256.Size() {
		return nil, fmt.Errorf("%wa pre-hashed digest for ES256 is %d bytes, got %d", joseerror.ErrSigningError, crypto.SHA256.Size(), len(digest))
	}

	signature, err = common.EllipticCurveSign(rand, *signer.privateKey, digest[:], keySize)
	if err != nil {
		return nil, err
	}

	return signature, nil
}

func (validator *Validator) ValidateSignature(digest, signature []byte) (bool, error) {
	//todo: I don't think we should eagerly hash the digest iun any validator - rather, return control to the end user
	bodyHash := sha256.Sum256(digest)

	r, s, err := common.ExtractRSFromSignature(signature, keySize)
	if err != nil {
		return false, nil
	}

	return ecdsa.Verify(validator.publicKey, bodyHash[:], r, s), nil
}

func (validator *Validator) Public() crypto.PublicKey {
	return validator.publicKey
}
