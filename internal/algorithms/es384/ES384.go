package es384

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha512"
	"fmt"
	"github.com/MichaelFraser99/go-jose/internal/algorithms/common"
	"github.com/MichaelFraser99/go-jose/internal/algorithms/keycopy"
	"github.com/MichaelFraser99/go-jose/joseerror"
	"github.com/MichaelFraser99/go-jose/jwa"
	"io"
)

const keySize = 96

type Signer struct {
	alg        jwa.Algorithm
	privateKey *ecdsa.PrivateKey
}

type Validator struct {
	publicKey *ecdsa.PublicKey
}

func NewSigner() (*Signer, error) {
	curve := elliptic.P384()
	pk, err := ecdsa.GenerateKey(curve, rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("%wfailed to generate key: %s", joseerror.ErrSigningError, err.Error())
	}
	return &Signer{
		alg:        jwa.ES384,
		privateKey: pk,
	}, nil
}

func NewSignerFromPrivateKey(privateKey crypto.PrivateKey) (*Signer, error) {
	ecdsaPrivateKey, ok := privateKey.(*ecdsa.PrivateKey)
	if !ok {
		return nil, fmt.Errorf("%wshould be instance of *ecdsa.PrivateKey", joseerror.ErrInvalidPrivateKey)
	}
	if err := common.CheckECDSAPrivateKey(ecdsaPrivateKey, elliptic.P384()); err != nil {
		return nil, err
	}
	return &Signer{
		alg:        jwa.ES384,
		privateKey: keycopy.ECDSAPrivateKey(ecdsaPrivateKey),
	}, nil
}

func NewValidator(publicKey crypto.PublicKey) (*Validator, error) {
	ecdsaPublicKey, ok := publicKey.(*ecdsa.PublicKey)
	if !ok {
		return nil, fmt.Errorf("%wshould be instance of *ecdsa.PublicKey", joseerror.ErrInvalidPublicKey)
	}
	if err := common.CheckECDSAPublicKey(ecdsaPublicKey, elliptic.P384(), joseerror.ErrInvalidPublicKey); err != nil {
		return nil, err
	}
	return &Validator{
		publicKey: keycopy.ECDSAPublicKey(ecdsaPublicKey),
	}, nil
}

func (signer *Signer) Alg() jwa.Algorithm {
	return signer.alg
}

func (signer *Signer) Public() crypto.PublicKey {
	return keycopy.ECDSAPublicKey(&signer.privateKey.PublicKey)
}

func (signer *Signer) Sign(rand io.Reader, digest []byte, opts crypto.SignerOpts) (signature []byte, err error) {
	if opts != nil && opts.HashFunc() > 0 && opts.HashFunc() != crypto.SHA384 {
		return nil, fmt.Errorf("%winvalid hash function provided for specified signer", joseerror.ErrSigningError)
	}

	if opts == nil || opts.HashFunc() == 0 {
		hashedDigest := sha512.Sum384(digest)
		digest = hashedDigest[:]
	} else if len(digest) != crypto.SHA384.Size() {
		return nil, fmt.Errorf("%wa pre-hashed digest for ES384 is %d bytes, got %d", joseerror.ErrSigningError, crypto.SHA384.Size(), len(digest))
	}

	signature, err = common.EllipticCurveSign(rand, *signer.privateKey, digest[:], keySize)
	if err != nil {
		return nil, err
	}

	return signature, nil
}

func (validator *Validator) ValidateSignature(digest, signature []byte) (bool, error) {
	bodyHash := sha512.Sum384(digest)

	r, s, err := common.ExtractRSFromSignature(signature, keySize)
	if err != nil {
		return false, nil
	}

	return ecdsa.Verify(validator.publicKey, bodyHash[:], r, s), nil
}

func (validator *Validator) Public() crypto.PublicKey {
	return keycopy.ECDSAPublicKey(validator.publicKey)
}
