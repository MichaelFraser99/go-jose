package rs384

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha512"
	"errors"
	"fmt"
	"github.com/MichaelFraser99/go-jose/internal/algorithms/common"
	"github.com/MichaelFraser99/go-jose/internal/algorithms/keycopy"
	"github.com/MichaelFraser99/go-jose/joseerror"
	"github.com/MichaelFraser99/go-jose/jwa"
	"io"
)

type Signer struct {
	alg        jwa.Algorithm
	privateKey *rsa.PrivateKey
}

type Validator struct {
	alg       jwa.Algorithm
	publicKey *rsa.PublicKey
}

func NewSigner(size int) (*Signer, error) {
	if size < common.MinimumRSAModulusBits {
		return nil, fmt.Errorf("%wspecified key bit size should be at least %d", joseerror.ErrInvalidPrivateKey, common.MinimumRSAModulusBits)
	}
	if size > common.MaximumRSAModulusBits {
		return nil, fmt.Errorf("%wspecified key bit size should be at most %d", joseerror.ErrInvalidPrivateKey, common.MaximumRSAModulusBits)
	}
	pk, err := rsa.GenerateKey(rand.Reader, size)
	if err != nil {
		return nil, fmt.Errorf("%wfailed to generate key: %s", joseerror.ErrSigningError, err.Error())
	}
	return &Signer{
		alg:        jwa.RS384,
		privateKey: pk,
	}, nil
}

func NewSignerFromPrivateKey(privateKey crypto.PrivateKey) (*Signer, error) {
	rsaPrivateKey, ok := privateKey.(*rsa.PrivateKey)
	if !ok {
		return nil, fmt.Errorf("%wshould be instance of *rsa.PrivateKey", joseerror.ErrInvalidPrivateKey)
	}
	completed, err := common.CompleteRSAPrivateKey(rsaPrivateKey)
	if err != nil {
		return nil, err
	}
	return &Signer{
		alg:        jwa.RS384,
		privateKey: completed,
	}, nil
}

func NewValidator(publicKey crypto.PublicKey) (*Validator, error) {
	rsaPublicKey, ok := publicKey.(*rsa.PublicKey)
	if !ok {
		return nil, fmt.Errorf("%wshould be instance of *rsa.PublicKey", joseerror.ErrInvalidPublicKey)
	}
	if err := common.CheckRSAPublicKey(rsaPublicKey, joseerror.ErrInvalidPublicKey); err != nil {
		return nil, err
	}
	return &Validator{
		alg:       jwa.RS384,
		publicKey: keycopy.RSAPublicKey(rsaPublicKey),
	}, nil
}

func (signer *Signer) Alg() jwa.Algorithm {
	return signer.alg
}

func (signer *Signer) Public() crypto.PublicKey {
	return keycopy.RSAPublicKey(&signer.privateKey.PublicKey)
}

func (signer *Signer) Sign(rand io.Reader, digest []byte, opts crypto.SignerOpts) (signature []byte, err error) {
	if opts != nil && opts.HashFunc() > 0 && opts.HashFunc() != crypto.SHA384 {
		return nil, fmt.Errorf("%winvalid hash function provided for specified signer", joseerror.ErrSigningError)
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

	if errors.Is(err, rsa.ErrVerification) {
		return false, nil
	}
	if err != nil {
		return false, fmt.Errorf("%w%s", joseerror.ErrInvalidSignature, err.Error())
	}

	return true, nil
}

func (validator *Validator) Public() crypto.PublicKey {
	return keycopy.RSAPublicKey(validator.publicKey)
}
