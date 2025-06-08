package ps256

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"fmt"
	"github.com/MichaelFraser99/go-jose/internal/algorithms/common"
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
	if size < 2048 {
		return nil, fmt.Errorf("specified key bit size should be at least 2048")
	}
	pk, err := rsa.GenerateKey(rand.Reader, size)
	if err != nil {
		return nil, fmt.Errorf("%wfailed to generate key: %s", joseerror.SigningError, err.Error())
	}
	return &Signer{
		alg:        jwa.PS256,
		privateKey: pk,
	}, nil
}

func NewSignerFromPrivateKey(privateKey crypto.PrivateKey) (*Signer, error) {
	rsaPrivateKey, ok := privateKey.(*rsa.PrivateKey)
	if !ok {
		return nil, fmt.Errorf("%winvalid key provided - should be instance of `*rsa.Privatekey`", joseerror.InvalidPrivateKey)
	}
	return &Signer{
		alg:        jwa.PS256,
		privateKey: rsaPrivateKey,
	}, nil
}

func NewValidator(publicKey crypto.PublicKey) (*Validator, error) {
	rsaPublicKey, ok := publicKey.(*rsa.PublicKey)
	if !ok {
		return nil, fmt.Errorf("%winvalid key provided - should be instance of `*rsa.PublicKey`", joseerror.InvalidPublicKey)
	}
	return &Validator{
		alg:       jwa.PS256,
		publicKey: rsaPublicKey,
	}, nil
}

func NewValidatorFromJwk(jwk map[string]any) (*Validator, error) {
	publicKey, err := common.RSAPublicKeyFromJwk(jwk)
	if err != nil {
		return nil, err
	}
	return NewValidator(publicKey)
}

func (signer *Signer) Alg() jwa.Algorithm {
	return signer.alg
}

func (signer *Signer) Public() crypto.PublicKey {
	return signer.privateKey.Public()
}

func (signer *Signer) Sign(rand io.Reader, digest []byte, opts crypto.SignerOpts) (signature []byte, err error) {
	if opts != nil && opts.HashFunc() > 0 && opts.HashFunc() != crypto.SHA256 {
		return nil, fmt.Errorf("%winvalid hash function provided for specified signer", joseerror.SigningError)
	}

	var hashedDigest []byte
	if opts == nil || opts.HashFunc() == 0 {
		hash := sha256.Sum256(digest)
		hashedDigest = hash[:]
	} else {
		hashedDigest = make([]byte, len(digest))
		copy(hashedDigest, digest)
	}

	signature, err = common.RsaPSSSign(rand, *signer.privateKey, hashedDigest[:], crypto.SHA256, len(hashedDigest))
	if err != nil {
		return nil, err
	}

	return signature, nil
}

func (validator *Validator) ValidateSignature(digest, signature []byte) (bool, error) {
	hashedDigest := sha256.Sum256(digest)

	opts := &rsa.PSSOptions{
		SaltLength: len(hashedDigest),
		Hash:       crypto.SHA256,
	}
	err := rsa.VerifyPSS(validator.publicKey, crypto.SHA256, hashedDigest[:], signature, opts)

	if err != nil {
		return false, fmt.Errorf("%winvalid signature: %s", joseerror.InvalidSignature, err.Error())
	}

	return true, nil
}

func (validator *Validator) Public() crypto.PublicKey {
	return validator.publicKey
}
