package mldsa

import (
	"crypto"
	fips204 "crypto/mldsa"
	"fmt"
	"io"

	"github.com/MichaelFraser99/go-jose/internal/algorithms/common"
	"github.com/MichaelFraser99/go-jose/joseerror"
	"github.com/MichaelFraser99/go-jose/jwa"
)

type Signer struct {
	alg        jwa.Algorithm
	privateKey *fips204.PrivateKey
}

type Validator struct {
	publicKey *fips204.PublicKey
}

func parameters(alg jwa.Algorithm) fips204.Parameters {
	params, _ := common.MLDSAParameters(alg.String())
	return params
}

func NewSigner(alg jwa.Algorithm) (*Signer, error) {
	privateKey, err := fips204.GenerateKey(parameters(alg))
	if err != nil {
		return nil, fmt.Errorf("%wfailed to generate key: %s", joseerror.ErrSigningError, err.Error())
	}
	return &Signer{
		alg:        alg,
		privateKey: privateKey,
	}, nil
}

func NewSignerFromPrivateKey(alg jwa.Algorithm, privateKey crypto.PrivateKey) (*Signer, error) {
	key, ok := privateKey.(*fips204.PrivateKey)
	if !ok {
		return nil, fmt.Errorf("%wshould be instance of *mldsa.PrivateKey", joseerror.ErrInvalidPrivateKey)
	}
	usable, err := common.UsableMLDSAPrivateKey(key, parameters(alg))
	if err != nil {
		return nil, err
	}
	return &Signer{
		alg:        alg,
		privateKey: usable,
	}, nil
}

func NewValidator(alg jwa.Algorithm, publicKey crypto.PublicKey) (*Validator, error) {
	key, ok := publicKey.(*fips204.PublicKey)
	if !ok {
		return nil, fmt.Errorf("%wshould be instance of *mldsa.PublicKey", joseerror.ErrInvalidPublicKey)
	}
	usable, err := common.UsableMLDSAPublicKey(key, parameters(alg), joseerror.ErrInvalidPublicKey)
	if err != nil {
		return nil, err
	}
	return &Validator{
		publicKey: usable,
	}, nil
}

func (signer *Signer) Alg() jwa.Algorithm {
	return signer.alg
}

func (signer *Signer) Public() crypto.PublicKey {
	return signer.privateKey.Public()
}

func (signer *Signer) Sign(_ io.Reader, digest []byte, opts crypto.SignerOpts) (signature []byte, err error) {
	if opts != nil && opts.HashFunc() != 0 {
		return nil, fmt.Errorf("%wML-DSA in JOSE signs the whole input, so it has no pre-hashed or external mu mode", joseerror.ErrSigningError)
	}
	if o, ok := opts.(*fips204.Options); ok && o != nil && o.Context != "" {
		return nil, fmt.Errorf("%wRFC 9964 section 5 requires an empty ML-DSA context", joseerror.ErrSigningError)
	}
	return signer.privateKey.Sign(nil, digest, nil)
}

func (validator *Validator) ValidateSignature(digest, signature []byte) (bool, error) {
	return fips204.Verify(validator.publicKey, digest, signature, nil) == nil, nil
}

func (validator *Validator) Public() crypto.PublicKey {
	return validator.publicKey
}
