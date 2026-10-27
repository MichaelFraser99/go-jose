package hs384

import (
	"crypto"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha512"
	"fmt"
	"github.com/MichaelFraser99/go-jose/internal/algorithms/common"
	"github.com/MichaelFraser99/go-jose/jwa"
	"github.com/MichaelFraser99/go-jose/model"
	"io"
	"slices"
)

var (
	_ model.Signer    = &Signer{}
	_ model.Validator = &Validator{}
)

type Signer struct {
	alg    jwa.Algorithm
	secret common.SecretKey
}

type Validator struct {
	alg    jwa.Algorithm
	secret common.SecretKey
}

func (v Validator) ValidateSignature(digest, signature []byte) (bool, error) {
	mac := common.ProduceMac(hmac.New(sha512.New384, v.secret), digest)
	return hmac.Equal(signature, mac), nil
}

func (v Validator) Public() crypto.PublicKey {
	return slices.Clone(v.secret)
}

func NewSigner(secretKey *[]byte) (*Signer, error) {
	var secret []byte
	if secretKey != nil {
		secret = *secretKey
	} else {
		secret = make([]byte, 384)
		_, err := rand.Read(secret)
		if err != nil {
			return nil, fmt.Errorf("error generating secret key value: %w", err)
		}
	}

	return &Signer{
		alg:    jwa.HS384,
		secret: slices.Clone(secret),
	}, nil
}

func NewValidator(publicKey crypto.PublicKey) (*Validator, error) {
	if publicKey == nil {
		return nil, fmt.Errorf("nil public key provided")
	} else if _, ok := publicKey.(common.SecretKey); !ok {
		return nil, fmt.Errorf("invalid public key provided - must be of type `common.SecretKey` for hmac algorithms")
	}
	secret := []byte(publicKey.(common.SecretKey))
	return &Validator{
		alg:    jwa.HS384,
		secret: slices.Clone(secret),
	}, nil
}

func (signer *Signer) Alg() jwa.Algorithm {
	return signer.alg
}

func (signer *Signer) Public() crypto.PublicKey {
	return slices.Clone(signer.secret)
}

func (signer *Signer) Sign(rand io.Reader, digest []byte, opts crypto.SignerOpts) (signature []byte, err error) {
	return common.ProduceMac(hmac.New(sha512.New384, signer.secret), digest), nil
}
