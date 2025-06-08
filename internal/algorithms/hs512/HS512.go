package hs512

import (
	"bytes"
	"crypto"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha512"
	"fmt"
	"github.com/MichaelFraser99/go-jose/internal/algorithms/common"
	"github.com/MichaelFraser99/go-jose/jwa"
	"github.com/MichaelFraser99/go-jose/model"
	"hash"
	"io"
)

var (
	_ model.Signer    = &Signer{}
	_ model.Validator = &Validator{} //todo: tests
)

type Signer struct {
	alg    jwa.Algorithm
	secret common.SecretKey
	hasher hash.Hash
}

type Validator struct {
	alg    jwa.Algorithm
	secret common.SecretKey
	hasher hash.Hash
}

func (v Validator) ValidateSignature(digest, signature []byte) (bool, error) {
	mac := common.ProduceMac(v.hasher, digest)
	return bytes.Equal(signature, mac), nil
}

func (v Validator) Public() crypto.PublicKey {
	return v.secret
}

func NewSigner(secretKey *[]byte) (*Signer, error) {
	var secret []byte
	if secretKey != nil {
		secret = *secretKey
	} else {
		secret = make([]byte, 512)
		_, err := rand.Read(secret)
		if err != nil {
			return nil, fmt.Errorf("error generating secret key value: %w", err)
		}
	}

	h := hmac.New(func() hash.Hash {
		return sha512.New()
	}, secret)

	return &Signer{
		alg:    jwa.HS512,
		secret: secret,
		hasher: h,
	}, nil
}

func NewValidator(publicKey crypto.PublicKey) (*Validator, error) {
	if publicKey == nil {
		return nil, fmt.Errorf("nil public key provided")
	} else if _, ok := publicKey.(common.SecretKey); !ok {
		return nil, fmt.Errorf("invalid public key provided - must be of type `common.SecretKey` for hmac algorithms")
	}
	secret := []byte(publicKey.(common.SecretKey))
	h := hmac.New(func() hash.Hash {
		return sha512.New()
	}, secret)

	return &Validator{
		alg:    jwa.HS512,
		secret: secret,
		hasher: h,
	}, nil
}

func (signer *Signer) Alg() jwa.Algorithm {
	return signer.alg
}

func (signer *Signer) Public() crypto.PublicKey {
	return signer.secret
}

func (signer *Signer) Sign(rand io.Reader, digest []byte, opts crypto.SignerOpts) (signature []byte, err error) {
	return common.ProduceMac(signer.hasher, digest), nil
}
