package hs384

import (
	"bytes"
	"crypto"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha512"
	"fmt"
	"github.com/MichaelFraser99/go-jose/model"
	"hash"
	"io"
)

type Signer struct {
	alg    model.Algorithm
	secret SecretKey
	hasher hash.Hash
}

type SecretKey []byte

func (s *SecretKey) Equal(x crypto.PublicKey) bool {
	secretKey, ok := x.(*SecretKey)
	if !ok {
		return false
	}

	return bytes.Equal(*s, *secretKey)
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

	h := hmac.New(func() hash.Hash {
		return sha512.New384()
	}, secret)

	return &Signer{
		alg:    model.HS384,
		secret: secret,
		hasher: h,
	}, nil
}

func (signer *Signer) Alg() model.Algorithm {
	return signer.alg
}

func (signer *Signer) Public() crypto.PublicKey {
	return signer.secret
}

func (signer *Signer) Sign(rand io.Reader, digest []byte, opts crypto.SignerOpts) (signature []byte, err error) {
	signer.hasher.Write(digest)
	signature = signer.hasher.Sum(nil)
	signer.hasher.Reset()

	return signature, nil
}
