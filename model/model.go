package model

import (
	"crypto"
	"io"
)

type Signer interface {
	Alg() Algorithm
	Public() crypto.PublicKey
	Validator() Validator
	Sign(rand io.Reader, digest []byte, opts crypto.SignerOpts) (signature []byte, err error)
}

type Validator interface {
	ValidateSignature(digest, signature []byte) (bool, error)
	Jwk() map[string]string
}

type Algorithm int

const (
	ES256 Algorithm = iota
	ES384
	ES512
	RS256
	RS384
	RS512
)

func (a Algorithm) String() string {
	switch a {
	case ES256:
		return "ES256"
	case ES384:
		return "ES384"
	case ES512:
		return "ES512"
	default:
		return ""
	}
}

type SignerOpts struct {
	Hash crypto.Hash
}

func (s SignerOpts) HashFunc() crypto.Hash {
	return s.Hash
}
