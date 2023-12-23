package model

import (
	"crypto"
	"io"
)

type Signer interface {
	Alg() Algorithm
	Public() crypto.PublicKey
	Sign(rand io.Reader, digest []byte, opts crypto.SignerOpts) (signature []byte, err error)
}

type Validator interface {
	ValidateSignature(digest, signature []byte) (bool, error)
	Public() crypto.PublicKey
}

type Algorithm int

const (
	ES256 Algorithm = iota
	ES384
	ES512
	RS256
	RS384
	RS512
	PS256
	PS384
	PS512
	HS256
	HS384
	HS512
)

func (a Algorithm) String() string {
	switch a {
	case ES256:
		return "ES256"
	case ES384:
		return "ES384"
	case ES512:
		return "ES512"
	case RS256:
		return "RS256"
	case RS384:
		return "RS384"
	case RS512:
		return "RS512"
	case PS256:
		return "PS256"
	case PS384:
		return "PS384"
	case PS512:
		return "PS512"
	case HS256:
		return "HS256"
	case HS384:
		return "HS384"
	case HS512:
		return "HS512"
	default:
		return ""
	}
}

type Opts struct {
	BitSize int
}

type SignerOpts struct {
	Hash crypto.Hash
}

func (s SignerOpts) HashFunc() crypto.Hash {
	return s.Hash
}
