package model

import (
	"crypto"
	"io"
	"strings"
)

// Signer signs JWS payloads per RFC 7515 / RFC 7518.
//
// The Sign method follows JOSE conventions rather than Go's crypto.Signer contract.
// It supports two modes:
//   - JOSE mode (opts == nil or opts.HashFunc() == 0): digest is the raw JWS Signing Input
//     and the implementation hashes it internally using the algorithm's designated hash.
//     This is the expected usage for JWS operations per RFC 7518.
//   - Pre-hashed mode (opts.HashFunc() != 0): digest is already hashed by the caller
//     and the implementation skips internal hashing. This supports interoperability with
//     callers following Go's crypto.Signer convention.
type Signer interface {
	Alg() Algorithm
	Public() crypto.PublicKey
	Sign(rand io.Reader, digest []byte, opts crypto.SignerOpts) (signature []byte, err error)
}

// Validator verifies JWS signatures per RFC 7515 / RFC 7518.
//
// ValidateSignature expects the raw JWS Signing Input as digest (not pre-hashed).
// The implementation hashes it internally using the algorithm's designated hash
// before performing verification.
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

// GetAlgorithm takes in a string representation of an Algorithm ("ES256" or "HS384")
// If the provided string does not match a defined algorithm, nil is returned
func GetAlgorithm(alg string) *Algorithm {
	switch strings.ToUpper(alg) {
	case "ES256":
		return algorithm(ES256)
	case "ES384":
		return algorithm(ES384)
	case "ES512":
		return algorithm(ES512)
	case "RS256":
		return algorithm(RS256)
	case "RS384":
		return algorithm(RS384)
	case "RS512":
		return algorithm(RS512)
	case "PS256":
		return algorithm(PS256)
	case "PS384":
		return algorithm(PS384)
	case "PS512":
		return algorithm(PS512)
	case "HS256":
		return algorithm(HS256)
	case "HS384":
		return algorithm(HS384)
	case "HS512":
		return algorithm(HS512)
	default:
		return nil
	}
}

func algorithm(a Algorithm) *Algorithm {
	return &a
}

// Opts configures key generation for new signers.
// BitSize applies to RSA algorithms. SecretKey applies to HMAC algorithms.
type Opts struct {
	BitSize   int
	SecretKey *[]byte
}

// SignerOpts implements crypto.SignerOpts and is used to signal that the digest
// passed to Sign has already been hashed. When provided with a non-zero Hash,
// the signer will skip internal hashing.
type SignerOpts struct {
	Hash crypto.Hash
}

func (s SignerOpts) HashFunc() crypto.Hash {
	return s.Hash
}
