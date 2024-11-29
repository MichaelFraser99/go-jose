package model

import (
	"crypto"
	"fmt"
	"github.com/MichaelFraser99/go-jose/joseerror"
)

type Retriever func() ([]crypto.PublicKey, error)

type Mode int //todo: do we actually need this?

const (
	JWS Mode = iota
	JWE
)

type Jwks struct {
	Keys []map[string]any `json:"keys"`
}

// RetrieveByKeyID
//
// # Returns a jwk from the key-set by provided key ID
//
// If no match is found or multiple entries exist for a given key ID, an error is thrown.
// Any keys with malformed kid claims are ignored
func (j *Jwks) RetrieveByKeyID(kid string) (map[string]any, error) {
	var keys []map[string]any
	for _, key := range j.Keys {
		if keyKid, ok := key["kid"]; ok {
			if strKeyKid, ok := keyKid.(string); ok {
				if kid == strKeyKid {
					keys = append(keys, key)
				}
			}
		}
	}
	if len(keys) == 0 {
		return nil, fmt.Errorf("%wno matching key found for provided key ID", joseerror.KeystoreError)
	}
	if len(keys) > 1 {
		return nil, fmt.Errorf("%wmultiple keys found for provided key ID", joseerror.KeystoreError)
	}
	return keys[0], nil
}

type Signer interface {
	Alg() Algorithm
	crypto.Signer
}

// todo: these could have jwk methods - especially the Validator
type Validator interface {
	ValidateSignature(digest, signature []byte) (bool, error)
	Public() crypto.PublicKey
}

type Algorithm int

// todo: finish this list
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
	EdDSA //todo: this needs validator & signer implementations
	Unknown
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
	case EdDSA:
		return "EdDSA"
	default:
		return ""
	}
}

// GetAlgorithm takes in a string representation of an Algorithm ("ES256" or "HS384")
// If the provided string does not match a defined algorithm, Unknown is returned
func GetAlgorithm(alg string) Algorithm {
	switch alg {
	case "ES256":
		return ES256
	case "ES384":
		return ES384
	case "ES512":
		return ES512
	case "RS256":
		return RS256
	case "RS384":
		return RS384
	case "RS512":
		return RS512
	case "PS256":
		return PS256
	case "PS384":
		return PS384
	case "PS512":
		return PS512
	case "HS256":
		return HS256
	case "HS384":
		return HS384
	case "HS512":
		return HS512
	case "EdDSA":
		return EdDSA
	default:
		return Unknown
	}
}

type Opts struct {
	BitSize   int
	SecretKey *[]byte
}

type SignerOpts struct {
	Hash crypto.Hash
}

func (s SignerOpts) HashFunc() crypto.Hash {
	return s.Hash
}

func Pointer[T any](v T) *T {
	return &v
}
