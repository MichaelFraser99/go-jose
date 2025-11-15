package model

import (
	"crypto"
	"fmt"
	"github.com/MichaelFraser99/go-jose/joseerror"
	"github.com/MichaelFraser99/go-jose/jwa"
)

type JoseOptions struct {
	// UseTokenProvidedKeys determines if cryptographic keys provided in the token header should be used for verification. Defaults to true
	UseTokenProvidedKeys bool

	// AllowedSigningAlgorithms defines the list of acceptable algorithms for token signature verification. If not specified, all algorithms are permitted
	AllowedSigningAlgorithms []jwa.Algorithm
}

type Retriever func() ([]crypto.PublicKey, error)

type Mode int //todo: do we actually need this?

const (
	JWS Mode = iota
	JWE
)

type Jwks struct {
	Keys []map[string]any `json:"keys"`
	Opts struct {
		EnforceUniqueKIDs bool //todo: we should enforce this on marshal too
	} `json:"-"`
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
		return nil, fmt.Errorf("%wno matching key found for provided key ID", joseerror.ErrKeystoreError)
	}
	if len(keys) > 1 {
		return nil, fmt.Errorf("%wmultiple keys found for provided key ID", joseerror.ErrKeystoreError)
	}
	return keys[0], nil
}

func (j *Jwks) Add(jwk map[string]any) error {
	if kid, ok := jwk["kid"]; ok && j.Opts.EnforceUniqueKIDs {
		if sKid, ok := kid.(string); !ok {
			return fmt.Errorf("%w malformed key ID found for JWK", joseerror.ErrKeystoreError)
		} else {
			if existing, _ := j.RetrieveByKeyID(sKid); existing != nil {
				return fmt.Errorf("%w provided jwk has kid value matching a value already present in the keyset", joseerror.ErrKeystoreError)
			}
		}
	}
	j.Keys = append(j.Keys, jwk)
	return nil
}

type Signer interface {
	Alg() jwa.Algorithm
	crypto.Signer
}

// todo: these could have jwk methods - especially the Validator
type Validator interface {
	ValidateSignature(digest, signature []byte) (bool, error)
	Public() crypto.PublicKey
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
