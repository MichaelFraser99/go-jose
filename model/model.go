package model

import (
	"crypto"
	"fmt"
	"github.com/MichaelFraser99/go-jose/joseerror"
	"github.com/MichaelFraser99/go-jose/jwa"
	"time"
)

type JoseOptions struct {
	// UseTokenProvidedKeys determines if cryptographic keys provided in the token header should be used for verification. Defaults to true
	UseTokenProvidedKeys bool

	// AllowedSigningAlgorithms defines the list of acceptable algorithms for token signature verification. If not specified, all algorithms are permitted
	AllowedSigningAlgorithms []jwa.Algorithm

	// ClockSkewLeeway widens the window the iat, nbf and exp claims are judged against, to allow for clock skew between the issuer and this verifier. A value of zero or less grants none. Defaults to 0
	ClockSkewLeeway time.Duration
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

// RetrieveByKeyID returns every jwk in the key set whose kid matches the one given,
// in the order the set holds them.
//
// RFC 7517 section 4.5 does not require a kid to be unique within a key set, so a
// set may legitimately carry more than one key under one kid, as an issuer mid key
// rotation does. An error is returned only when no key carries the kid. Keys with
// an absent or non-string kid are ignored.
func (j *Jwks) RetrieveByKeyID(kid string) ([]map[string]any, error) {
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
	return keys, nil
}

func (j *Jwks) Add(jwk map[string]any) error {
	if kid, ok := jwk["kid"]; ok && j.Opts.EnforceUniqueKIDs {
		if sKid, ok := kid.(string); !ok {
			return fmt.Errorf("%w malformed key ID found for JWK", joseerror.ErrKeystoreError)
		} else {
			if existing, _ := j.RetrieveByKeyID(sKid); len(existing) > 0 {
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
