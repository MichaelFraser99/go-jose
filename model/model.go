package model

import (
	"crypto"
	"crypto/x509"
	"fmt"
	"github.com/MichaelFraser99/go-jose/joseerror"
	"github.com/MichaelFraser99/go-jose/jwa"
	"net/http"
	"time"
)

type JoseOptions struct {
	// IgnoreTokenProvidedKeys stops the keys a token carries in its own header — jwk,
	// jku, x5c and x5u — from being used for verification. They are used by default,
	// so a caller wanting only its own key material opts out here.
	//
	// The sense is negative so that the zero value is the default. The field this
	// replaced read UseTokenProvidedKeys and documented itself as defaulting to true,
	// which held only while a caller passed no options at all: constructing the struct
	// to set anything else zeroed it and silently turned every header key source off.
	IgnoreTokenProvidedKeys bool

	// HttpClient fetches the resources a token's jku and x5u headers name. Both URLs
	// come from the header of the token being verified, so this library makes an
	// outbound request to an address a peer chose: supply a client whose transport
	// rejects the destinations your deployment will not allow.
	//
	// With no client, jku and x5u contribute no key.
	HttpClient *http.Client

	// AllowedSigningAlgorithms defines the list of acceptable algorithms for token signature verification. If not specified, all algorithms are permitted
	AllowedSigningAlgorithms []jwa.Algorithm

	// ClockSkewLeeway widens the window the iat, nbf and exp claims are judged against, to allow for clock skew between the issuer and this verifier. A value of zero or less grants none. Defaults to 0
	ClockSkewLeeway time.Duration

	// AcceptedTypes lists the media types the 'typ' header may name. They are
	// compared as RFC 7515 section 4.1.9 requires: case-insensitively, with
	// "application/" treated as prepended to any value containing no "/".
	//
	// With none listed, 'typ' is not checked.
	AcceptedTypes []string

	// RequireKeyIdentifier refuses a token whose 'kid' header is absent or is not a
	// non-empty string. RFC 7517 section 4.5 leaves 'kid' optional, so this is off by
	// default; a profile that pins a key by identifier will want it on.
	RequireKeyIdentifier bool

	// UnderstoodCriticalHeaders names the extension header parameters this caller
	// understands. RFC 7515 section 4.1.11 says a JWS whose 'crit' lists anything the
	// recipient does not understand MUST be rejected, so an entry not named here is
	// refused. Names are compared exactly, since a header parameter name is.
	//
	// With none named, any 'crit' is refused, because this library understands no
	// extensions of its own.
	UnderstoodCriticalHeaders []string

	// X509Roots holds the trust anchors a certificate chain named by the x5c or x5u
	// header must validate against. RFC 7515 section 4.1.6 requires a recipient to
	// validate the chain per RFC 5280, and RFC 5280 path validation takes a trust
	// anchor as an input, so neither header can be used without one.
	//
	// With no roots configured, a token's x5c and x5u headers are ignored: they
	// contribute no key, and the token verifies only if another source does.
	X509Roots *x509.CertPool
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
