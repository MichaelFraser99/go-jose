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
	// UseTokenProvidedKeys lets a key the token names through its jwk or jku header
	// verify it. Off by default, including when no options are passed: RFC 7515 section
	// 10.3 requires the origin of a key to be authenticated, and neither header carries
	// anything that authenticates it. x5c and x5u are governed by X509Roots instead.
	//
	// When on, a header key and the caller's own retriever are both tried, and either
	// may verify the token.
	UseTokenProvidedKeys bool

	// HttpClient fetches the resources a token's jku and x5u headers name. Both URLs
	// come from the header of the token being verified, so this library makes an
	// outbound request to an address a peer chose: supply a client whose transport
	// rejects the destinations your deployment will not allow. FetchTimeout bounds each
	// fetch whatever Timeout the client sets, provided its transport honours the
	// request's context.
	//
	// With no client, jku and x5u contribute no key.
	HttpClient *http.Client

	// FetchTimeout bounds each jku or x5u fetch, from sending the request to reading the
	// last byte of the body, provided the HttpClient's transport honours the request's
	// context. Zero or less means 10 seconds. A deadline or cancellation on the context
	// passed to jwt.Validate or jws.VerifyCompactSerialization also applies.
	FetchTimeout time.Duration

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
	// Setting roots is what opts in to x5c and x5u: a chain that validates against
	// them authenticates the key's origin, as RFC 7515 section 10.3 requires. x5u also
	// needs HttpClient. With no roots configured, both headers are ignored.
	//
	// When a retriever is also given, any certificate that chains to these roots can
	// verify the token, not only the retriever's key.
	X509Roots *x509.CertPool

	// X509ExtKeyUsages names the extended key usages that permit an x5c or x5u
	// certificate to verify a JWS. RFC 5280 section 4.2.1.12 says a certificate whose
	// extension is present MUST only be used for a purpose it names, and no purpose is
	// registered for JWS. When set, the signing certificate and every certificate
	// above it must permit one of these, or carry no extended key usage. Naming
	// x509.ExtKeyUsageAny turns the check off.
	//
	// When unset, a signing certificate whose extension is present must name
	// anyExtendedKeyUsage.
	X509ExtKeyUsages []x509.ExtKeyUsage
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

// Signer signs JWS payloads per RFC 7515 / RFC 7518.
//
// The Sign method follows JOSE conventions rather than Go's crypto.Signer contract.
// It supports two modes:
//   - JOSE mode (opts == nil or opts.HashFunc() == 0): digest is the raw JWS Signing Input
//     and the implementation hashes it internally using the algorithm's designated hash.
//     This is the expected usage for JWS operations per RFC 7518.
//   - Pre-hashed mode (opts.HashFunc() != 0): digest is already hashed by the caller
//     and the implementation skips internal hashing. This supports interoperability with
//     callers following Go's crypto.Signer convention. It applies to the ES, RS and PS
//     algorithms. The HS algorithms have no such mode, because HMAC is itself the keyed
//     hash, and refuse a non-zero HashFunc rather than mac an already hashed digest.
type Signer interface {
	Alg() jwa.Algorithm
	crypto.Signer
}

// Validator verifies JWS signatures per RFC 7515 / RFC 7518.
//
// ValidateSignature expects the raw JWS Signing Input as digest (not pre-hashed).
// The implementation hashes it internally using the algorithm's designated hash
// before performing verification.
//
// todo: these could have jwk methods - especially the Validator
type Validator interface {
	ValidateSignature(digest, signature []byte) (bool, error)
	Public() crypto.PublicKey
}

// Opts configures key generation for new signers.
// BitSize applies to RSA algorithms. SecretKey applies to HMAC algorithms.
type Opts struct {
	BitSize   int
	SecretKey *[]byte
}

// SignerOpts implements crypto.SignerOpts and signals that the digest passed to
// Sign has already been hashed. ES, RS and PS signers skip their internal hashing
// when Hash is non-zero, and refuse a Hash that is not their own. HMAC signers have
// no pre-hashed mode and refuse a non-zero Hash.
type SignerOpts struct {
	Hash crypto.Hash
}

func (s SignerOpts) HashFunc() crypto.Hash {
	return s.Hash
}

func Pointer[T any](v T) *T {
	return &v
}
