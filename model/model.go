package model

import (
	"crypto"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"github.com/MichaelFraser99/go-jose/internal/jose/jsonutils"
	"github.com/MichaelFraser99/go-jose/joseerror"
	"github.com/MichaelFraser99/go-jose/jwa"
	"io"
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
	// request's context. A fetch uses a copy of this client with no cookie jar, so it
	// sends no cookies and stores none, as RFC 8725 section 3.10 asks.
	//
	// Every request of a fetch, including each redirect hop, must be https, as RFC 7515
	// sections 4.1.2 and 4.1.5 require. Any other is refused before it is sent.
	//
	// With no client, jku and x5u contribute no key.
	HttpClient *http.Client

	// FetchTimeout bounds each jku or x5u fetch, from sending the request to reading the
	// last byte of the body, provided the HttpClient's transport honours the request's
	// context. Zero or less means 10 seconds. A deadline or cancellation on the context
	// passed to jwt.Validate or jws.VerifyCompactSerialization also applies.
	FetchTimeout time.Duration

	// MaxKeysTried bounds how many keys a token's signature is checked against,
	// across every key source. RFC 7517 section 4.5 does not require a kid to be
	// unique, so a key set a peer publishes may hold thousands of keys under one
	// kid, each costing a signature verification. A token that would need more is
	// refused with ErrTooManyKeys. A key that cannot be used with the token's alg
	// costs no verification and does not count. jwe.Decrypt applies the same
	// bound to the decrypters of the token's alg. Zero or less means 100.
	MaxKeysTried int

	// AllowedSigningAlgorithms defines the list of acceptable algorithms for token signature verification. If not specified, all algorithms are permitted
	AllowedSigningAlgorithms []jwa.Algorithm

	// AllowedKeyManagementAlgorithms lists the 'alg' values a JWE may name. With
	// none named, every key management algorithm this library implements is
	// permitted. A JWE naming another is refused with ErrUnsupportedAlgorithm.
	AllowedKeyManagementAlgorithms []jwa.Algorithm

	// AllowedContentEncryptionAlgorithms lists the 'enc' values a JWE may name.
	// With none named, every content encryption algorithm this library
	// implements is permitted. A JWE naming another is refused with
	// ErrUnsupportedAlgorithm.
	AllowedContentEncryptionAlgorithms []jwa.Encryption

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

	// IgnoreKeyUse lets a jwk or jku key verify a token whatever its "use" and "key_ops"
	// members say. Off by default, including when no options are passed: a key whose
	// "use" is present and is not "sig", or whose "key_ops" is present and lacks
	// "verify", is refused, because its publisher marked it as not for verifying
	// signatures (RFC 7517 sections 4.2 and 4.3). Neither member is required by any RFC,
	// so turn this on to accept keys whose publisher marks them inconsistently.
	IgnoreKeyUse bool

	// X509ExtKeyUsages names the extended key usages that permit an x5c or x5u
	// certificate to verify a JWS. RFC 5280 section 4.2.1.12 says a certificate whose
	// extension is present MUST only be used for a purpose it names, and no purpose is
	// registered for JWS. When unset, only the signing certificate is checked, and
	// if its extension is present it must name anyExtendedKeyUsage. When set, Go's
	// chain verification nests extended key usage, so the signing certificate and
	// every certificate above it must permit one of these, or carry no extended key
	// usage. Naming x509.ExtKeyUsageAny turns this purpose check off. A signing
	// certificate or intermediate whose extension names no purpose is refused in
	// every case, as RFC 5280 section 4.2.1.12 allows no empty extension.
	X509ExtKeyUsages []x509.ExtKeyUsage

	// ExpectedAudience names this recipient. When set, jwt.Validate requires the "aud"
	// claim to hold a value equal to one of these, compared exactly and case-sensitively
	// as RFC 7519 section 4.1.3 requires. A token with no "aud" is refused with
	// ErrMissingClaim, as RFC 8725 section 3.9 requires, and one naming only other
	// recipients with ErrAudienceMismatch. An empty string names no recipient, so
	// jwt.Validate refuses options holding one with ErrInvalidOptions.
	//
	// With none named, "aud" is not compared, though its type is still checked. This
	// default departs from RFC 7519 section 4.1.3, which says: "If the principal
	// processing the claim does not identify itself with a value in the "aud" claim
	// when this claim is present, then the JWT MUST be rejected." Set ExpectedAudience
	// to meet that MUST.
	ExpectedAudience []string
}

// Retriever supplies the keys a token may be verified with. A bare
// crypto.PublicKey carries no algorithm. An EC key is bound to one algorithm by
// its curve, as RFC 7518 section 3.4 defines each ES algorithm over one curve.
// An RSA key verifies a token under any of RS256 to PS512 that the token names,
// and an HMAC secret under any HS algorithm whose minimum length it meets.
// RFC 8725 section 3.1 requires each key to be used with exactly one algorithm,
// so bind such a key to its algorithm with JoseOptions.AllowedSigningAlgorithms.
// That list applies to every key the retriever returns, so keys bound to
// different algorithms of one family need separate retrievers.
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

// MarshalJSON writes a JWK Set. RFC 7517 section 5 requires the "keys" member to be an
// array, so a set with no keys is written as an empty array rather than null.
func (j Jwks) MarshalJSON() ([]byte, error) {
	keys := j.Keys
	if keys == nil {
		keys = []map[string]any{}
	}
	return json.Marshal(struct {
		Keys []map[string]any `json:"keys"`
	}{keys})
}

// UnmarshalJSON reads a JWK Set. RFC 7517 section 5 requires a JSON object with a
// "keys" member holding an array of JWKs, each a JSON object, so anything else,
// including a JSON null in place of the set or of a member, is refused with
// ErrKeystoreError. So is a document that is not UTF-8 (RFC 8259 section 8.1) or that
// holds an unpaired UTF-16 surrogate escape (RFC 8259 section 8.2). The member name is
// matched exactly, by the RFC 7515 section 5.3 comparison rules; other members are
// ignored. A struct field that may hold no set should be a *Jwks, which a JSON null
// leaves nil. Opts.EnforceUniqueKIDs applies to Add, not to decoding.
func (j *Jwks) UnmarshalJSON(data []byte) error {
	members, err := jsonutils.DecodeJSONObject(data)
	if err != nil {
		return fmt.Errorf("%wa JWK Set must be a UTF-8 JSON object: %w", joseerror.ErrKeystoreError, err)
	}
	raw, present := members["keys"]
	if !present {
		return fmt.Errorf("%wa JWK Set must have a \"keys\" member", joseerror.ErrKeystoreError)
	}
	values, isArray := raw.([]any)
	if !isArray {
		return fmt.Errorf("%wthe \"keys\" member of a JWK Set must be an array of JWKs", joseerror.ErrKeystoreError)
	}
	keys := make([]map[string]any, 0, len(values))
	for i, value := range values {
		key, isObject := value.(map[string]any)
		if !isObject {
			return fmt.Errorf("%wmember %d of the \"keys\" array of a JWK Set must be a JSON object", joseerror.ErrKeystoreError, i)
		}
		keys = append(keys, key)
	}
	j.Keys = keys
	return nil
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
			return fmt.Errorf("%wmalformed key ID found for JWK", joseerror.ErrKeystoreError)
		} else {
			if existing, _ := j.RetrieveByKeyID(sKid); len(existing) > 0 {
				return fmt.Errorf("%wprovided jwk has kid value matching a value already present in the keyset", joseerror.ErrKeystoreError)
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
//     Ed25519 refuses it too: RFC 9864 section 4.1.1 names pure Ed25519, which signs
//     the whole input. So does ML-DSA: RFC 9964 section 5 signs with FIPS 204
//     Algorithm 2, pure ML-DSA, over the whole input.
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

// Encrypter determines the Content Encryption Key of a JWE and encrypts it for
// the recipient, as RFC 7516 section 5.1 steps 1 to 5 describe.
//
// WrapKey returns a CEK of the length enc requires and the JWE Encrypted Key,
// which is empty for "dir". An algorithm that defines header parameters of its
// own, such as "epk" (RFC 7518 section 4.6.1), writes them into header, which
// becomes the JWE Protected Header.
type Encrypter interface {
	Alg() jwa.Algorithm
	Public() crypto.PublicKey
	WrapKey(rand io.Reader, enc jwa.Encryption, header map[string]any) (cek, encryptedKey []byte, err error)
}

// Decrypter recovers the Content Encryption Key of a JWE from its JWE Encrypted
// Key, as RFC 7516 section 5.2 steps 9 and 10 describe. It is a crypto.Decrypter:
// Decrypt takes the JWE Encrypted Key as msg and a DecrypterOpts, and returns the
// CEK. An RSA key held outside this process, such as in a hardware module, can
// decrypt through jwe.GetDecrypter.
type Decrypter interface {
	Alg() jwa.Algorithm
	crypto.Decrypter
}

// DecrypterOpts carries what a Decrypter needs beyond the JWE Encrypted Key:
// the JWE Protected Header, which holds the parameters of algorithms such as
// ECDH-ES, and the content encryption algorithm, whose key length some
// algorithms derive a key for.
type DecrypterOpts struct {
	Header map[string]any
	Enc    jwa.Encryption
}

// Opts configures key generation for new signers.
// BitSize applies to RSA algorithms. SecretKey applies to HMAC algorithms.
type Opts struct {
	BitSize   int
	SecretKey *[]byte
}

// SignerOpts implements crypto.SignerOpts and signals that the digest passed to
// Sign has already been hashed. ES, RS and PS signers skip their internal hashing
// when Hash is non-zero, and refuse a Hash that is not their own. HMAC, Ed25519 and
// ML-DSA signers have no pre-hashed mode and refuse a non-zero Hash (RFC 9964
// section 5 for ML-DSA).
type SignerOpts struct {
	Hash crypto.Hash
}

func (s SignerOpts) HashFunc() crypto.Hash {
	return s.Hash
}

func Pointer[T any](v T) *T {
	return &v
}
