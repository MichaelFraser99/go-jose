# Go Jose
A Go implementation of the JOSE suite of specifications — JWS ([RFC 7515](https://www.rfc-editor.org/rfc/rfc7515)), JWA ([RFC 7518](https://www.rfc-editor.org/rfc/rfc7518)), JWK ([RFC 7517](https://www.rfc-editor.org/rfc/rfc7517)), and JWT ([RFC 7519](https://www.rfc-editor.org/rfc/rfc7519)).

## Requirements
- Go 1.21 or higher

## Import paths

There is **no root package**. Import the subpackage you need:

```go
import (
	"github.com/MichaelFraser99/go-jose/jwa"        // algorithm identifiers
	"github.com/MichaelFraser99/go-jose/jwk"        // jwk conversion
	"github.com/MichaelFraser99/go-jose/jws"        // signers and validators
	"github.com/MichaelFraser99/go-jose/jwt"        // jwt signing and validation
	"github.com/MichaelFraser99/go-jose/joseerror"  // error sentinels
	"github.com/MichaelFraser99/go-jose/model"      // shared types and options
)
```

## Installation
```bash
go get github.com/MichaelFraser99/go-jose
```

## Algorithms Supported
Currently, the module supports the following asymmetric algorithms:
- ES256
- ES384
- ES512
- RS256
- RS384
- RS512
- PS256
- PS384
- PS512

Also supported are the following HMAC with SHA2 symmetric algorithms:
- HS256
- HS384
- HS512

`GetSigner` requires a secret key as `[]byte`, passed in `model.Opts`. With no secret it returns an error: the random-secret path inside each package is not reachable through the public API.

**This is a breaking change:** a secret must be at least as long as the hash output. That is 32 bytes for HS256, 48 for HS384, and 64 for HS512. RFC 7518 section 3.2 makes the rule a MUST, because a shorter secret caps the cost of a forgery at the entropy of the secret instead of the strength of the MAC. `GetSigner` refuses a shorter secret with `ErrInvalidPrivateKey`. Earlier versions accepted a secret of any length, a one-byte secret included, and a nil secret gave a usable validator.

Give your secret at least that many bytes.

**A validator for these algorithms can only be built from a signer.** `GetValidator` accepts what `Signer.Public` returns and nothing else: a raw `[]byte` is refused, and `GetValidatorFromJwk` refuses an `oct` key outright. So to verify an HS token with a secret you were given, construct a signer with that secret first:

```go
signer, err := jws.GetSigner(jwa.HS256, &model.Opts{SecretKey: &secret})
validator, err := jws.GetValidator(signer.Alg(), signer.Public())
```

`GetValidator` applies the same length rule and refuses with `ErrInvalidPublicKey`, but a secret that reached it through a signer has already passed the rule, so the refusal is not one you can trigger from outside this library.

`Public` returns a `SecretKey`, which is a `[]byte` defined in an internal package. A consumer cannot name the type, so reach its `Equal` method through an interface:

```go
if comparer, ok := validator.Public().(interface{ Equal(crypto.PublicKey) bool }); ok {
	same := comparer.Equal(other.Public())
}
```

`SecretKey.Equal` reports whether two keys hold the same bytes. It compares in constant time, because an early-exit comparison tells a caller who submits guesses how many leading bytes were correct.

Note what `Equal` does not answer. HMAC pads a key shorter than its block size and hashes a longer one, so two different byte strings can key identically. `Equal` compares the bytes and reports such a pair as unequal. `SecretKey` carries no algorithm, and the block size differs between HS256 and the other two, so there is no one canonical form it could compare instead.

Algorithms are identified by the `jwa` package:
```go
type jwa.Algorithm int
```

Its zero value is `jwa.Unknown`, so a variable you forgot to set names no algorithm rather than ES256.

```go
func (a Algorithm) String() string
```
`String` returns the name of the algorithm, such as `"RS256"`. It returns the empty string for `Unknown`.

```go
func GetAlgorithm(alg string) Algorithm
```
`GetAlgorithm` returns the algorithm a name identifies, and `Unknown` if no algorithm has that name. The comparison is case sensitive, because RFC 7515 section 4.1.1 makes the `alg` header value case sensitive.

## Signers
To create a Signer, use `jws.GetSigner`. It takes an algorithm and an optional `model.Opts`, and returns a `model.Signer` with a generated key pair. `Opts.BitSize` sets the modulus size for the RSA algorithms. `Opts.SecretKey` carries the secret for the HMAC algorithms, where it is required rather than optional. The example below generates a signer for ES256:
```go
signer, err := jws.GetSigner(jwa.ES256, nil)
```

`jws.GetSignerFromPrivateKey` builds a signer from a key you already hold. It takes an algorithm and a `crypto.PrivateKey`. It refuses the HMAC algorithms, which take their secret through `model.Opts` instead. The example below builds a signer for ES256:
```go
signer, err := jws.GetSignerFromPrivateKey(jwa.ES256, privateKey)
```

## Signing Contract
The `Sign` method follows JOSE conventions per RFC 7518 rather than Go's `crypto.Signer` contract. It supports two modes:

- **JOSE mode** (`opts == nil` or `opts.HashFunc() == 0`): pass the raw JWS Signing Input — the signer hashes it internally using the algorithm's designated hash. This is the expected usage for JWS operations.
- **Pre-hashed mode** (`opts.HashFunc() != 0`): pass an already-hashed digest — the signer skips internal hashing. This supports interoperability with callers following Go's `crypto.Signer` convention. ES, RS and PS implement this mode, and refuse a `Hash` that is not the algorithm's own with `ErrSigningError`.

> **The HMAC algorithms have no pre-hashed mode, and refuse one.** HMAC is itself a keyed hash, so there is no internal hashing step for a caller to skip. HS256, HS384 and HS512 refuse a non-zero `opts.HashFunc()` with `ErrSigningError`. Pass the signing input whole and leave `opts` nil.
>
> **This is a breaking change,** and it breaks two kinds of caller differently. One passed a pre-hashed digest with a non-zero `Hash`, as the old documentation described: they were already producing a MAC over the digest rather than over the signing input, which no validator accepts, with no error to say so. They now get an error at the call that causes it. The other is generic over `crypto.Signer` and passes a non-zero `Hash` alongside the **raw** signing input — that worked, because `opts` was ignored, and it no longer does. Such a caller should pass `nil` for an HS algorithm, or a zero `Hash`.

A `SignerOpts` implementation is provided:
```go
type SignerOpts struct {
	Hash crypto.Hash
}
```

`ValidateSignature` always expects the raw signing input (not pre-hashed) and hashes internally.

## Validators
In addition to the packaged signers, a validator type is also included for each algorithm. This can be constructed in one of two ways:

The `GetValidator` method takes in a crypto.PublicKey implementation and returns a validator instance. The below example shows how to generate a validator for ES256:
```go
// Construct a validator from a public key
validator, err := jws.GetValidator(jwa.ES256, publicKey)

// Construct a validator from a signer instance
signer, err := jws.GetSigner(jwa.ES256, nil)
validator, err := jws.GetValidator(signer.Alg(), signer.Public())
```

`jws.GetValidatorFromJwk` builds a validator from a jwk, decoded as a `map[string]any` rather than raw bytes. It refuses the HMAC algorithms, because an `oct` key cannot be reached this way. The example below builds a validator for ES256:
```go
// Construct a validator from a jwk public key
validator, err := jws.GetValidatorFromJwk(jwa.ES256, publicKeyMap)
```

`ValidateSignature` takes the raw signing input and the signature, and reports whether the signature verifies. Do not hash the input first: the validator hashes it internally with the algorithm's own hash. A signature that does not verify returns `false` with a nil error. The error is non-nil only when the signature could not be checked at all.
```go
// Validate a signature
validator, err := jws.GetValidator(jwa.ES256, publicKey)

valid, err := validator.ValidateSignature(digest, signature)
```

Finally, validators expose their PublicKey with the `Public()` method
```go
validator, err := jws.GetValidator(jwa.ES256, publicKey)
pk := validator.Public()
```

## Keys a token carries

A JOSE header can name the key that signed the token, through `jwk`, `jku`, `x5c` or `x5u`. `jwt.Validate` and `jws.VerifyCompactSerialization` use those keys by default. A caller wanting only its own key material opts out:

```go
head, body, err := jwt.Validate(token, retriever, &model.JoseOptions{IgnoreTokenProvidedKeys: true})
```

The sense is negative so the zero value is the default, which matters because a caller setting any other option constructs the struct. The field this replaced read `UseTokenProvidedKeys` and documented itself as defaulting to true — and that held only while you passed no options at all. Setting anything else zeroed it and silently turned every header key source off.

### jku and x5u need a client

The two remote headers name a URL this library fetches. Supply the client it should use:

```go
head, body, err := jwt.Validate(token, nil, &model.JoseOptions{
    HttpClient: &http.Client{Timeout: 10 * time.Second, Transport: yourGuardedTransport},
    X509Roots:  roots,
})
```

Both URLs come from the header of the token being verified, so this library makes an outbound request to an address a peer chose, before the signature is checked. Give the client a transport that rejects the destinations your deployment will not allow — private, loopback, link-local and other reserved ranges — and a timeout. The body is capped at 4 MiB whatever client you supply.

With no client, `jku` and `x5u` contribute no key. The members of a `jku` set are first narrowed by the token's `kid` and `alg`. Then any remaining member this library cannot read is skipped, as RFC 7517 section 5 recommends, and the rest are used. Because narrowing comes first, an unreadable member can still match the `kid` or `alg` and so keep a readable member out. A set whose `keys` array holds a number, string, boolean or array is not a JWK Set, so the whole set is refused. `jku` must be `https`, as RFC 7515 section 4.1.2 requires integrity protection, and an `x5u` resource is read as the PEM encoding section 4.1.5 requires, falling back to raw DER for a server that sends that instead.

### Stating what you expect of a header

Most JOSE profiles pin their own `typ`, many require a `kid`, and RFC 7515 section 4.1.11 says a JWS whose `crit` lists an extension the recipient does not understand **MUST** be rejected. Rather than decoding the header yourself to check those, say what you expect:

```go
head, body, err := jwt.Validate(token, retriever, &model.JoseOptions{
    AcceptedTypes:             []string{"example+jwt"},
    RequireKeyIdentifier:      true,
    UnderstoodCriticalHeaders: []string{"x-example"},
    AllowedSigningAlgorithms:  []jwa.Algorithm{jwa.ES256, jwa.RS256},
})
```

Each is off when unset, so none of this changes what an existing caller sees — except `crit`, below.

`AcceptedTypes` compares as RFC 7515 section 4.1.9 requires: case-insensitively, with `application/` treated as prepended to any value containing no `/`. So naming `example+jwt` accepts `application/example+jwt` and `Example+JWT`, and refuses `x-example+jwt`.

`RequireKeyIdentifier` refuses a `kid` that is absent or is not a non-empty string. RFC 7517 section 4.5 leaves `kid` optional, which is why it is off by default.

`UnderstoodCriticalHeaders` names the extensions you handle. **This one is a breaking change:** this library understands no extensions of its own, so with nothing named, any `crit` is now refused. Previously a `crit` listing an unknown extension was accepted, which section 4.1.11 forbids. A caller that handles an extension names it; a caller that handles none needs no change, because a token carrying `crit` was never safe for them to accept.

`AllowedSigningAlgorithms` is refused during header validation rather than at signature verification, so a declined algorithm stops before any `jku` or `x5u` is fetched on that header's behalf. It reports `ErrUnsupportedAlgorithm`: the signature was never examined, so a caller can tell this from a bad signature with `errors.Is`.

### x5c and x5u need trust anchors

The two certificate headers are different, and they do nothing unless you configure roots for them. RFC 7515 section 4.1.6 says a recipient:

> MUST validate the certificate chain according to RFC 5280 and consider the certificate or certificate chain to be invalid if any validation failure occurs.

RFC 5280 path validation takes a trust anchor as an **input**. A chain cannot vouch for itself, so without an anchor there is nothing to validate against and the header cannot be used:

```go
roots := x509.NewCertPool()
roots.AppendCertsFromPEM(issuerRootPEM)

head, body, err := jwt.Validate(token, nil, &model.JoseOptions{X509Roots: roots})
```

With no `X509Roots` configured, a token's `x5c` and `x5u` headers contribute no key. They are not an error — section 4.1.6 makes use of the header OPTIONAL — so the token still verifies if another key source does, and fails with `no cyptographic material provided for signature validation` if none does.

A malformed `x5c` is refused whether or not roots are configured, because its shape is a property of the claim rather than of your trust configuration. An array that is not an array of strings, an empty array, or an entry that is not base64-encoded DER is `ErrMalformedClaim`.

`jwk` and `jku` are deliberately left alone by this. Neither carries a validation MUST, and an inline `jwk` is transparently "here is my key, check against it" — a caller reading the header knows no trust is being conferred. An `x5c` chain looks like PKI, which is why it is the one that needs the anchor made explicit.

## Jwks
This library includes two methods for converting keys into JWK format

All JWK methods include in the returned map a KID suggestion based on the public key component

**This is a breaking change for Ed25519 keys.** Earlier versions computed the suggestion for an Ed25519 key and then discarded it, so the jwk went out with no `kid` at all. It now carries one, like every other algorithm. Two consequences for a caller: the serialised jwk of an Ed25519 key gains a member, so a pinned fixture of that JSON no longer matches; and `Jwks.Add` with `EnforceUniqueKIDs` now refuses a second copy of one Ed25519 key, where before it had no `kid` to compare and accepted it.

`jwk.PublicJwk` takes a public key and returns the jwk representation of it:
```go
func jwk.PublicJwk(publicKey crypto.PublicKey) (*map[string]any, error)
func jwk.PrivateJwk(privateKey crypto.PrivateKey) (*map[string]any, error)
```

Pass a pointer to the key. An `*ecdsa.PublicKey`, an `*rsa.PublicKey` or an `*ed25519.PublicKey` is accepted; anything else is refused with `ErrInvalidPublicKey`.

```go
// Direct from a public key
jwkMap, err := jwk.PublicJwk(publicKey)

// From a Signer. Note Public() is a call, and its result is already a pointer
// for the EC and RSA algorithms
signer, err := jws.GetSigner(jwa.ES256, nil)
jwkMap, err := jwk.PublicJwk(signer.Public())
```

Two methods convert a jwk back into a key:

```go
func jwk.PublicFromJwk(jwk map[string]any) (crypto.PublicKey, error)
func jwk.PrivateFromJwk(jwk map[string]any) (crypto.PrivateKey, error)
```

The value returned is a pointer to the respective key, such as `*ecdsa.PublicKey` or `*rsa.PublicKey`.

An `OKP` jwk is read only when its `crv` is `Ed25519`, the one OKP subtype this library supports. RFC 8037 section 2 requires `crv`, so a jwk without a string `crv` is refused as an invalid key. Any other subtype is refused with `ErrUnsupportedAlgorithm`. Each of `x` and `d` must be 32 octets, the key sizes RFC 8032 section 5.1.5 sets for Ed25519. For a private key, `x` must be the public key of `d`.

**This is a breaking change for OKP keys.** Earlier versions ignored the value of `crv`, so an `X25519` or `Ed448` key was returned as an Ed25519 key. They also accepted any length of `x` and `d`, and did not compare `x` with `d`. A key that those versions read can now be refused.

## JWTs
This library includes two methods for jwt handling

The first signs a jwt from a signer, a head map and a body map:

```go
func jwt.New(signer crypto.Signer, head, body map[string]any, opts jwt.Opts) (*string, error)
```

If the head carries no `typ` claim, `New` inserts `"JWT"`. If the signer is one of this module's own implementations, `New` adds the `alg` claim when the head does not already carry one.

`jwt.Opts` names the algorithm to sign with:

```go
type jwt.Opts struct {
	Algorithm jwa.Algorithm
}
```

Give it the algorithm the signer was built for. `New` hashes the signing input only for an ES, RS or PS algorithm. A signer from this library refuses a hash that is not its own, and an HMAC signer refuses any hash. With an HS or EdDSA algorithm, or none, `New` passes the input whole and the signer signs with its own algorithm. A `crypto.Signer` from elsewhere makes no such check. If the hash `Opts` names is not the one that signer uses, the signature verifies against nothing.

The second validates a jwt and returns the decoded head and body:

```go
func jwt.Validate(token string, outOfBoundsPublicKey model.Retriever, opts *model.JoseOptions) (head, body map[string]any, err error)
```

The retriever supplies key material of your own. Pass nil to rely only on what the token's header names. `model.JoseOptions` carries everything described under [Keys a token carries](#keys-a-token-carries), and may be nil for the defaults.

If the `iat`, `nbf` and `exp` claims are present, `Validate` checks them. `JoseOptions.ClockSkewLeeway` widens the window they are judged against.

## Errors
Sentinel errors live in the `joseerror` package. Match one with `errors.Is`:

| Sentinel | Meaning |
| --- | --- |
| `ErrInvalidPublicKey` | The public key given cannot be used for this algorithm |
| `ErrInvalidPrivateKey` | The private key or secret given cannot be used for this algorithm |
| `ErrInvalidSignature` | The signature does not verify against the signing input |
| `ErrDecryptionFailed` | Reserved for JWE. Nothing returns it: the `jwe` package is a stub and exports nothing |
| `ErrUnsupportedAlgorithm` | The algorithm named is not supported, or not permitted by the options given |
| `ErrSigningError` | Signing failed |
| `ErrMalformedClaim` | A claim is present but its type or value is wrong |
| `ErrMissingClaim` | A required claim is absent |
| `ErrMissingCriticalClaim` | A header named in `crit` is absent, or names an extension this library does not understand |
| `ErrNoKeyIdentifierMatch` | No key could be selected. The `kid` matches nothing, a `jku` set holds no usable key that matches the header, a certificate chain does not reach a configured root, or an `x5t` thumbprint does not match the chain |
| `ErrKeystoreError` | A `model.Jwks` lookup or addition failed, or the configuration needed to use a key source is absent, such as `X509Roots` for a certificate chain |
| `ErrApplicationError` | Key material a header named could not be obtained, decoded or used. Covers a failed `jku` or `x5u` fetch, a local decode of what one returned, and an inline `jwk` of a key type or curve this library does not support |
| `ErrMalformedToken` | The token is not a well formed JOSE object |

Each sentinel carries a prefix terminated by `": "`, so wrap one with `%w` immediately followed by the rest of the message and no space:

```go
fmt.Errorf("%wshould be an instance of *ecdsa.PrivateKey", joseerror.ErrInvalidPrivateKey)
```

That reads `invalid private key: should be an instance of *ecdsa.PrivateKey`, and `errors.Is` still matches.

## Upgrading from the pre-0.10 line

Every change below is a compile error or a silent behaviour change for a consumer of the previous release.

### Packages moved

| Was | Now |
| --- | --- |
| `go-jose/error` | `go-jose/joseerror` |
| `model.Algorithm`, `model.ES256` and the rest | `jwa.Algorithm`, `jwa.ES256` and the rest |
| `jose.GetSigner` and friends | `jws.GetSigner`; there is no root package |

### Error sentinels

`ErrSigning` is now `ErrSigningError`. Eight sentinels are new.

**Every sentinel message now ends in `": "`,** so a sentinel composes with the text that wraps it into one sentence. If you match on an error string, that match breaks. Match with `errors.Is` instead:

```go
if errors.Is(err, joseerror.ErrInvalidSignature) {
```

### Signatures changed

| Function | Change |
| --- | --- |
| `jwa.GetAlgorithm` | Returns `Algorithm`, not `*Algorithm`. Returns `jwa.Unknown` rather than nil for an unknown name, and the comparison is now case sensitive |
| `jwt.New` | Takes a fourth parameter, `jwt.Opts`, naming the algorithm to sign with |
| `jwt.Validate` | Takes `(token string, retriever model.Retriever, opts *model.JoseOptions)`. The `publicKey` parameter is gone: supply key material through the retriever, or rely on what the token's header names |
| `jws.GetValidatorFromJwk` | Takes `map[string]any`, not `[]byte` |
| `jwk.PublicJwk`, `jwk.PrivateJwk` | Return `*map[string]any`, not `map[string]string` |

### Behaviour changes documented elsewhere in this file

- An HMAC secret must be at least the hash output size, and a validator for an HMAC algorithm can only be built from a signer.
- An Ed25519 jwk now carries a `kid`.
- An `OKP` jwk is read only when it is a well-formed Ed25519 key.
- `JoseOptions.IgnoreTokenProvidedKeys` replaces `UseTokenProvidedKeys`, inverted so the zero value is the documented default.
- A `crit` header naming an extension you have not declared in `UnderstoodCriticalHeaders` is refused.
- `x5c` and `x5u` contribute no key unless `JoseOptions.X509Roots` is configured.

### Not implemented

The `jwe` package exports nothing. JWE is not supported in this release.
