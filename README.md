# Go Jose
A Go implementation of the JOSE suite of specifications — JWS ([RFC 7515](https://www.rfc-editor.org/rfc/rfc7515)), JWA ([RFC 7518](https://www.rfc-editor.org/rfc/rfc7518)), JWK ([RFC 7517](https://www.rfc-editor.org/rfc/rfc7517)), and JWT ([RFC 7519](https://www.rfc-editor.org/rfc/rfc7519)).

## Requirements
- Go 1.21 or higher

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

Algorithms are represented inside this module with the following type:
```go
type Algorithm int
```

with the following methods defined

```go
func (a Algorithm) String() string
```
String returns the string representation of that algorithm (i.e. "RS256" or "HS384")

```go
func GetAlgorithm(alg string) *Algorithm
```
GetAlgorithm takes in a string and returns a pointer to the relevant algorithm type or nil if an invalid string provided

## Signers
To create a Signer object use the `GetSigner` method. This takes in an algorithm and an optional `Opts` object (defines a bit size used for RSA keys) and returns a `crypto.Signer` implementation complete with generated key pair. The below example shows how to generate a signer for ES256:
```go
signer, err := jose.GetSigner(jwa.ES256, nil)
```

The `GetSignerFromPrivateKey` method can also be used. This takes in an algorithm and a pointer to a `crypto.PrivateKey` implementation. The below example shows how to generate a signer for ES256:
```go
signer, err := jose.GetSignerFromPrivateKey(jwa.ES256, privateKey)
```

## Signing Contract
The `Sign` method follows JOSE conventions per RFC 7518 rather than Go's `crypto.Signer` contract. It supports two modes:

- **JOSE mode** (`opts == nil` or `opts.HashFunc() == 0`): pass the raw JWS Signing Input — the signer hashes it internally using the algorithm's designated hash. This is the expected usage for JWS operations.
- **Pre-hashed mode** (`opts.HashFunc() != 0`): pass an already-hashed digest — the signer skips internal hashing. This supports interoperability with callers following Go's `crypto.Signer` convention.

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
validator, err := jose.GetValidator(jwa.ES256, publicKey)

// Construct a validator from a signer instance
signer, err := jose.GetSigner(jwa.ES256, nil)
validator, err := jose.GetValidator(signer.Alg(), signer.Public())
```

The `GetValidatorFromJwk` method takes in the bytes of a jwk format public key and returns a validator instance. The below example shows how to generate a validator for ES256:
```go
// Construct a validator from a jwk public key
validator, err := jose.GetValidatorFromJwk(jwa.ES256, publicKeyBytes)
```

The validator object has a method `ValidateSignature` which takes in the bytes of the digest and signature and returns a boolean indicating whether the signature is valid. The below example shows how to validate a signature:
```go
// Validate a signature
validator, err := jose.GetValidator(jwa.ES256, publicKey)

valid, err := validator.ValidateSignature(digest, signature)
```

Finally, validators expose their PublicKey with the `Public()` method
```go
validator, err := jose.GetValidator(jwa.ES256, publicKey)
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

With no client, `jku` and `x5u` contribute no key. `jku` must be `https`, as RFC 7515 section 4.1.2 requires integrity protection, and an `x5u` resource is read as the PEM encoding section 4.1.5 requires, falling back to raw DER for a server that sends that instead.

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

PublicJwk takes in a pointer to a public key and returns a `map[string]string` containing the jwk representation of the provided public key
```go
// Direct from a public key
jwkMap, err := PublicJwk(publicKey)

// From a Signer
signer, err := jose.GetSigner(jwa.ES256, nil)
publicKey := signer.Public
jwkMap, err := PublicJwk(&publicKey)
```

Also included is a method to convert an existing public key JWK back into it's respective public key

The value returned is a pointer to the respective public key `*ecdsa.PublicKey` or `*rsa.PublicKey`

```go
PublicFromJwk(jwk map[string]any) (crypto.PublicKey, error)
```

## JWTs
This library includes two methods for jwt handling

The first is for signing a jwt from provided signer implementation, head map, and body map

If the head does not include the `typ` claim, the method will insert a value of "JWT"

Additionally, if the `crypto.Signer` implementation provided is one of the implementations defined in this module, the `alg` claim is also added (if not already present)

```go
New(signer crypto.Signer, head, body map[string]any) (*string, error) {
```

The second provides basic jwt validation and returns the decoded head and body values as instances of `map[string]any`

If present, the `iat`, `nbf`, and `exp` claims will also be validated

```go
Validate(publicKey crypto.PublicKey, jwt string) (head, body map[string]any, err error)
```

### Errors
Sentinel errors live in the `joseerror` package. Match one with `errors.Is`:

| Sentinel | Meaning |
| --- | --- |
| `ErrInvalidPublicKey` | The public key given cannot be used for this algorithm |
| `ErrInvalidPrivateKey` | The private key or secret given cannot be used for this algorithm |
| `ErrInvalidSignature` | The signature does not verify against the signing input |
| `ErrDecryptionFailed` | A JWE payload could not be decrypted |
| `ErrUnsupportedAlgorithm` | The algorithm named is not supported, or not permitted by the options given |
| `ErrSigningError` | Signing failed |
| `ErrMalformedClaim` | A claim is present but its type or value is wrong |
| `ErrMissingClaim` | A required claim is absent |
| `ErrMissingCriticalClaim` | A claim named in `crit` is absent from the header |
| `ErrNoKeyIdentifierMatch` | No key in the set carries the `kid` the token names |
| `ErrKeystoreError` | A key set could not be read or does not hold a usable key |
| `ErrApplicationError` | A resource a header named could not be retrieved |
| `ErrMalformedToken` | The token is not a well formed JOSE object |

Each sentinel carries a prefix terminated by `": "`, so wrap one with `%w` immediately followed by the rest of the message and no space:

```go
fmt.Errorf("%wshould be an instance of *ecdsa.PrivateKey", joseerror.ErrInvalidPrivateKey)
```

That reads `invalid private key: should be an instance of *ecdsa.PrivateKey`, and `errors.Is` still matches.
