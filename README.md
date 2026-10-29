# Go Jose
A Go implementation of the JOSE suite of specifications — JWS ([RFC 7515](https://www.rfc-editor.org/rfc/rfc7515)), JWA ([RFC 7518](https://www.rfc-editor.org/rfc/rfc7518)), JWK ([RFC 7517](https://www.rfc-editor.org/rfc/rfc7517)), and JWT ([RFC 7519](https://www.rfc-editor.org/rfc/rfc7519)).

## Requirements
- Go 1.27 or higher

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
- Ed25519
- ML-DSA-44
- ML-DSA-65
- ML-DSA-87

ML-DSA-44, ML-DSA-65 and ML-DSA-87 are the FIPS 204 post-quantum signature parameter sets, as RFC 9964 section 5 registers them for JOSE. They use the standard library's `crypto/mldsa`. That package is unavailable under the FIPS 140-3 Go Cryptographic Module v1.0.0, and there building an ML-DSA signer or validator returns an error. HashML-DSA is not supported: RFC 9964 section 7.2 registers no JOSE algorithm for it.

Ed25519 is EdDSA with the Ed25519 parameters of RFC 8032 section 5.1, as RFC 9864 section 4.1.1 registers it. Ed448 is not supported.

`EdDSA` is accepted for verification only, and only with an Ed25519 key. RFC 9864 section 4.1.2 deprecates `EdDSA` in favour of `Ed25519`. Section 4.4 tells new producers to prefer the replacement, but it does not tell verifiers to refuse the old identifier. So:

- A token whose `alg` is `EdDSA` verifies under an Ed25519 key, as RFC 8037 defines it.
- `GetSigner`, `GetSignerFromPrivateKey` and `jwt.New` refuse `EdDSA` with `ErrUnsupportedAlgorithm`. Sign with `Ed25519`.
- `EdDSA` and `Ed25519` are separate values of `jwa.Algorithm`. To refuse `EdDSA` tokens, set `AllowedSigningAlgorithms` to `jwa.Ed25519` without `jwa.EdDSA`.

Also supported are the following HMAC with SHA2 symmetric algorithms:
- HS256
- HS384
- HS512

`GetSigner` requires a secret key as `*[]byte`, passed in `model.Opts.SecretKey`. With no secret it returns an error: the random-secret path inside each package is not reachable through the public API.

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

### Which keys a signer or validator accepts

`GetSigner`, `GetSignerFromPrivateKey`, `GetValidator` and `GetValidatorFromJwk` refuse a key the algorithm cannot use, with `ErrInvalidPrivateKey` or `ErrInvalidPublicKey`:

- **RS and PS:** the modulus must be 2048 to 8192 bits. RFC 7518 sections 3.3 and 3.5 make 2048 bits a MUST. The 8192-bit ceiling is this library's: the cost of an RSA verification grows with the square of the modulus, and a token can name its own key, so an unbounded modulus lets a peer hold a core for seconds. 8192 bits is also the default cap `crypto/tls` puts on a peer's RSA key. `Opts.BitSize` takes the same range.
- **RS and PS exponent:** the public exponent must be odd and between 3 and 2^31 - 1. RFC 8017 section 3.1 puts e between 3 and n - 1 with GCD(e, λ(n)) = 1, and λ(n) is even, so e is odd. With e = 1 a signature is its own encoded message, so anyone could forge one. `crypto/rsa` refuses such a key when it verifies, and this library refuses it earlier, when the signer or validator is built.
- **ES:** the key must lie on the algorithm's own curve: P-256 for ES256, P-384 for ES384 and P-521 for ES512. RFC 7518 section 3.1 defines each algorithm by its curve. A private key's `d` must be the private key of its point.
- **Every family:** the signer and validator keep their own copy of the key, so a later change to your key does not affect them. `Public` returns a new copy each time, so a change to that copy does not affect them either.
- **ML-DSA:** the key must be an `*mldsa.PrivateKey` or `*mldsa.PublicKey` of the algorithm's own parameter set, so an ML-DSA-65 key is refused for ML-DSA-44. A zero-value key, such as `&mldsa.PrivateKey{}`, is refused. A zero-value private key reports the all-zero seed, so it is not rebuilt from it: that is the published example key of RFC 9964 Appendix A.
- **Ed25519:** the key must be an `ed25519.PrivateKey` or `ed25519.PublicKey`, or a pointer to one. A private key must be 64 bytes, and its public half must be the public key of its seed. A public key must be 32 bytes. RFC 8032 section 5.1.5 sets these sizes. A public key must encode a y below 2^255 - 19, because RFC 8032 section 5.1.3 says that any other y fails to decode. A public key of small order is refused too. NIST SP 800-186 appendix D.1.3.2 refuses such a key in full public key validation, and under the neutral element one fixed signature verifies every message. This check does not refuse a key of mixed order.
- **Every family:** a nil key, or one missing the modulus, exponent, curve, coordinates or private scalar, is refused when the signer or validator is built rather than panicking later. An RSA private key needs only `D`, as RFC 7518 section 6.3.2 makes the primes optional. Without primes, the signer recovers the two primes from `N`, `E` and `D`, as NIST SP 800-56B Rev. 2 Appendix C.1 describes, and signs with them. If `D` does not undo `E`, or the modulus is not the product of two primes, the key is refused. With primes, the key must pass `rsa.PrivateKey.Validate`.

## Signing Contract
The `Sign` method follows JOSE conventions per RFC 7518 rather than Go's `crypto.Signer` contract. It supports two modes:

- **JOSE mode** (`opts == nil` or `opts.HashFunc() == 0`): pass the raw JWS Signing Input — the signer hashes it internally using the algorithm's designated hash. This is the expected usage for JWS operations.
- **Pre-hashed mode** (`opts.HashFunc() != 0`): pass an already-hashed digest — the signer skips internal hashing. This supports interoperability with callers following Go's `crypto.Signer` convention. ES, RS and PS implement this mode. They refuse a `Hash` that is not the algorithm's own, and a digest whose length is not that hash's output size, with `ErrSigningError`.

> **The HMAC algorithms have no pre-hashed mode, and refuse one.** HMAC is itself a keyed hash, so there is no internal hashing step for a caller to skip. HS256, HS384 and HS512 refuse a non-zero `opts.HashFunc()` with `ErrSigningError`. Pass the signing input whole and leave `opts` nil.
>
> **Ed25519 has no pre-hashed mode either, and refuses one.** Ed25519 hashes the whole signing input as part of the signature. For a non-zero hash, `crypto/ed25519` signs with Ed25519ph, which is a different algorithm. So the Ed25519 signer refuses a non-zero `opts.HashFunc()` with `ErrSigningError`. An `*ed25519.Options` with a non-empty `Context` is refused the same way: RFC 8032 section 5.1 gives Ed25519 no context, and a context asks `crypto/ed25519` for Ed25519ctx.
>
> **ML-DSA has no pre-hashed mode either, and refuses one.** RFC 9964 section 5 signs the whole input. ML-DSA signers refuse a non-zero `opts.HashFunc()` with `ErrSigningError`, including `crypto.MLDSAMu`, which asks `crypto/mldsa` to sign an externally computed mu. RFC 9964 section 5 also requires an empty context, so an `*mldsa.Options` with a non-empty `Context` is refused the same way. An ML-DSA signature is hedged, the default variant of FIPS 204 section 3.4, so two signatures of one input differ.
>
> **This is a breaking change,** and it breaks two kinds of caller differently. One passed a pre-hashed digest with a non-zero `Hash`, as the old documentation described: they were already producing a MAC over the digest rather than over the signing input, which no validator accepts, with no error to say so. They now get an error at the call that causes it. The other is generic over `crypto.Signer` and passes a non-zero `Hash` alongside the **raw** signing input — that worked, because `opts` was ignored, and it no longer does. Such a caller should pass `nil` for an HS algorithm, or a zero `Hash`.

Every signer accepts a nil `rand`. PS signatures are randomised, so the PS signers then read from `crypto/rand.Reader`.

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
signerValidator, err := jws.GetValidator(signer.Alg(), signer.Public())
```

`jws.GetValidatorFromJwk` builds a validator from a jwk, decoded as a `map[string]any` rather than raw bytes. It reads the key by its `kty`, as `jwk.PublicFromJwk` does, so a jwk without a `kty`, or whose `kty` does not match its algorithm, is refused. RFC 8725 section 3.1 requires each key to be used with exactly one algorithm, so a jwk that carries an `alg` member is refused with `ErrInvalidPublicKey` unless that member is the algorithm you asked for. `EdDSA` and `Ed25519` count as the same algorithm here, because this library supports only the Ed25519 curve for `EdDSA`. A jwk whose `use` is present and is not `"sig"` is refused with `ErrInvalidPublicKey`. So is a jwk whose `key_ops` is present and does not include `"verify"`. RFC 7517 sections 4.2 and 4.3 let a publisher mark a key as not for verifying signatures. `IgnoreKeyUse` does not apply to `GetValidatorFromJwk`. To verify with such a key, read it with `jwk.PublicFromJwk` and give the key to `GetValidator`, which has no key-use rule. It refuses the HMAC algorithms, because an `oct` key cannot be reached this way. The example below builds a validator for ES256:
```go
// Construct a validator from a jwk public key
validator, err := jws.GetValidatorFromJwk(jwa.ES256, publicKeyMap)
```

`ValidateSignature` takes the raw signing input and the signature, and reports whether the signature verifies. Do not hash the input first: the validator hashes it internally with the algorithm's own hash. A signature that does not verify returns `false` with a nil error. The error is non-nil only when the signature could not be checked at all. This holds for every family: an RS or PS signature that `crypto/rsa` rejects returns `false` with a nil error, and so does an ES signature of the wrong length, because RFC 7518 section 3.4 says that "the validation has failed".
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

### Binding a key to one algorithm

RFC 8725 section 3.1 requires each key to be used with exactly one algorithm. A bare `crypto.PublicKey` carries no algorithm, so this library cannot check that for you when the key comes from `GetValidator` or from a `model.Retriever`. One RSA key builds a validator for each of RS256, RS384, RS512, PS256, PS384 and PS512, and a retriever's RSA key verifies a token that names any of them. Binding the key is your job:

- With `GetValidator`, pass the algorithm the key was issued for, not the `alg` a token names.
- With a retriever, set `JoseOptions.AllowedSigningAlgorithms` to the algorithm your keys are for.

A jwk can carry its own `alg`, and `GetValidatorFromJwk` and a token's `jwk` header both enforce it.

## Verifying a JWS

`jws.Verify` checks a JWS Compact Serialization and returns its protected header and its payload as the signed octets. RFC 7515 section 2 lets a payload be "an arbitrary sequence of octets", so `Verify` does not parse it. Text, binary data and an empty payload all verify:

```go
head, payload, err := jws.Verify(ctx, token, retriever, opts)
```

`jws.VerifyCompactSerialization` does the same checks and also parses the payload as a JSON object, which is what a JWT carries. It refuses any other payload, including `null`. `jwt.Validate` is built on it.

Both apply the same rules to the token:

- Each segment must be base64url exactly as RFC 7515 section 2 defines it. A segment holding a line break, whitespace, `=` padding or any other character outside `A-Z a-z 0-9 - _` is refused, as section 5.2 steps 2, 6 and 7 require. A final character whose unused low bits are not zero is refused too, as RFC 4648 section 3.5 permits. So each segment has exactly one accepted encoding.
- The protected header must be a UTF-8 JSON object, as section 5.2 step 3 and RFC 8725 section 3.7 require. `VerifyCompactSerialization` holds the payload to the same rule.
- A JSON string in the protected header must not hold an unpaired UTF-16 surrogate escape, such as `"\ud800"`. RFC 8259 section 8.2 calls the behaviour of a receiver of such a string unpredictable. Go would turn it into U+FFFD, so different signed bytes would give the same value. `VerifyCompactSerialization` holds the payload to the same rule.
- An `alg` this library has no validator for is refused with `ErrUnsupportedAlgorithm` before any key is sought, so no `jku` or `x5u` is fetched for it.
- A `b64` header of `false` is refused with `ErrMissingCriticalClaim`, even when you name `b64` in `UnderstoodCriticalHeaders`. RFC 7797 section 3 says such a payload is not base64url-encoded, and this library always decodes it. A `b64` header that is not a JSON boolean is refused with `ErrMalformedClaim`, as RFC 7797 section 3 requires.
- A `typ` or `cty` header that is not a string is refused with `ErrMalformedClaim`, whether or not you set `AcceptedTypes`. RFC 7515 sections 4.1.9 and 4.1.10 define each as a media type, which is a string.

One message can still have more than one valid token. ECDSA signatures are malleable: for an `ES256`, `ES384` or `ES512` token, anyone can replace the signature's `S` with `n - S` and get a second token that verifies. This needs no key. So do not key a replay or deduplication cache on the raw token string. Key it on a claim such as `jti` instead.

`VerifyCompactSerialization` refuses a nested JWT with `ErrMalformedToken`, before any key is sought. RFC 7519 section 5.2 marks one with a `cty` of `JWT`, compared as RFC 7515 section 4.1.10 describes: case-insensitively, with `application/` treated as prepended. Media-type parameters are ignored, so `application/jwt; charset=utf-8` is a nested JWT too. `Verify` does not look at `cty`, because section 4.1.10 says JWS implementations ignore it. To unwrap a nested JWT yourself, call `Verify` and verify the payload it returns.

Both try the keys from every source until one verifies the signature, up to `JoseOptions.MaxKeysTried`, which is 100 when unset. RFC 7517 section 4.5 does not require a `kid` to be unique, so a key set a peer publishes can hold thousands of keys under one `kid`, and each costs a signature verification. A token that would need more keys than the limit is refused with `ErrTooManyKeys`, not `ErrInvalidSignature`, so you can tell an oversized key set from a forgery. Only a key that a validator can be built from for the token's `alg` counts. The limit covers the keys your retriever returns too. When the limit is reached, no further `jku` or `x5u` is fetched.

## Keys a token carries

A JOSE header can name the key that signed the token, through `jwk`, `jku`, `x5c` or `x5u`. RFC 7515 section 10.3 says the technique used to get a public key "must authenticate the origin of the key". The four headers differ in whether anything authenticates the key, so each has its own switch:

| Header | Used when | What authenticates the key |
| --- | --- | --- |
| `x5c` | `X509Roots` is set | The chain validates against your roots, as section 4.1.6 requires |
| `x5u` | `X509Roots` and `HttpClient` are set | The same chain validation, after the fetch |
| `jwk` | `UseTokenProvidedKeys` is true | Nothing. The token names its own key |
| `jku` | `UseTokenProvidedKeys` is true and `HttpClient` is set | Nothing. The token's signer chooses the URL, and TLS proves only the server's identity |

`jwk` and `jku` are off by default, including when you pass no options, because anyone can sign a token and name their own key. A token that verifies against such a key proves only that its signer holds that key. Turn `UseTokenProvidedKeys` on only when your application ties those keys to a party you trust some other way:

```go
head, body, err := jwt.Validate(ctx, token, nil, &model.JoseOptions{UseTokenProvidedKeys: true})
```

Setting `X509Roots` does not turn `jwk` or `jku` on.

When you supply your own retriever and also use a header source, both are tried. The token verifies if a key from either source verifies it.

**This is a breaking change for a caller that passes no options.** v0.10.0 used a `jwk` header key when `opts` was `nil`. Such a caller must now pass `UseTokenProvidedKeys: true` to keep using it. A caller that set `UseTokenProvidedKeys` keeps a `jwk` header key, and now also gets `jku`. A caller that constructed `JoseOptions` without it was already getting no token keys.

### jku and x5u need a client

The two remote headers name a URL this library fetches. Supply the client it should use. The example below uses `x5u`; `jku` also needs `UseTokenProvidedKeys`:

```go
head, body, err := jwt.Validate(ctx, token, nil, &model.JoseOptions{
    HttpClient: &http.Client{Transport: yourGuardedTransport},
    X509Roots:  roots,
})
```

Both URLs come from the header of the token being verified, so this library makes an outbound request to an address a peer chose, before the signature is checked. Give the client a transport that rejects the destinations your deployment will not allow, such as private, loopback, link-local and other reserved ranges. The body is capped at 4 MiB whatever client you supply. Each fetch uses a copy of your client without its cookie jar. The fetch sends no cookies, and a cookie the server sets does not go into your jar. RFC 8725 section 3.10 asks for this.

Every request a fetch makes must use `https`, including each redirect hop. RFC 7515 sections 4.1.2 and 4.1.5 say an HTTP GET to retrieve the resource MUST use TLS, so a redirect to plain `http` is refused before the request is sent, whatever transport you supply. Your client's own redirect policy still applies. When it sets no `CheckRedirect`, Go's default stops after 10 redirects.

Each fetch is also bounded in time, provided your client's transport honours the request's context. `JoseOptions.FetchTimeout` covers the whole fetch, from sending the request to reading the last byte of the body. When it is zero, the limit is 10 seconds. A deadline or cancellation on the `ctx` you pass to `jwt.Validate`, `jws.Verify` or `jws.VerifyCompactSerialization` also stops the fetch. The limit applies to each fetch, so a token naming both `jku` and `x5u` can take two of them. Use `ctx` to bound the whole call.

A fetch stopped by either limit returns an error that matches `ErrApplicationError` and `context.DeadlineExceeded`. One stopped by cancelling `ctx` matches `context.Canceled`.

With no client, `jku` and `x5u` contribute no key. Each member of a `jku` set is judged on its own, as [Which jwk and jku keys are used](#which-jwk-and-jku-keys-are-used) describes, and a member this library cannot read is skipped, as RFC 7517 section 5 recommends. A document that is not a JWK Set is refused as a whole: one without a `keys` member, one whose `keys` is null or not an array, and one whose `keys` array holds a number, string, boolean or array. `jku` must be `https`, as RFC 7515 section 4.1.2 requires integrity protection, and an `x5u` resource is read as the PEM encoding section 4.1.5 requires. A server that sends raw DER instead is still read: a body that parses as DER certificates is taken as exactly those certificates, and is never searched for PEM text. Any other body is read as PEM text, so a body whose explanatory text is not valid UTF-8 is refused.

### Which jwk and jku keys are used

A key from a `jwk` header, or a member of a `jku` set, verifies the token only when all of these hold:

- Its `kid` is absent or equals the header's `kid`. RFC 7515 section 4.1.4 calls the header's `kid` a hint, and RFC 7517 section 4.5 makes a jwk's `kid` optional, so a key that names no `kid` stays a candidate.
- Its `alg` is absent or equals the header's `alg`. RFC 8725 section 3.1 says "each key MUST be used with exactly one algorithm". `EdDSA` and `Ed25519` count as equal, because with an Ed25519 key they name the same algorithm. A key that names no `alg` stays a candidate, since RFC 7517 section 4.4 makes `alg` optional. Such a key verifies under any algorithm its key type allows, so pin `AllowedSigningAlgorithms` to bind it to one.
- Its `use` is absent or `"sig"`, and its `key_ops` is absent or includes `"verify"`. RFC 7517 sections 4.2 and 4.3 let a publisher mark a key as not for verifying signatures.

A `jku` set is never used whole because nothing in it matched. When no member qualifies, the set contributes no key and the `jku` retriever's error matches `ErrNoKeyIdentifierMatch`. `VerifyCompactSerialization` then tries the next key source. If no key verifies, it reports `ErrInvalidSignature` and names the retriever's error only in its message, unless another source failed.

When a key source fails, verification continues with the next source. A source fails when a fetch fails, a body is too large, a body does not decode, or your retriever returns an error. A key the token carries that is itself malformed is different: it is wrong in the signed header every time. So when verification reaches it, a `jwk` with a member of the wrong type, or an `x5c` or `x5u` chain out of order, refuses the token at once with `ErrMalformedClaim`, and no later source is tried. Verification stops at the first key that verifies, so a key from your own retriever, which is tried first, can verify the token before a malformed header source is read. If no key verifies the signature, the error wraps each failure. It matches `ErrApplicationError` for a failed fetch, and `context.DeadlineExceeded` or `context.Canceled` when applicable. It does not match `ErrInvalidSignature`. A `kid`, `alg`, `use` or `key_ops` of the wrong JSON type disqualifies a `jku` member, and refuses an inline `jwk` with `ErrMalformedClaim`, whatever the header holds.

No RFC makes `use` or `key_ops` a requirement: section 4.3 leaves it to each application to say which, if either, it honours. This library honours both by default. Set `JoseOptions.IgnoreKeyUse` to skip that check. It never relaxes the `kid` and `alg` rules.

### Stating what you expect of a header

Most JOSE profiles pin their own `typ`, many require a `kid`, and RFC 7515 section 4.1.11 says a JWS whose `crit` lists an extension the recipient does not understand **MUST** be rejected. Rather than decoding the header yourself to check those, say what you expect:

```go
head, body, err := jwt.Validate(ctx, token, retriever, &model.JoseOptions{
    AcceptedTypes:             []string{"example+jwt"},
    RequireKeyIdentifier:      true,
    UnderstoodCriticalHeaders: []string{"x-example"},
    AllowedSigningAlgorithms:  []jwa.Algorithm{jwa.ES256, jwa.RS256},
})
```

Each is off when unset, so none of this changes what an existing caller sees — except `crit`, below.

`AcceptedTypes` compares as RFC 7515 section 4.1.9 requires: case-insensitively, with `application/` treated as prepended to any value containing no `/`. So naming `example+jwt` accepts `application/example+jwt` and `Example+JWT`, and refuses `x-example+jwt`. Media-type parameters are ignored on both sides, so `example+jwt; v=1` matches `example+jwt`. A `typ` with no type before its parameters matches nothing.

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

head, body, err := jwt.Validate(ctx, token, nil, &model.JoseOptions{X509Roots: roots})
```

With no `X509Roots` configured, a token's `x5c` and `x5u` headers contribute no key. They are not an error — section 4.1.6 makes use of the header OPTIONAL — so the token still verifies if another key source does, and fails with `no cyptographic material provided for signature validation` if none does.

A malformed `x5c` is refused whether or not roots are configured, because its shape is a property of the claim rather than of your trust configuration. An array that is not an array of strings, an empty array, or an entry that is not exactly one base64-encoded DER certificate is `ErrMalformedClaim`. Section 4.1.6 names the base64 of RFC 4648 section 4, and RFC 4648 section 3.3 says a decoder MUST reject characters outside the alphabet. So an entry holding a line break is refused, as is one whose pad bits are not zero. An `x5u` body is PEM, where line breaks are part of the format, so this does not apply to it.

The signing key is taken from the first certificate, and that certificate is the one validated against your roots, as section 4.1.6 requires. The algorithm the issuer used to sign that certificate is not compared with the token's `alg`. An ES256 key in a certificate issued by an RSA root is usable.

An `x5c` or `x5u` chain must be in order. Each certificate after the first must be the one that signed the certificate before it, as RFC 7515 sections 4.1.5 and 4.1.6 require. Its subject must be the issuer of the certificate before it. A chain can hold at most 16 certificates. A chain that breaks either rule is refused with `ErrMalformedClaim`. This library checks the `x5c` count even when no roots are configured.

That first certificate must also be one whose key may verify a signature. `x5c` and `x5u` get the same checks:

- **Key usage.** When the certificate has a key usage extension, it must assert `digitalSignature` or `nonRepudiation` (`x509.KeyUsageContentCommitment`). RFC 5280 section 4.2.1.3 defines both as the bits for a key that verifies signatures, and requires at least one bit to be set when the extension appears, so an extension with no bit set is refused. A CA certificate that asserts only `keyCertSign` is refused, as is a key agreement certificate. An intermediate whose key usage extension is present must assert `keyCertSign`, as RFC 5280 section 6.1.4(n) requires. Go's chain verification checks this only when some bit is set, so this library also refuses an intermediate whose extension asserts no bit. The certificate is accepted when at least one chain avoids such an intermediate, and the trust anchor is not checked.
- **Extended key usage.** RFC 5280 section 4.2.1.12 says that when the extension is present, the certificate "MUST only be used for one of the purposes indicated". No purpose is registered for JWS, so you name the ones you accept in `JoseOptions.X509ExtKeyUsages`. When it is unset, only the signing certificate is checked: if its extension is present, it must name `anyExtendedKeyUsage`. When it is set, it is passed to Go's chain verification, which nests extended key usage, so the signing certificate and every CA above it must permit one of those purposes. A certificate with no extended key usage extension is accepted either way. A signing certificate or intermediate whose extension names no purpose is refused in every case, because the section defines it as a sequence of at least one. Go's chain verification treats such an extension as no restriction at all, so this library checks every chain it returns, and accepts the certificate when at least one chain has no such intermediate. The trust anchor is not checked: RFC 5280 section 6.1.1 takes from it only a name and a key.

```go
head, body, err := jwt.Validate(ctx, token, nil, &model.JoseOptions{
    X509Roots:        roots,
    X509ExtKeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageCodeSigning},
})
```

Naming `x509.ExtKeyUsageAny` turns the purpose check off, as it does in Go's `x509.VerifyOptions`. A purpose Go has no constant for, such as a private OID, cannot be named, so a certificate restricted to one is accepted only with the check off. A refusal for either usage matches `ErrNoKeyIdentifierMatch`, as a chain that does not validate does.

Configuring roots does not make `jwk` or `jku` usable. Nothing anchors those keys, so they need `UseTokenProvidedKeys`, as described under [Keys a token carries](#keys-a-token-carries).

## Jwks
This library includes two methods for converting keys into JWK format

Every jwk these methods return carries a `kid`: the key's RFC 7638 JWK SHA-256 Thumbprint, base64url encoded. RFC 7638 hashes only the key type's required members, `kty` included, so two keys of different types cannot share a `kid`. Any other implementation computes the same value for the same key. A private key's `kid` is that of its public key, as RFC 7638 section 3.2.1 defines. The `kid` is a suggestion: set your own on the returned map if you name keys another way.

`jwk.Thumbprint` computes the thumbprint of any jwk of `kty` EC, RSA, oct, OKP or AKP. For AKP the members are `alg`, `kty` and `pub`, as RFC 9964 section 6 defines:

```go
func jwk.Thumbprint(jwk map[string]any) (string, error)
```

It refuses a jwk missing a required member, or one whose member would need escaping in JSON, because RFC 7638 section 3.3 defines no thumbprint for it.

`jwk.PublicJwk` takes a public key and returns the jwk representation of it:
```go
func jwk.PublicJwk(publicKey crypto.PublicKey) (*map[string]any, error)
func jwk.PrivateJwk(privateKey crypto.PrivateKey) (*map[string]any, error)
```

Pass the key in the form the standard library gives it. An `*ecdsa.PublicKey`, an `*rsa.PublicKey`, an `ed25519.PublicKey` (or a pointer to one), or an `*mldsa.PublicKey` is accepted. `PrivateJwk` takes the private equivalents. Anything else is refused with `ErrInvalidPublicKey` or `ErrInvalidPrivateKey`.

A key that cannot be encoded is refused with the same errors:

- A nil key, or a key with a missing field.
- An EC key on a curve other than P-256, P-384 and P-521, the curves RFC 7518 section 6.2.1.1 registers. The curve must be the standard library's own `elliptic.P256()`, `P384()` or `P521()`; another curve that carries one of those names is refused.
- An EC key whose point is not on its curve, including a negative coordinate or one too large for the curve.
- An EC private key whose `d` is outside `[1, n-1]`, where `n` is the order of the curve.
- An EC private key whose `d` is not the private key of its point.
- An Ed25519 private key whose second half is not the public key of its seed.
- An Ed25519 public key that is not the canonical encoding of a point. RFC 8032 section 5.1.3 refuses a `y` of 2^255-19 or more, and a set sign bit when `x` is 0.
- An RSA key whose `e` is not an odd integer from 3 to 2^31-1.
- An RSA private key whose `d` is not between 0 and `n`, or does not undo `e`.
- An RSA private key with no primes and a modulus over 8192 bits.
- An RSA private key with one prime, or more than two. RFC 7518 section 6.3.2.7 says a consumer that does not support more than two MUST NOT use such a key, and `PrivateFromJwk` refuses a jwk that carries `oth`.
- An RSA private key with a prime that is not positive. RFC 8017 section 3.2 makes `p` and `q` positive integers.
- A two-prime RSA private key that `rsa.PrivateKey.Validate` rejects, such as one whose primes do not multiply to `n`.

An EC private key's `d` is padded to the length of the curve order, as RFC 7518 section 6.2.2.1 requires.

An RSA private key with no primes is encoded as `n`, `e` and `d`. RFC 7518 section 6.3.2 makes `d` the only required private member. A two-prime key also carries `p`, `q`, `dp`, `dq` and `qi`, which that section says producers SHOULD include. The CRT values are computed on a copy, so the caller's key is not changed.

```go
// Direct from a public key
jwkMap, err := jwk.PublicJwk(publicKey)

// From a Signer. Note Public() is a call, and its result is already a pointer
// for the EC and RSA algorithms
signer, err := jws.GetSigner(jwa.ES256, nil)
signerJwkMap, err := jwk.PublicJwk(signer.Public())
```

Two methods convert a jwk back into a key:

```go
func jwk.PublicFromJwk(jwk map[string]any) (crypto.PublicKey, error)
func jwk.PrivateFromJwk(jwk map[string]any) (crypto.PrivateKey, error)
```

The value returned is a pointer to the respective key, such as `*ecdsa.PublicKey` or `*rsa.PublicKey`.

An `OKP` jwk is read only when its `crv` is `Ed25519`, the one OKP subtype this library supports. RFC 8037 section 2 requires `crv`, so a jwk without a string `crv` is refused as an invalid key. Any other subtype is refused with `ErrUnsupportedAlgorithm`. Each of `x` and `d` must be 32 octets, the key sizes RFC 8032 section 5.1.5 sets for Ed25519. For a private key, `x` must be the public key of `d`. `x` must be the canonical encoding of a point, so one key has one `x` and one thumbprint.

**This is a breaking change for OKP keys.** Earlier versions ignored the value of `crv`, so an `X25519` or `Ed448` key was returned as an Ed25519 key. They also accepted any length of `x` and `d`, and did not compare `x` with `d`. A key that those versions read can now be refused.

An `AKP` jwk is read as RFC 9964 defines it. Section 3 requires `alg`, and it must be `ML-DSA-44`, `ML-DSA-65` or `ML-DSA-87`. A jwk with no string `alg` is refused as an invalid key, and any other `alg` with `ErrUnsupportedAlgorithm`. `pub` must be the public key size section 5 gives for that `alg`: 1312, 1952 or 2592 octets. A private key's `priv` must be the 32 octet seed of section 4, and `pub` must be the public key that seed derives, which section 7.4 calls for. `PublicFromJwk` reads the public key of a private AKP jwk and does not read `priv`, as it does for EC and RSA. `PublicJwk` never writes `priv`, which section 3 says MUST NOT be present in a public key.

An `EC` jwk is read only when its `crv` is P-256, P-384 or P-521. Any other curve is refused with `ErrUnsupportedAlgorithm`. Each of `x` and `y` must be the full size of a coordinate of the curve: 32, 48 or 66 octets. RFC 7518 sections 6.2.1.2 and 6.2.1.3 require this, so a coordinate with a leading zero octet dropped or added is refused. The point must be on the curve. A private key must carry `d`, which RFC 7518 section 6.2.2 makes REQUIRED. `d` must be the length of the curve order, in `[1, n-1]`, and `x` and `y` must be its public point.

Each integer member of an `RSA` jwk (`n`, `e`, `d`, `p`, `q`, `dp`, `dq` and `qi`) must use the minimum number of octets, as RFC 7518 section 2 requires of a Base64urlUInt. A member with a leading zero octet is refused with `ErrMalformedClaim`. Zero itself is the one octet `"AA"`. Without this rule one key would have more than one jwk, and so more than one RFC 7638 thumbprint.

An `RSA` jwk's `e` must be an odd integer from 3 to 2^31-1. RFC 3447 section 3.1 sets the lower bound and requires an odd value, and `crypto/rsa` refuses a larger one. A private key's `d` must be a positive integer less than `n`, as RFC 3447 section 3.2 defines it. When `p` and `q` are present, the key must pass `rsa.PrivateKey.Validate`, and `dp`, `dq` and `qi` must be the CRT values of `p`, `q` and `d`. When they are absent, the reader recovers `p` and `q` from `n`, `e` and `d`, as NIST SP 800-56B Rev. 2 Appendix C.1 describes. The key must then pass `rsa.PrivateKey.Validate`. The key that the reader returns carries `p`, `q` and their CRT values, so it signs as fast as a key read with them. If `d` does not undo `e`, the primes are not found or the key fails `Validate`, and the jwk is refused. The method recovers only two primes, so a key with no primes whose modulus has more than two is refused, like a jwk that carries `oth`. An `*rsa.PrivateKey` that lists more than two primes, as `rsa.GenerateMultiPrimeKey` returns, is still accepted by the signers. Recovery usually costs one or two full-size exponentiations. `PrivateFromJwk` refuses a bad `n` or `e` in an RSA private key with `ErrInvalidPrivateKey`, and a refused `e` also matches `ErrInvalidPublicKey`. A Base64urlUInt with no octets is refused with `ErrMalformedClaim`. An `n` of zero is refused. With no primes, a modulus over 8192 bits is refused before the primes are recovered.

A jwk with no `kty` is refused with `ErrInvalidPublicKey` or `ErrInvalidPrivateKey`. The error for an unsupported `kty` or `crv` names the values this library supports. It does not repeat the value the jwk carried, so a peer's text does not reach your logs.

### Key sets

`model.Jwks` holds a JWK Set. Decoding JSON into it follows RFC 7517 section 5: the document must be an object with a `keys` member holding an array of JWKs. Anything else is refused with `ErrKeystoreError`, including a missing `keys`, `"keys": null` and a document that is itself `null`. A field that may hold no set should be a `*model.Jwks`, which `null` leaves nil. The member is found by its exact name, `keys`, as RFC 7515 section 5.3 compares names; `KEYS`, `Keys` and other spellings are ignored like any unknown member. A `keys` member that is `null`, or that is not a JSON object, is refused. A document that is not UTF-8, or that holds an unpaired UTF-16 surrogate escape, is refused with `ErrKeystoreError`. RFC 8259 sections 8.1 and 8.2 give these rules.

`Opts.EnforceUniqueKIDs` applies to `Add` only. Decoding keeps every key, including keys with the same `kid`.

`Jwks.RetrieveByKeyID` returns every key that carries the given `kid`, in set order, because RFC 7517 section 4.5 does not make a `kid` unique. It returns an error only when no key carries it.

## JWTs
This library includes two methods for jwt handling

The first signs a jwt from a signer, a head map and a body map:

```go
func jwt.New(signer crypto.Signer, head, body map[string]any, opts jwt.Opts) (*string, error)
```

`New` does not change the maps you pass. A nil head is an empty header, and a nil body is the empty claims set `{}`. If the head carries no `typ`, the token's header gets `"JWT"`.

`jwt.Opts` names the algorithm to sign with:

```go
type jwt.Opts struct {
	Algorithm jwa.Algorithm
}
```

The token's `alg` header always names the algorithm that made the signature, as RFC 7515 section 4.1.1 requires:

- A signer from this library signs with its own algorithm, and `New` writes that algorithm into `alg`. `Opts` may leave `Algorithm` unset. `New` calls it in JOSE mode, with the whole signing input. So does any other `model.Signer`.
- Any other `crypto.Signer` takes its algorithm from `Opts.Algorithm`, or from an `alg` the head names. With neither, `New` returns an error.
- If the head's `alg` or `Opts.Algorithm` names a different algorithm, `New` returns `ErrUnsupportedAlgorithm`. So does an `alg` that is not a string.

A `crypto.Signer` from elsewhere, such as an `*ecdsa.PrivateKey`, an `*rsa.PrivateKey`, an `ed25519.PrivateKey` or a KMS signer, is called as Go's `crypto.Signer` contract defines:

- For ES256, ES384 and ES512, `New` converts the ASN.1 DER signature the signer returns to the fixed-length R||S form of RFC 7518 section 3.4. The key must be on P-256, P-384 or P-521 respectively. Output that is not DER, or an R or S outside 1 to n-1 (FIPS 186-5 section 6.4.1), is refused with `ErrSigningError`.
- For PS256, PS384 and PS512, `New` asks for RSASSA-PSS with a salt the size of the hash, as RFC 7518 section 3.5 requires. For RS256, RS384 and RS512 it asks for RSASSA-PKCS1-v1_5.
- For Ed25519, the key must be an Ed25519 key.
- For ML-DSA-44, ML-DSA-65 and ML-DSA-87, the key must be an ML-DSA key of that parameter set. `New` passes the whole signing input with a zero hash, so `crypto/mldsa` signs it with an empty context.
- A key that does not suit the algorithm, and any HS algorithm, is refused with `ErrInvalidPrivateKey`.
- `New` passes an `*ecdsa.PrivateKey`, `*rsa.PrivateKey`, `ed25519.PrivateKey` or `*ed25519.PrivateKey` to `GetSignerFromPrivateKey`, and refuses each key that `GetSignerFromPrivateKey` refuses. So an RS or PS key needs a modulus of 2048 to 8192 bits. For any other `crypto.Signer`, `New` checks the public key that `Public` returns, the same way a validator does.
- `New` refuses a nil signer, or a nil pointer, with `ErrInvalidPrivateKey`. It does not panic.
- `New` refuses an `alg` outside `jwa`, such as `jwa.Algorithm(999)`, with `ErrUnsupportedAlgorithm`. RFC 7515 section 4.1.1 says `alg` must be present and understood.
- `New` checks the header it will sign with the same rules `Validate` applies, and returns the same errors. So it does not sign a header that its own `Validate` refuses for its shape:
  - `jku` and `x5u` must be HTTPS URLs. RFC 7515 sections 4.1.2 and 4.1.5 require TLS.
  - `jwk` must be a JSON object (section 4.1.3).
  - `kid`, `typ` and `cty` must be strings (sections 4.1.4, 4.1.9 and 4.1.10).
  - `x5c` must be a non-empty array of base64 DER certificates (section 4.1.6).
  - `x5t` and `x5t#S256` must be base64url (sections 4.1.7 and 4.1.8).
  - `crit` must be a non-empty array of distinct names. Each name must be in the header, and must not be a parameter that RFC 7515 defines (section 4.1.11).
  - `b64` must be a JSON boolean (RFC 7797 section 3).

  A fault is `ErrMalformedClaim`. A `crit` name that the header does not hold is `ErrMissingCriticalClaim`.
- `New` refuses a `b64` of `false` with `ErrMissingCriticalClaim`, because it always encodes the payload.
- `New` refuses a `b64` that `crit` does not name with `ErrMissingCriticalClaim`. RFC 7797 section 6 says `crit` MUST include `b64` when `b64` is used. To sign with `"b64": true`, also set `"crit": ["b64"]`. A verifier must then name `b64` in `UnderstoodCriticalHeaders`.

The second validates a jwt and returns the decoded head and body:

```go
func jwt.Validate(ctx context.Context, token string, outOfBoundsPublicKey model.Retriever, opts *model.JoseOptions) (head, body map[string]any, err error)
```

The retriever supplies key material of your own. Pass nil only when a key the token's header names can verify it: when you have turned on `UseTokenProvidedKeys` for `jwk` and `jku`, or set `X509Roots` for `x5c` and `x5u`. `model.JoseOptions` carries everything described under [Keys a token carries](#keys-a-token-carries), and may be nil for the defaults.

`Validate` checks each registered claim that is present:

| Claim | Rule | Error when broken |
| --- | --- | --- |
| `iss`, `sub`, `jti` | Must be a string (RFC 7519 sections 4.1.1, 4.1.2 and 4.1.7) | `ErrMalformedClaim` |
| `aud` | Must be a string or an array of strings (RFC 7519 section 4.1.3) | `ErrMalformedClaim` |
| `iat`, `nbf`, `exp` | Must be a JSON number, a NumericDate (RFC 7519 section 2). A fractional value keeps its fraction, and is compared as float64 seconds, to within a microsecond | `ErrMalformedClaim` |
| `exp` | The current time must be before `exp` (RFC 7519 section 4.1.4). A token is expired at the instant `exp` names | `ErrExpired` |
| `nbf` | The current time must be at or after `nbf` (RFC 7519 section 4.1.5) | `ErrNotYetValid` |
| `iat` | Must not be after the current time | `ErrNotYetValid` |

The `iat` rule is this library's own. RFC 7519 section 4.1.6 sets no acceptance rule for `iat`, but a token issued in the future signals a clock fault or a forged timestamp, so `Validate` refuses it.

`JoseOptions.ClockSkewLeeway` widens the window the three time claims are judged against: `nbf` and `iat` may be up to the leeway in the future, and a token stays valid until the leeway has passed after `exp`.

A value too large for any clock, such as an `nbf` of `1e19`, is judged as a time far in the future. It is not converted to an integer, so the result is the same on every CPU. A number outside the float64 range, such as `1e400`, is different: the JSON decoder refuses the token with `ErrMalformedToken` before any claim is read. RFC 8259 section 6 lets a recipient limit the range of numbers.

`Validate` refuses a token that does not have three segments with `ErrMalformedToken`. A token of five segments is a JWE, which this library does not support, so it is refused with `ErrUnsupportedAlgorithm`.

To check the audience, name this recipient in `JoseOptions.ExpectedAudience`:

```go
opts := &model.JoseOptions{ExpectedAudience: []string{"https://rp.example"}}
```

`aud` must then hold a value equal to one of these, compared exactly and case-sensitively, as RFC 7519 section 4.1.3 requires. A token with no `aud` is refused with `ErrMissingClaim`, as RFC 8725 section 3.9 requires. A token naming only other recipients is refused with `ErrAudienceMismatch`.

An empty string names no recipient. If `ExpectedAudience` holds one, `Validate` refuses every token with `ErrInvalidOptions`. This catches a value read from an unset environment variable, which would otherwise match a token whose `aud` is `""`.

**With `ExpectedAudience` unset, this library does not meet RFC 7519 section 4.1.3.** That section says: "If the principal processing the claim does not identify itself with a value in the "aud" claim when this claim is present, then the JWT MUST be rejected." By default, `Validate` checks only the type of `aud` and accepts a token whatever it names. Set `ExpectedAudience` to meet that MUST. RFC 8725 section 3.9 also requires the check whenever one issuer issues tokens for more than one audience.

## Errors
Sentinel errors live in the `joseerror` package. Match one with `errors.Is`:

| Sentinel | Meaning |
| --- | --- |
| `ErrInvalidPublicKey` | The public key given cannot be used for this algorithm |
| `ErrInvalidPrivateKey` | The private key or secret given cannot be used for this algorithm |
| `ErrInvalidSignature` | The signature does not verify against the signing input |
| `ErrDecryptionFailed` | Reserved for JWE. Nothing returns it: the `jwe` package is a stub and exports nothing |
| `ErrUnsupportedAlgorithm` | The algorithm named is not supported, has no validator in this library, or is not permitted by the options given |
| `ErrSigningError` | Signing failed |
| `ErrMalformedClaim` | A claim is present but its type or value is wrong. This includes a `b64` that is not a boolean, and an `x5c` or `x5u` chain that is out of order or longer than 16 certificates |
| `ErrMissingClaim` | A required claim is absent |
| `ErrMissingCriticalClaim` | A header named in `crit` is absent, or names an extension this library does not understand, or `b64` is `false` |
| `ErrNoKeyIdentifierMatch` | No key could be selected. The `kid` matches nothing, a `jku` set holds no usable key that matches the header, a certificate chain does not reach a configured root, or an `x5t` thumbprint does not match the chain |
| `ErrKeystoreError` | A `model.Jwks` lookup or addition failed, a document decoded into `model.Jwks` is not a JWK Set, or the configuration needed to use a key source is absent, such as `X509Roots` for a certificate chain |
| `ErrApplicationError` | Key material a header named could not be obtained, decoded or used. Covers a failed `jku` or `x5u` fetch, a local decode of what one returned (an empty `x5u` body is a failed decode), and an inline `jwk` of a key type or curve this library does not support. A fetch that ran out of time also matches `context.DeadlineExceeded`, and one cancelled through `ctx` matches `context.Canceled` |
| `ErrMalformedToken` | The token is not a well formed JOSE object |
| `ErrExpired` | The current time is not before the token's `exp`, allowing for `ClockSkewLeeway` |
| `ErrNotYetValid` | The token's `nbf` or `iat` is after the current time, allowing for `ClockSkewLeeway` |
| `ErrAudienceMismatch` | `JoseOptions.ExpectedAudience` is set and the token's `aud` names none of its values |
| `ErrInvalidOptions` | The options passed are themselves wrong, whatever the token. A nil `ctx`, and a `JoseOptions.ExpectedAudience` that holds an empty string, are two cases |
| `ErrTooManyKeys` | The signature did not verify under as many keys as `JoseOptions.MaxKeysTried` allows, and more keys or key sources remained |

Each sentinel carries a prefix terminated by `": "`, so wrap one with `%w` immediately followed by the rest of the message and no space:

```go
fmt.Errorf("%wshould be an instance of *ecdsa.PrivateKey", joseerror.ErrInvalidPrivateKey)
```

That reads `invalid private key: should be an instance of *ecdsa.PrivateKey`, and `errors.Is` still matches.

When a header check echoes a value from the token in its error, the value is quoted with Go escaping and cut to its first 64 characters, with `...` marking the cut. A peer cannot put a raw line break or kilobytes of text into your logs this way. This includes the error from parsing an `x5c` or `x5u` certificate.

## Upgrading from 0.10.x

Every change below is a compile error or a silent behaviour change for a consumer of v0.10.0. Additions that change nothing you already use are listed in [New in 0.11.0](#new-in-0110).

### Module and API

- This module now requires Go 1.27. v0.10.0 declared Go 1.21, which Go no longer supports.
- `jwt.Validate` and `jws.VerifyCompactSerialization` take a `context.Context` first. It bounds any `jku` or `x5u` fetch. A nil `ctx` is refused with `ErrInvalidOptions`.
- Every `jwa.Algorithm` constant has a new integer value. `Unknown` is now 0, so a zero `Algorithm` names no algorithm. In v0.10.0 the zero value was `ES256`, so an unset `jwt.Opts.Algorithm` or configuration field meant ES256. v0.10.0's `Unknown` was 13, which is now `EdDSA`. If you store or send an `Algorithm` as an integer, store its `String()` and read it back with `jwa.GetAlgorithm`.
- `model.Jwks.RetrieveByKeyID` returns `[]map[string]any`, every key carrying the `kid` in set order, not one `map[string]any`. It returns an error only when no key carries the `kid`. To keep the old exactly-one meaning, check `len(keys) == 1` and use `keys[0]`.
- `model.Jwks.Add` with `EnforceUniqueKIDs` refuses a `kid` the set already holds more than once. v0.10.0 added it.
- `json.Marshal` of an empty `model.Jwks` writes `{"keys":[]}`. v0.10.0 wrote `{"keys":null}`.
- Decoding JSON into `model.Jwks` refuses a document with no `keys` member, with `"keys": null`, or that is `null`, and reads `keys` only by its exact name. It also refuses a `keys` member that is `null` or not an object, and a document that is not UTF-8 or holds an unpaired UTF-16 surrogate escape. See [Key sets](#key-sets).
- Every error sentinel's message now ends in `": "`, so it composes with the text that wraps it. A match on an error string breaks. Match with `errors.Is` instead.
- A header validation error now wraps its cause with `%w`. `errors.Is` matches the inner sentinel, such as `ErrMalformedClaim` or `ErrUnsupportedAlgorithm`, as well as `ErrMalformedToken`.
- Header errors that echo a token value use double quotes, not single quotes, and cut the value at 64 characters. Match errors with `errors.Is`, not their text.
- `GetSigner`, `GetSignerFromPrivateKey`, `GetValidator` and `GetValidatorFromJwk` return a nil interface when they fail. v0.10.0 could return a typed nil beside the error. That value was not `== nil`, and a call on it panicked.

### Signers and validators

- An HMAC secret must be at least the hash output size. `GetSigner` for HS256, HS384 or HS512 with no secret returns `ErrInvalidPrivateKey`. v0.10.0 returned an error that matched no sentinel.
- HS256, HS384 and HS512 signers refuse a non-zero `opts.HashFunc()` with `ErrSigningError`. v0.10.0 ignored `opts`. See [Signing Contract](#signing-contract).
- RS and PS signers and validators refuse a modulus under 2048 bits or over 8192 bits, wherever the key comes from. `GetSigner` refuses an `Opts.BitSize` over 8192. An `Opts.BitSize` under 2048 is now refused with `ErrInvalidPrivateKey`, so its message gains that error's `invalid private key: ` prefix.
- RS and PS signers and validators refuse a public exponent that is even, under 3, or over 2^31 - 1, with `ErrInvalidPrivateKey` or `ErrInvalidPublicKey`.
- An ES validator refuses a key on another curve, so `GetValidator(jwa.ES384, p256Key)` now fails with `ErrInvalidPublicKey`.
- A nil key, or one with missing fields, is refused when the signer or validator is built, rather than panicking later.
- Every signer and validator keeps its own copy of the key, and `Public` returns a new copy. In v0.10.0 an ES, RS or PS signer or validator used your key in place, so a later change to your key changed it. A validator built from a 2048-bit RSA key could then verify under a smaller one.
- ES, RS and PS signers refuse a private key whose private half does not belong to its public half. An RS or PS signer refuses such a key when it is built, not at `Sign`. An RSA private key that lists no primes has them recovered from `n`, `e` and `d`, so the signer signs with them.
- An ES signer in pre-hashed mode refuses a digest whose length is not the hash's output size with `ErrSigningError`.
- An RS or PS signature that does not verify returns `false` with a nil error, and an ES signature of the wrong length does too. Both used to return an error wrapping `ErrInvalidSignature`. If you told a forged signature apart by its error, check the boolean.
- `GetValidatorFromJwk` refuses a jwk with no `kty`, a `kty` that does not fit the algorithm, or an `alg` member that is not the algorithm you asked for. It also refuses a jwk whose `use` is present and not `"sig"`, or whose `key_ops` is present and lacks `"verify"`. To use such a key, read it with `jwk.PublicFromJwk` and pass it to `GetValidator`.

### `jwt.New`

- `jwt.New` now always calls a `model.Signer` in JOSE mode, with the whole signing input. v0.10.0 called it in pre-hashed mode whenever `Opts.Algorithm` named an ES, RS or PS algorithm. That included the zero `jwt.Opts{}`, whose `Algorithm` was ES256, so every `model.Signer` got a SHA-256 digest by default. A `model.Signer` of your own must accept the whole signing input.
- `jwt.New` refuses a head whose `alg` names a different algorithm from the one that signs, and an `alg` that is not a string, with `ErrUnsupportedAlgorithm`. It also refuses `Opts.Algorithm` naming a different algorithm from a signer of this library. Earlier versions wrote the caller's `alg` into the header unchecked.
- `jwt.New` with a `crypto.Signer` from outside this library needs an algorithm, from `Opts.Algorithm` or the head's `alg`, and a key that suits it. Earlier versions emitted a token with no `alg`. With a standard library ECDSA or RSA key, they also emitted an ES or PS signature no verifier would accept.
- `jwt.New` expects a `crypto.Signer` from outside this library to follow Go's `crypto.Signer` contract. For ES256, ES384 and ES512 that means ASN.1 DER output, which `New` converts to R||S. A signer that already returns raw R||S is now refused with `ErrSigningError`. Earlier versions passed its output through unchanged, so such a signer worked. Make it return DER, or make it a `model.Signer`.
- `jwt.New` refuses a `crypto.Signer` from outside this library for HS256, HS384 and HS512 with `ErrInvalidPrivateKey`. Earlier versions passed it the whole signing input. Build an HMAC signer with `jws.GetSigner` instead.
- `jwt.New` refuses `EdDSA` with `ErrUnsupportedAlgorithm`, whether `Opts.Algorithm` or the head's `alg` names it. v0.10.0 signed an `EdDSA` token with an `ed25519.PrivateKey`. Name `jwa.Ed25519` instead. A verifier that does not yet know `Ed25519` refuses the token, so make sure that your verifiers support it first.
- `jwt.New` refuses a nil signer or a nil key with `ErrInvalidPrivateKey`. v0.10.0 panicked.
- `jwt.New` refuses every key that `GetSignerFromPrivateKey` refuses, such as an RSA key under 2048 bits, and checks the public key of a `crypto.Signer` from outside this library. v0.10.0 signed with such keys, and this library then refused the token.
- `jwt.New` refuses an algorithm with no name, such as `jwa.Algorithm(999)`, with `ErrUnsupportedAlgorithm`. v0.10.0 wrote `"alg":""`.
- `jwt.New` refuses a head that `jwt.Validate` would refuse for its shape: a `kid` that is not a string, a `jku` or `x5u` that is not an `https` URL, a malformed `x5c`, `x5t`, `x5t#S256` or `jwk`, a `typ` or `cty` that is not a string, a `b64` that is not a boolean or is `false`, and a `crit` that breaks RFC 7515 section 4.1.11. It also refuses a `b64` that `crit` does not name, as RFC 7797 section 6 requires.
- `jwt.New` no longer writes `alg` and `typ` into the head map you pass.

### Verifying a token

- `JoseOptions.UseTokenProvidedKeys` is off unless set, including when `opts` is `nil`, and covers only `jwk` and `jku`. v0.10.0 used a `jwk` header key when `opts` was `nil`. Pass `UseTokenProvidedKeys: true` to keep using it.
- A `jwk` header key whose `use` is present and not `"sig"`, or whose `key_ops` is present and lacks `"verify"`, no longer verifies a token. The same rule applies to `jku` keys. Set `JoseOptions.IgnoreKeyUse` to accept such a key.
- `jku` and `x5u` can now supply a key. They are fetched with the client you set in `JoseOptions.HttpClient`. v0.10.0 passed no client, so neither header could be fetched, and a token naming one failed with `ErrApplicationError` unless your own key verified it first. With no client, both are now ignored. A fetch that fails gives way to the next key source. See [jku and x5u need a client](#jku-and-x5u-need-a-client).
- `x5c` and `x5u` now work, but only when `JoseOptions.X509Roots` is set. `x5u` also needs `HttpClient`. v0.10.0 refused every token that carried `x5c`, because it could not read the JSON array, and never fetched `x5u`. A token with a well-formed `x5c` now verifies under your retriever's key when no roots are set. A chain must also be in order, hold at most 16 certificates, and pass the usage and encoding checks in [x5c and x5u need trust anchors](#x5c-and-x5u-need-trust-anchors). If your issuer gives signing certificates `serverAuth`, `clientAuth` or another purpose, list it in `X509ExtKeyUsages`.
- An `alg` that `AllowedSigningAlgorithms` does not allow is refused before any key is sought, with an error that matches `ErrUnsupportedAlgorithm` and `ErrMalformedToken`. v0.10.0 refused it with `ErrInvalidSignature`.
- A token whose `alg` is `EdDSA` now verifies under an Ed25519 key. v0.10.0 refused it with `ErrInvalidSignature`.
- A `crit` header naming an extension you have not declared in `UnderstoodCriticalHeaders` is refused.
- A token whose segments are not exactly base64url is refused, even when it is correctly signed. This covers line breaks, whitespace, padding and non-zero unused bits in the last character. The same rule applies to the base64url members of a jwk, such as `n`, `e`, `x`, `y` and `d`, and to `x5t` and `x5t#S256`.
- A protected header or JWT claims set that is not valid UTF-8 is refused. Previously each invalid byte became U+FFFD.
- A protected header or JWT claims set with a string that holds an unpaired UTF-16 surrogate escape, such as `"\ud800"`, is refused. Previously the escape became U+FFFD. A U+FFFD that is in the signed bytes, raw or as `\ufffd`, is still accepted.
- A JWT claims set of `null` is refused. `jwt.Validate` and `jws.VerifyCompactSerialization` previously returned a nil body and no error.
- A `b64` header of `false` is refused, even when `UnderstoodCriticalHeaders` names `b64`. A `b64` that is not a JSON boolean is refused with `ErrMalformedClaim`.
- A `typ` or `cty` header that is not a string is refused with `ErrMalformedClaim`, as RFC 7515 sections 4.1.9 and 4.1.10 require.
- A token whose `cty` is `JWT` is refused by `jws.VerifyCompactSerialization` and `jwt.Validate` with a message naming nested JWTs. Media-type parameters on the `cty` are ignored.
- A token's signature is checked against at most `JoseOptions.MaxKeysTried` keys, 100 by default, across every source. A token that would need more is refused with `ErrTooManyKeys`. If your retriever returns more than 100 keys that suit one `alg`, raise the limit.

### JWKs

- Every `kid` that `PublicJwk` and `PrivateJwk` produce has changed. It is now the key's RFC 7638 thumbprint, which other implementations compute the same way. The old value was a SHA-256 over the encoded public members with no `kty`, so keys of different types could share one. An Ed25519 jwk now carries a `kid` too. Re-derive any `kid` you stored or pinned.
- `PublicJwk` and `PrivateJwk` refuse a key they cannot encode, rather than panic or produce a malformed jwk.
- An `OKP` jwk is read only when it is a well-formed Ed25519 key, whose `x` is the canonical encoding of a point.
- A jwk with no `kty` is refused with `ErrInvalidPublicKey` or `ErrInvalidPrivateKey`. v0.10.0 returned an error that matched no sentinel.
- `PublicFromJwk`, `PrivateFromJwk`, `PublicJwk`, `PrivateJwk` and `Thumbprint` handle `AKP` keys. v0.10.0 refused every `AKP` jwk.
- `PublicFromJwk` and `PrivateFromJwk` refuse an EC jwk whose `x` or `y` is not the full coordinate size of its curve, or whose point is not on the curve. A producer that strips leading zero octets breaks RFC 7518 section 6.2.1.2, and its keys are now refused.
- `PrivateFromJwk` refuses an EC jwk with no `d`. It used to return a key that panicked when used.
- `PrivateFromJwk` refuses an EC or RSA jwk whose private members do not belong to its public members. An RSA jwk with no primes has them recovered, as NIST SP 800-56B Rev. 2 Appendix C.1 describes. So the key it returns carries `p` and `q`, a `d` that does not undo `e` is refused, and a modulus that is not the product of two primes is refused. Such a key, written again with `PrivateJwk`, now carries `p`, `q`, `dp`, `dq` and `qi`.
- `PublicJwk` and `PrivateJwk` refuse every key that `PublicFromJwk` and `PrivateFromJwk` refuse, such as an EC key whose `d` is not the private key of its point, or an RSA key whose `e` is even.
- An EC jwk with an unsupported `crv` is now refused with `ErrUnsupportedAlgorithm`. Before, the error matched no sentinel. The error text for an unsupported `kty` or `crv` no longer repeats the value.
- `PublicFromJwk` and `PrivateFromJwk` refuse an RSA integer member with a leading zero octet, such as `e: "AAEAAQ"`, with `ErrMalformedClaim`. RFC 7518 section 2 requires the minimum number of octets. A producer that copies a DER integer, sign octet included, into `n` makes such a member. Have it strip the leading zero octet.
- `PublicFromJwk` and `PrivateFromJwk` refuse an RSA `e` that is even, below 3 or above 2^31-1. An `e` of more than 8 octets used to be read as its low 64 bits. They also refuse an RSA integer member with no octets, an `n` of zero, and a private key with no primes whose modulus is over 8192 bits.
- `PrivateFromJwk` reports a bad `n` or `e` in an RSA private jwk with `ErrInvalidPrivateKey`. The error still matches the class of the inner fault, such as `ErrInvalidPublicKey` for a refused `e`.

### `jwt.Validate`

- `jwt.Validate` refuses a token at the instant its `exp` names, and judges a fractional `iat`, `nbf` or `exp` without dropping the fraction. Earlier versions cut the current time and each claim to whole seconds. So they accepted a token for up to a second past `exp`, and up to a second before a fractional `nbf` or `iat`.
- `jwt.Validate` refuses an `iss`, `sub`, `jti` or `aud` of the wrong JSON type with `ErrMalformedClaim`.
- `jwt.Validate` refuses a token that does not have three segments with `ErrMalformedToken`, and one of five segments, a JWE, with `ErrUnsupportedAlgorithm`. v0.10.0 returned errors that matched no sentinel.
- A time-claim refusal now matches `ErrMalformedClaim`, `ErrExpired` or `ErrNotYetValid`, and its message has changed. If you match on the old text, such as `exp claim is before current time`, match with `errors.Is` instead.

### New in 0.11.0

These add to the API without changing what you already use:

- `jws.Verify` returns the payload as octets, for a JWS whose payload is not a JSON object.
- `jwk.Thumbprint` computes the RFC 7638 thumbprint of a jwk.
- `jwa.Ed25519`, `jwa.MLDSA44`, `jwa.MLDSA65` and `jwa.MLDSA87`, each with a signer and a validator.
- `JoseOptions` fields: `HttpClient`, `FetchTimeout`, `MaxKeysTried`, `AcceptedTypes`, `RequireKeyIdentifier`, `UnderstoodCriticalHeaders`, `X509Roots`, `IgnoreKeyUse`, `X509ExtKeyUsages` and `ExpectedAudience`. Each is off, or the documented default, when unset.
- Error sentinels: `ErrExpired`, `ErrNotYetValid`, `ErrAudienceMismatch`, `ErrInvalidOptions` and `ErrTooManyKeys`.

## Upgrading from the pre-0.10 line

Every change below is a compile error or a silent behaviour change for a consumer of the release before v0.10.0. Apply [Upgrading from 0.10.x](#upgrading-from-010x) as well.

### Packages moved

| Was | Now |
| --- | --- |
| `go-jose/error` | `go-jose/joseerror` |
| `model.Algorithm`, `model.ES256` and the rest | `jwa.Algorithm`, `jwa.ES256` and the rest |

### Error sentinels

Every sentinel gained an `Err` prefix: `InvalidPublicKey` is now `ErrInvalidPublicKey`, `SigningError` is now `ErrSigningError`, and the same for the rest. v0.10.0 added eight sentinels, and v0.11.0 adds five more. Match a sentinel with `errors.Is`:

```go
if errors.Is(err, joseerror.ErrInvalidSignature) {
```

### Signatures changed

| Function | Change |
| --- | --- |
| `jwa.GetAlgorithm` | Returns `Algorithm`, not `*Algorithm`. Returns `jwa.Unknown` rather than nil for an unknown name, and the comparison is now case sensitive |
| `jwt.New` | Takes a fourth parameter, `jwt.Opts`, naming the algorithm to sign with |
| `jwt.Validate` | Takes a `model.Retriever` and `*model.JoseOptions` after the token. The `publicKey` parameter is gone: supply key material through the retriever, or turn on `UseTokenProvidedKeys` to use what the token's header names |
| `jws.GetValidatorFromJwk` | Takes `map[string]any`, not `[]byte` |

### Behaviour changes documented elsewhere in this file

- A validator for an HMAC algorithm can only be built from a signer.

### Not implemented

The `jwe` package exports nothing. JWE is not supported in this release.
