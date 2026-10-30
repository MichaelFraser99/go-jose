# CLAUDE.md

This file gives guidance to Claude Code (claude.ai/code) when it works in this repository.

## Overview

A zero-dependency Go implementation of the JOSE standards: JWS (RFC 7515), JWE (RFC 7516), JWK (RFC 7517), JWA (RFC 7518) and JWT (RFC 7519). It is a library, not a service.

JWE is the Compact Serialization only, with the RSA-OAEP family, AES Key Wrap and `dir` for key management and all six RFC 7518 section 5 content encryption algorithms. `RSA1_5` is left out on purpose (RFC 8725 section 3.2). ECDH-ES, AES GCM key wrap, PBES2, `zip`, nested JWTs and HPKE are planned under issue #72 and not yet implemented.

## Commands

- **Test:** `go test ./...`. CI runs a second `go test -race ./...` pass, so a change must be clean under the race detector too.
- **Single test:** `go test ./jws -run TestGetSigner_AFailedConstructionReturnsNoSigner` (add `-v` for verbose).
- **Lint:** `golangci-lint run`.
- **Format:** `gofmt -l .` must print nothing.
- **Go version:** see `go.mod`.

## Comments

Concise and genuinely helpful godoc comments are permitted here. Two conditions, and both apply:

1. **Godoc only.** A comment documents an exported declaration and sits directly above it. Do not put notes inside a function body. If a test needs explaining, put the explanation in its name and in its failure message.
2. **Concise.** Say what the thing does, and name the clause that makes it behave that way. Do not explain what changed or why a previous version was wrong. That belongs in the commit message.

A godoc comment that names an RFC clause earns its place. One that recounts a fix does not.

## Layout

- **`jwa/`** — algorithm identifiers. `Algorithm` is an int whose zero value is `Unknown`.
- **`jws/`**, **`jwe/`**, **`jwt/`**, **`jwk/`** — the public API. There is **no root package**: `go-jose` itself holds only `e2e_test.go`. Import the subpackage.
- **`model/`** — exported types shared across packages, including `JoseOptions`.
- **`joseerror/`** — the error sentinels. Each carries a message prefix, so wrap with `%w` followed immediately by the rest of the message and no space.
- **`internal/algorithms/<alg>/`** — one package per algorithm. A signature algorithm has `NewSigner` and `NewValidator`. A JWE key management algorithm (`rsaoaep`, `keywrap`, `direct`) has `NewEncrypter` and `NewDecrypter`. `contentenc` builds the AEAD for an `enc`, and `aeskw`, `concatkdf` and `cbchmac` are the primitives the standard library lacks.
- **`internal/algorithms/common/`** — shared key handling, jwk production and jwk reading.
- **`internal/jose/`** — header validation, jwk parsing, x5 certificate handling, JSON utilities.
- **`internal/httputils/`** — the one place this library makes an outbound request.

## Things that are easy to get wrong

### An exported constructor must return a nil interface when it fails

`GetSigner`, `GetValidator`, `GetSignerFromPrivateKey` and `GetValidatorFromJwk` each assign a concrete pointer into an interface variable. If you return that variable alongside a non-nil error, the interface holds a typed nil: the value is not `nil` and any method call on it panics. Each of the four ends with an explicit `if err != nil { return nil, err }` for this reason. Keep it.

### Key material is handled by length, and the length rules differ

`internal/algorithms/hs256|hs384|hs512` each declare `MinimumSecretBytes` (32, 48, 64) and enforce it in both constructors, because RFC 7518 section 3.2 makes a key of at least the hash output size a MUST. RFC 7518 sections 3.3 and 3.5 require 2048 bits for the RS and PS families. There is no EC curve rule and no OKP rule in those sections, so do not invent one.

RFC 4231 test case 2 cannot go through an HMAC constructor: section 4.3 says its 4-byte key is chosen to test "a key shorter than the length of the HMAC output". It is pinned against `ProduceMac` in `internal/algorithms/common` instead, which sits below the length rule. The per-algorithm conformance tests use case 6, whose key is 131 bytes.

### A validator for an HMAC algorithm can only be built from a signer

`common.SecretKey` is an internal type, so an outside caller cannot construct one. `GetValidator` accepts only what `Signer.Public` returns, and `GetValidatorFromJwk` refuses an `oct` key outright. To verify with a secret you were given, build a signer with it first and pass `signer.Public()`. The length refusal inside `NewValidator` is therefore unreachable from outside the library.

### A peer chooses the `jku` and `x5u` a token names

Both URLs come from the header of the token being verified, so this library makes an outbound request to an address a peer chose. `internal/httputils` caps a body at `MaxBodyBytes` and reads one byte past it, so a caller can tell an oversize body from one that exactly fills the cap. The address policy is the caller's: `JoseOptions.HttpClient` documents that their transport must refuse what their deployment will not allow. The time bound is the library's: every fetch runs under a context derived from the caller's `ctx`, limited by `JoseOptions.FetchTimeout` (10 seconds when unset), and released when the body is closed. Read a fetched body through `httputils.ReadBody`, which closes it on every path.

### A malformed jwk must return an error, never panic

A `kty` this library does not recognise returns an error. Hold every new reader to the same standard, including one for a key type that is valid JOSE but unsupported here. Assert on a map member's type before using it: an unchecked `kty.(string)` panics on a peer's object or number.

### RFC 7515 section 4.1.6 requires a trust anchor

A recipient MUST validate an `x5c` chain per RFC 5280, and RFC 5280 path validation takes a trust anchor as an input. So a chain cannot vouch for itself. With no `JoseOptions.X509Roots` configured, `x5c` and `x5u` contribute no key.

### `JoseOptions` fields default by their zero value

A zero-valued field and a `nil` `*JoseOptions` must mean the same thing. `UseTokenProvidedKeys` is the example: it is off when unset and off when no options are passed. In v0.10.0 a `nil` options pointer turned it on while a constructed struct turned it off, so setting any unrelated option silently changed which keys verified a token. Keep new fields in the same shape, so that the zero value is the behaviour the documentation describes.

### Never ask a caller's ML-DSA key for its parameters

`crypto/mldsa` panics when `Parameters()` is called on a zero-value `*mldsa.PrivateKey` or `*mldsa.PublicKey`, and a zero-value private key reports the all-zero seed, which is the published RFC 9964 example key. So `common.UsableMLDSAPrivateKey` and `common.UsableMLDSAPublicKey` rebuild a key for the parameter set the algorithm names, and require the rebuilt key to match. Route every new ML-DSA entry point through them.

### `go.mod` retracts v0.10.1, and every release must keep that line

The tag v0.10.1 points at the wrong commit and stays only because the Go proxy has it. The `retract` directive in `go.mod` warns users off it. The Go toolchain reads retractions from the `go.mod` of the latest release only, so a release whose `go.mod` drops the line un-retracts v0.10.1. Do not remove it.

### A token's own keys are not trusted by default

A `jwk`, `jku`, `x5c` or `x5u` header names a key the token's signer chose. RFC 7515 section 10.3 requires the origin of a key to be authenticated. `x5c` and `x5u` are authenticated by chain validation against `X509Roots`, so setting roots is their opt-in. `jwk` and `jku` carry nothing that authenticates them, so they need `UseTokenProvidedKeys`. Setting one switch must never admit the other kind of source. Any new key source must name what authenticates it and be gated on that.

### Every JWE decryption failure must look the same

RFC 7516 section 11.5 requires a recipient not to reveal which step of decryption failed. `jwe.Decrypt` therefore never returns early once it has a candidate decrypter. If a decrypter fails, or returns a CEK of the wrong length, `Decrypt` uses a random CEK in its place and carries on to the tag check, then to the next decrypter. Every failure that depends on a key is `ErrDecryptionFailed` with one fixed message. The only other `ErrDecryptionFailed` message says that no decrypter implements the token's `alg`, which is public. Do not wrap a decrypter's own error into it, and do not add a check that returns between `Decrypt` on the key and `Open` on the content. Faults in the public structure of the token, such as an IV of the wrong length, are checked first and may be `ErrMalformedToken`.

### A JWE header's key parameters name the recipient's public key

In a JWS, `jku`, `jwk`, `x5u` and `x5c` name the key that verifies. In a JWE they name the public key the sender encrypted to, which cannot decrypt. So `jwe.Decrypt` never fetches or reads them, and the caller's decrypters are the only keys. Do not route a JWE header through `header.ValidateHeader`, which builds retrievers for them. `header.ValidateJWEHeader` is the JWE path.

## Conventions

- `//todo:` comments mark known incomplete areas. They are intentional signposts, not stray notes.
- Tests live beside the code as `_test.go`. Table-driven tests are strongly preferred over single-case.
- A test's failure message names the clause it tests, in brackets: `[RFC 7518 3.2]`.
- Derive a test's expected value from the specification, or from the standard library. Never compute it with the function under test, and never regenerate it from this implementation.
- Commits must not be co-authored.

## Standards

Pull the latest version of any specification before you rely on a clause from it.
