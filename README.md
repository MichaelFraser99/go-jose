# Go Jose
Package go_jose is a set of crypto signer implementations for common algorithms

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

Please note `Validator` objects cannot be created for HMAC algorithms. When creating a new Signer an optional secret key can be passed as `[]byte`. If none provided, a random key is instead generated and can be retrieved with the `Public` method. This returns an object of type `SecretKey` defined as so:
```go
type SecretKey []byte

func (s *SecretKey) Equal(x crypto.PublicKey) bool {
	secretKey, ok := x.(*SecretKey)
	if !ok {
		return false
	}

	return bytes.Equal(*s, *secretKey)
}
```

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

## SignerOpts
This package includes a SignerOpts implementation as shown below:
```go
type SignerOpts struct {
	Hash crypto.Hash
}
```
This is provided for simplicity and usage is in line with that specified by the `crypto.Signer` interface. If a hash isn't specified, no hashing is assumed as having occured and the signing algorithms will perform their own hashing.

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
validator, err :- jose.GetValidator(jwa.ES256, publicKey)
pk := validator.Public()
```

## Keys a token carries

A JOSE header can name the key that signed the token, through `jwk`, `jku`, `x5c` or `x5u`. `jwt.Validate` and `jws.VerifyCompactSerialization` will use those keys, which is what `JoseOptions.UseTokenProvidedKeys` governs. It defaults to true, so a token carrying its own key verifies against it unless you turn that off:

```go
head, body, err := jwt.Validate(token, nil, &model.JoseOptions{UseTokenProvidedKeys: false})
```

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
This package defines the following errors:
- InvalidSignature - The provided signature does not match the digest
- UnsupportedAlgorithm - The algorithm specified is not currently supported
- InvalidPublicKey - The provided public key is invalid
- SigningError - An error occurred while signing the token
