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
signer, err := jose.GetSigner(model.ES256, nil)
```

The `GetSignerFromPrivateKey` method can also be used. This takes in an algorithm and a pointer to a `crypto.PrivateKey` implementation. The below example shows how to generate a signer for ES256:
```go
signer, err := jose.GetSignerFromPrivateKey(model.ES256, privateKey)
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
validator, err := jose.GetValidator(model.ES256, publicKey)

// Construct a validator from a signer instance
signer, err := jose.GetSigner(model.ES256, nil)
validator, err := jose.GetValidator(signer.Alg(), signer.Public())
```

The `GetValidatorFromJwk` method takes in the bytes of a jwk format public key and returns a validator instance. The below example shows how to generate a validator for ES256:
```go
// Construct a validator from a jwk public key
validator, err := jose.GetValidatorFromJwk(model.ES256, publicKeyBytes)
```

The validator object has a method `ValidateSignature` which takes in the bytes of the digest and signature and returns a boolean indicating whether the signature is valid. The below example shows how to validate a signature:
```go
// Validate a signature
validator, err := jose.GetValidator(model.ES256, publicKey)

valid, err := validator.ValidateSignature(digest, signature)
```

Finally, validators expose their PublicKey with the `Public()` method
```go
validator, err :- jose.GetValidator(model.ES256, publicKey)
pk := validator.Public()
```

## Jwks
This library includes two methods for converting keys into JWK format

All JWK methods include in the returned map a KID suggestion based on the public key component

PublicJwk takes in a pointer to a public key and returns a `map[string]string` containing the jwk representation of the provided public key
```go
// Direct from a public key
jwkMap, err := PublicJwk(publicKey)

// From a Signer
signer, err := jose.GetSigner(model.ES256, nil)
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
