# Go Jose
Package go_jose is a set of crypto signer implementations for common algorithms

## Requirements
- Go 1.21 or higher

## Installation
```bash
go get github.com/MichaelFraser99/go-jose
```

## Algorithms Supported
Currently, the module supports the following signing algorithms:
- ES256
- ES384
- ES512
- RS256
- RS384
- RS512
- PS256
- PS384
- PS512

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

In addition, the validator object also has a method `Jwk()` which returns a `map[string]string` representation of the public key in jwk format
```go
validator, err := jose.GetValidator(model.ES256, publicKey)
jwk := validator.Jwk()
```

Finally, validators expose their PublicKey with the `Public()` method
```go
validator, err :- jose.GetValidator(model.ES256, publicKey)
pk := validator.Public()
```

### Errors
This package defines the following errors:
- InvalidSignature - The provided signature does not match the digest
- UnsupportedAlgorithm - The algorithm specified is not currently supported
- InvalidPublicKey - The provided public key is invalid
- SigningError - An error occurred while signing the token
