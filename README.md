# Go Jose
Package go_jose is a set of crypto signer implementations for common algorithms

## Requirements
- Go 1.21 or higher

## Installation
```bash
go get github.com/MichaelFraser99/go-jose
```

## Algorithms Supported
Currently, the module will support the following signing algorithms:
- ES256
- ES384
- ES512

## Signers
Each algorithm packages a NewSigner() method. This returns a `crypto.Signer` implementation for the given algorithm complete with generated key pair. The below example shows how to generate a signer for ES256:
```go
signer, err := es256.NewSigner()
```

In addition to the methods specified by the `crypto.Signer` interface, the signer object also packages a Validator (see more below) bound to matching public key. This can be accessed through the `Validator()` method
```go
signer, err := es256.NewSigner()
validator := signer.Validator()
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

The NewValidator method takes in a crypto.PublicKey implementation and returns a validator instance. The below example shows how to generate a validator for ES256:
```go
// Construct a validator from a public key
validator, err := es256.NewValidator(publicKey)

// Construct a validator from a signer instance
signer, err := es256.NewSigner()
validator, err := es256.NewValidator(signer.Public())
```

The NewValidatorFromJwk method takes in the bytes of a jwk format public key and returns a validator instance. The below example shows how to generate a validator for ES256:
```go
// Construct a validator from a jwk public key
validator, err := es256.NewValidatorFromJwk(publicKeyBytes)
```

The validator object has a method `ValidateSignature` which takes in the bytes of the digest and signature and returns a boolean indicating whether the signature is valid. The below example shows how to validate a signature:
```go
// Validate a signature
validator, err := es256.NewValidator(publicKey)

valid, err := validator.ValidateSignature(digest, signature)
```

In addition, the validator object also has a method `Jwk()` which returns a `map[string]string` representation of the public key in jwk format
```go
validator, err := es256.NewValidator(publicKey)
jwk := validator.Jwk()
```

### Errors
This package defines the following errors:
- InvalidSignature - The provided signature does not match the digest
- UnsupportedAlgorithm - The algorithm specified is not currently supported
- InvalidPublicKey - The provided public key is invalid
- SigningError - An error occurred while signing the token
