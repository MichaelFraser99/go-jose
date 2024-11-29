package joseerror

import "errors"

var (
	InvalidPublicKey     = errors.New("")
	InvalidPrivateKey    = errors.New("")
	InvalidSignature     = errors.New("")
	UnsupportedAlgorithm = errors.New("")
	SigningError         = errors.New("")
	MalformedClaim       = errors.New("")
	MissingCriticalClaim = errors.New("")
	MissingClaim         = errors.New("")
	KeystoreError        = errors.New("")
	ApplicationError     = errors.New("")
	NoKeyIdentifierMatch = errors.New("")
	MalformedToken       = errors.New("")
)
