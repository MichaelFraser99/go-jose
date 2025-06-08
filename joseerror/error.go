package joseerror

import "errors"

var (
	ErrInvalidPublicKey     = errors.New("")
	ErrInvalidPrivateKey    = errors.New("")
	ErrInvalidSignature     = errors.New("")
	ErrDecryptionFailed     = errors.New("")
	ErrUnsupportedAlgorithm = errors.New("")
	ErrSigningError         = errors.New("")
	ErrMalformedClaim       = errors.New("")
	ErrMissingCriticalClaim = errors.New("")
	ErrMissingClaim         = errors.New("")
	ErrKeystoreError        = errors.New("")
	ErrApplicationError     = errors.New("")
	ErrNoKeyIdentifierMatch = errors.New("")
	ErrMalformedToken       = errors.New("")
)
