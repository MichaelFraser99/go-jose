package joseerror

import "errors"

// Sentinel errors each carry a prefix terminated by ": ". Wrap one with %w and a
// discriminating suffix so the two compose into a single sentence:
//
//	fmt.Errorf("%wshould be an instance of *ecdsa.PrivateKey", joseerror.ErrInvalidPrivateKey)
//
// reads "invalid private key: should be an instance of *ecdsa.PrivateKey", and
// errors.Is(err, joseerror.ErrInvalidPrivateKey) still matches.
var (
	ErrInvalidPublicKey     = errors.New("invalid public key: ")
	ErrInvalidPrivateKey    = errors.New("invalid private key: ")
	ErrInvalidSignature     = errors.New("invalid signature: ")
	ErrDecryptionFailed     = errors.New("decryption failed: ")
	ErrUnsupportedAlgorithm = errors.New("unsupported algorithm: ")
	ErrSigningError         = errors.New("signing error: ")
	ErrEncryptionError      = errors.New("encryption error: ")
	ErrMalformedClaim       = errors.New("malformed claim: ")
	ErrMissingCriticalClaim = errors.New("missing critical claim: ")
	ErrMissingClaim         = errors.New("missing claim: ")
	ErrKeystoreError        = errors.New("keystore error: ")
	ErrApplicationError     = errors.New("application error: ")
	ErrNoKeyIdentifierMatch = errors.New("no key identifier match: ")
	ErrMalformedToken       = errors.New("malformed token: ")
	ErrExpired              = errors.New("expired: ")
	ErrNotYetValid          = errors.New("not yet valid: ")
	ErrAudienceMismatch     = errors.New("audience mismatch: ")
	ErrInvalidOptions       = errors.New("invalid options: ")
	ErrTooManyKeys          = errors.New("too many keys: ")
)
