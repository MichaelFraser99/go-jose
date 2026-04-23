package error

import "errors"

var ErrInvalidPublicKey = errors.New("invalid public key: ")
var ErrInvalidPrivateKey = errors.New("invalid private key: ")
var ErrInvalidSignature = errors.New("invalid signature")
var ErrUnsupportedAlgorithm = errors.New("unsupported algorithm: ")
var ErrSigning = errors.New("signing error: ")
