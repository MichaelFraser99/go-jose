package error

import "errors"

type InvalidSignature struct {
	Message string
}

func (e *InvalidSignature) Error() string {
	return e.Message
}

type UnsupportedAlgorithm struct {
	Message string
}

func (e *UnsupportedAlgorithm) Error() string {
	return e.Message
}

var InvalidPublicKey = errors.New("")
var InvalidPrivateKey = errors.New("")

type SigningError struct {
	Message string
}

func (e *SigningError) Error() string {
	return e.Message
}
