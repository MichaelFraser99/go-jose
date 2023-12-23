package error

import "errors"

var InvalidPublicKey = errors.New("")
var InvalidPrivateKey = errors.New("")
var InvalidSignature = errors.New("")
var UnsupportedAlgorithm = errors.New("")
var SigningError = errors.New("")
