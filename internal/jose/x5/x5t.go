package x5

import (
	"crypto/sha1"
	"crypto/sha256"
	"encoding/base64"
	"hash"
)

func CalculateX5t(cert []byte) string {
	return calculate(cert, sha1.New())
}

func CalculateX5tS256(cert []byte) string {
	return calculate(cert, sha256.New())
}

func calculate(cert []byte, h hash.Hash) string {
	hashed := h.Sum(cert)
	var encodedHash = make([]byte, base64.RawURLEncoding.EncodedLen(len(hashed)))
	base64.RawURLEncoding.Encode(encodedHash, hashed[:])
	return string(encodedHash)
}
