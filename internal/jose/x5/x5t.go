package x5

import (
	"crypto/sha1"
	"crypto/sha256"
	"encoding/base64"
	"hash"
)

// CalculateX5t returns the base64url-encoded SHA-1 digest of the DER encoding of
// the given X.509 certificate, as RFC 7515 section 4.1.7 defines the x5t header.
func CalculateX5t(cert []byte) string {
	return calculate(cert, sha1.New())
}

// CalculateX5tS256 returns the base64url-encoded SHA-256 digest of the DER encoding
// of the given X.509 certificate, as RFC 7515 section 4.1.8 defines the x5t#S256 header.
func CalculateX5tS256(cert []byte) string {
	return calculate(cert, sha256.New())
}

func calculate(cert []byte, h hash.Hash) string {
	h.Write(cert)
	hashed := h.Sum(nil)
	var encodedHash = make([]byte, base64.RawURLEncoding.EncodedLen(len(hashed)))
	base64.RawURLEncoding.Encode(encodedHash, hashed)
	return string(encodedHash)
}
