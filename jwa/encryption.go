package jwa

// Encryption identifies a JWE content encryption algorithm, the "enc" header
// parameter of RFC 7516 section 4.1.2. Its zero value is UnknownEncryption, so an
// Encryption a caller never set names no algorithm.
type Encryption int

const (
	// UnknownEncryption names no content encryption algorithm.
	UnknownEncryption Encryption = iota
	// A128CBCHS256 is AES_128_CBC_HMAC_SHA_256, RFC 7518 section 5.2.3.
	A128CBCHS256
	// A192CBCHS384 is AES_192_CBC_HMAC_SHA_384, RFC 7518 section 5.2.4.
	A192CBCHS384
	// A256CBCHS512 is AES_256_CBC_HMAC_SHA_512, RFC 7518 section 5.2.5.
	A256CBCHS512
	// A128GCM is AES GCM with a 128-bit key, RFC 7518 section 5.3.
	A128GCM
	// A192GCM is AES GCM with a 192-bit key, RFC 7518 section 5.3.
	A192GCM
	// A256GCM is AES GCM with a 256-bit key, RFC 7518 section 5.3.
	A256GCM
)

func (e Encryption) String() string {
	switch e {
	case A128CBCHS256:
		return "A128CBC-HS256"
	case A192CBCHS384:
		return "A192CBC-HS384"
	case A256CBCHS512:
		return "A256CBC-HS512"
	case A128GCM:
		return "A128GCM"
	case A192GCM:
		return "A192GCM"
	case A256GCM:
		return "A256GCM"
	case UnknownEncryption:
		return ""
	default:
		return ""
	}
}

// GetEncryption returns the content encryption algorithm an "enc" value names,
// compared case-sensitively as RFC 7516 section 4.1.2 requires, and
// UnknownEncryption for any other value.
func GetEncryption(enc string) Encryption {
	switch enc {
	case "A128CBC-HS256":
		return A128CBCHS256
	case "A192CBC-HS384":
		return A192CBCHS384
	case "A256CBC-HS512":
		return A256CBCHS512
	case "A128GCM":
		return A128GCM
	case "A192GCM":
		return A192GCM
	case "A256GCM":
		return A256GCM
	default:
		return UnknownEncryption
	}
}
