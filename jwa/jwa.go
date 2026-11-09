package jwa

// Algorithm is an "alg" value: a JWS signature algorithm (RFC 7518 section 3,
// RFC 9864, RFC 9964) or a JWE key management algorithm (RFC 7518 section 4).
// A signer or validator refuses a key management algorithm, and an encrypter or
// decrypter refuses a signature algorithm.
type Algorithm int

// Unknown is the zero value, so an Algorithm a caller never set names no
// algorithm rather than aliasing a real one.
const (
	Unknown Algorithm = iota
	ES256
	ES384
	ES512
	RS256
	RS384
	RS512
	PS256
	PS384
	PS512
	HS256
	HS384
	HS512
	// EdDSA is accepted for verification only, and only with an Ed25519 key.
	// RFC 9864 section 4.1.2 deprecates it in favour of Ed25519, so this library
	// does not sign with it.
	EdDSA
	// Ed25519 is EdDSA with the Ed25519 parameters of RFC 8032 section 5.1, as
	// RFC 9864 section 4.1.1 registers it.
	Ed25519
	// MLDSA44 is ML-DSA with the ML-DSA-44 parameters of FIPS 204, as RFC 9964
	// section 5 registers it.
	MLDSA44
	// MLDSA65 is ML-DSA with the ML-DSA-65 parameters of FIPS 204, as RFC 9964
	// section 5 registers it.
	MLDSA65
	// MLDSA87 is ML-DSA with the ML-DSA-87 parameters of FIPS 204, as RFC 9964
	// section 5 registers it.
	MLDSA87
	// RSAOAEP is RSAES-OAEP with SHA-1 and MGF1 with SHA-1, as RFC 7518 section
	// 4.3 defines it.
	RSAOAEP
	// RSAOAEP256 is RSAES-OAEP with SHA-256 and MGF1 with SHA-256, as RFC 7518
	// section 4.3 defines it.
	RSAOAEP256
	// RSAOAEP384 is RSAES-OAEP with SHA-384 and MGF1 with SHA-384, as the IANA JOSE
	// registry records it for WebCrypto.
	RSAOAEP384
	// RSAOAEP512 is RSAES-OAEP with SHA-512 and MGF1 with SHA-512, as the IANA JOSE
	// registry records it for WebCrypto.
	RSAOAEP512
	// A128KW is AES Key Wrap with a 128-bit key, as RFC 7518 section 4.4 defines it.
	A128KW
	// A192KW is AES Key Wrap with a 192-bit key, as RFC 7518 section 4.4 defines it.
	A192KW
	// A256KW is AES Key Wrap with a 256-bit key, as RFC 7518 section 4.4 defines it.
	A256KW
	// Dir is direct use of a shared symmetric key as the CEK, as RFC 7518 section
	// 4.5 defines it.
	Dir
	// ECDHES is ECDH-ES key agreement used directly as the CEK, as RFC 7518
	// section 4.6 defines it.
	ECDHES
	// ECDHESA128KW is ECDH-ES key agreement whose result wraps the CEK with
	// A128KW, as RFC 7518 section 4.6 defines it.
	ECDHESA128KW
	// ECDHESA192KW is ECDH-ES key agreement whose result wraps the CEK with
	// A192KW, as RFC 7518 section 4.6 defines it.
	ECDHESA192KW
	// ECDHESA256KW is ECDH-ES key agreement whose result wraps the CEK with
	// A256KW, as RFC 7518 section 4.6 defines it.
	ECDHESA256KW
	// A128GCMKW is AES GCM key wrap with a 128-bit key, as RFC 7518 section 4.7
	// defines it.
	A128GCMKW
	// A192GCMKW is AES GCM key wrap with a 192-bit key, as RFC 7518 section 4.7
	// defines it.
	A192GCMKW
	// A256GCMKW is AES GCM key wrap with a 256-bit key, as RFC 7518 section 4.7
	// defines it.
	A256GCMKW
	// PBES2HS256A128KW is PBES2 with HMAC SHA-256 and A128KW wrapping, as RFC 7518
	// section 4.8 defines it.
	PBES2HS256A128KW
	// PBES2HS384A192KW is PBES2 with HMAC SHA-384 and A192KW wrapping, as RFC 7518
	// section 4.8 defines it.
	PBES2HS384A192KW
	// PBES2HS512A256KW is PBES2 with HMAC SHA-512 and A256KW wrapping, as RFC 7518
	// section 4.8 defines it.
	PBES2HS512A256KW
)

func (a Algorithm) String() string {
	switch a {
	case Unknown:
		return ""
	case ES256:
		return "ES256"
	case ES384:
		return "ES384"
	case ES512:
		return "ES512"
	case RS256:
		return "RS256"
	case RS384:
		return "RS384"
	case RS512:
		return "RS512"
	case PS256:
		return "PS256"
	case PS384:
		return "PS384"
	case PS512:
		return "PS512"
	case HS256:
		return "HS256"
	case HS384:
		return "HS384"
	case HS512:
		return "HS512"
	case EdDSA:
		return "EdDSA"
	case Ed25519:
		return "Ed25519"
	case MLDSA44:
		return "ML-DSA-44"
	case MLDSA65:
		return "ML-DSA-65"
	case MLDSA87:
		return "ML-DSA-87"
	case RSAOAEP:
		return "RSA-OAEP"
	case RSAOAEP256:
		return "RSA-OAEP-256"
	case RSAOAEP384:
		return "RSA-OAEP-384"
	case RSAOAEP512:
		return "RSA-OAEP-512"
	case A128KW:
		return "A128KW"
	case A192KW:
		return "A192KW"
	case A256KW:
		return "A256KW"
	case Dir:
		return "dir"
	case ECDHES:
		return "ECDH-ES"
	case ECDHESA128KW:
		return "ECDH-ES+A128KW"
	case ECDHESA192KW:
		return "ECDH-ES+A192KW"
	case ECDHESA256KW:
		return "ECDH-ES+A256KW"
	case A128GCMKW:
		return "A128GCMKW"
	case A192GCMKW:
		return "A192GCMKW"
	case A256GCMKW:
		return "A256GCMKW"
	case PBES2HS256A128KW:
		return "PBES2-HS256+A128KW"
	case PBES2HS384A192KW:
		return "PBES2-HS384+A192KW"
	case PBES2HS512A256KW:
		return "PBES2-HS512+A256KW"
	default:
		return ""
	}
}

// GetAlgorithm returns the Algorithm a registered "alg" name identifies, such as
// "ES256" or "RSA-OAEP-256", and Unknown for any other string. The comparison is
// case sensitive (RFC 7515 section 4.1.1, RFC 7516 section 4.1.1). A result
// other than Unknown may be a signature or a key management algorithm.
func GetAlgorithm(alg string) Algorithm {
	switch alg {
	case "ES256":
		return ES256
	case "ES384":
		return ES384
	case "ES512":
		return ES512
	case "RS256":
		return RS256
	case "RS384":
		return RS384
	case "RS512":
		return RS512
	case "PS256":
		return PS256
	case "PS384":
		return PS384
	case "PS512":
		return PS512
	case "HS256":
		return HS256
	case "HS384":
		return HS384
	case "HS512":
		return HS512
	case "EdDSA":
		return EdDSA
	case "Ed25519":
		return Ed25519
	case "ML-DSA-44":
		return MLDSA44
	case "ML-DSA-65":
		return MLDSA65
	case "ML-DSA-87":
		return MLDSA87
	case "RSA-OAEP":
		return RSAOAEP
	case "RSA-OAEP-256":
		return RSAOAEP256
	case "RSA-OAEP-384":
		return RSAOAEP384
	case "RSA-OAEP-512":
		return RSAOAEP512
	case "A128KW":
		return A128KW
	case "A192KW":
		return A192KW
	case "A256KW":
		return A256KW
	case "dir":
		return Dir
	case "ECDH-ES":
		return ECDHES
	case "ECDH-ES+A128KW":
		return ECDHESA128KW
	case "ECDH-ES+A192KW":
		return ECDHESA192KW
	case "ECDH-ES+A256KW":
		return ECDHESA256KW
	case "A128GCMKW":
		return A128GCMKW
	case "A192GCMKW":
		return A192GCMKW
	case "A256GCMKW":
		return A256GCMKW
	case "PBES2-HS256+A128KW":
		return PBES2HS256A128KW
	case "PBES2-HS384+A192KW":
		return PBES2HS384A192KW
	case "PBES2-HS512+A256KW":
		return PBES2HS512A256KW
	default:
		return Unknown
	}
}

//todo: I think we need to refactor algorithms to be more than labels. They need to have uses, logic baked into them, etc
//todo: I don't think they should satisfy signed interfaces though - just provide the logic for handling that specific.
//todo: So maybe pass a signer into the RS256.sign() method or some such
//todo: this also means we can simplify the handling of different key management types depending on the interface each alg implements
