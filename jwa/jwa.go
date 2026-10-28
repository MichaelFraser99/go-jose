package jwa

type Algorithm int

// Unknown is the zero value, so an Algorithm a caller never set names no
// algorithm rather than aliasing a real one.
//
// todo: finish this list
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
	default:
		return ""
	}
}

// GetAlgorithm takes in a string representation of an Algorithm ("ES256" or "HS384")
// If the provided string does not match a defined algorithm, Unknown is returned
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
	default:
		return Unknown
	}
}

//todo: I think we need to refactor algorithms to be more than labels. They need to have uses, logic baked into them, etc
//todo: I don't think they should satisfy signed interfaces though - just provide the logic for handling that specific.
//todo: So maybe pass a signer into the RS256.sign() method or some such
//todo: this also means we can simplify the handling of different key management types depending on the interface each alg implements
