package jwa

type Algorithm int

// todo: finish this list
const (
	ES256 Algorithm = iota
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
	EdDSA //todo: this needs validator & signer implementations
	Unknown
)

func (a Algorithm) String() string {
	switch a {
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
	default:
		return Unknown
	}
}

//todo: I think we need to refactor algorithms to be more than labels. They need to have uses, logic baked into them, etc
//todo: I don't think they should satisfy signed interfaces though - just provide the logic for handling that specific.
//todo: So maybe pass a signer into the RS256.sign() method or some such
//todo: this also means we can simplify the handling of different key management types depending on the interface each alg implements
