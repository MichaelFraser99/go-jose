package model

type Algorithm int

const (
	ES256 Algorithm = iota
	ES384
	ES512
)

func (a Algorithm) String() string {
	switch a {
	case ES256:
		return "ES256"
	case ES384:
		return "ES384"
	case ES512:
		return "ES512"
	default:
		return ""
	}
}
