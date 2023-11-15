package jose

import (
	"crypto"
	"fmt"
	e "github.com/MichaelFraser99/go-jose/error"
	"github.com/MichaelFraser99/go-jose/internal/algorithms/es256"
	"github.com/MichaelFraser99/go-jose/model"
)

type Validator interface {
	ValidateSignature(digest, signature []byte) (bool, error)
}

func GetValidator(alg model.Algorithm, publicKey crypto.PublicKey) (Validator, error) {
	var v Validator
	var err error
	switch alg {
	case model.ES256:
		v, err = es256.NewValidator(publicKey)
	default:
		return nil, &e.UnsupportedAlgorithm{Message: fmt.Sprintf("unsupported algorithm: '%s'", alg.String())}
	}
	return v, err
}
