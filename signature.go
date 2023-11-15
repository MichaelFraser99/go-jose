package jose

import (
	"crypto"
	"fmt"
	e "github.com/MichaelFraser99/go-jose/error"
	"github.com/MichaelFraser99/go-jose/internal/algorithms/es256"
	"github.com/MichaelFraser99/go-jose/internal/algorithms/es384"
	"github.com/MichaelFraser99/go-jose/internal/algorithms/es512"
	"github.com/MichaelFraser99/go-jose/model"
	"io"
)

type Signer interface {
	Alg() model.Algorithm
	Public() crypto.PublicKey
	Sign(rand io.Reader, digest []byte, opts crypto.SignerOpts) (signature []byte, err error)
}

func GetSigner(alg model.Algorithm) (Signer, error) {
	var s Signer
	var err error
	switch alg {
	case model.ES256:
		s, err = es256.NewSigner()
	case model.ES384:
		s, err = es384.NewSigner()
	case model.ES512:
		s, err = es512.NewSigner()

	default:
		return nil, &e.UnsupportedAlgorithm{Message: fmt.Sprintf("unsupported algorithm: '%s'", alg)}
	}

	return s, err
}
