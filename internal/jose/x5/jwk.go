package x5

import (
	"crypto/x509"
	"fmt"
	"github.com/MichaelFraser99/go-jose/joseerror"
)

func CertificateSigningAlgorithmToJoseIdentifier(x509Alg x509.SignatureAlgorithm) (string, error) {
	var alg string
	switch x509Alg {
	case x509.SHA256WithRSA:
		alg = "RS256"
	case x509.SHA384WithRSA:
		alg = "RS384"
	case x509.SHA512WithRSA:
		alg = "RS512"
	case x509.ECDSAWithSHA256:
		alg = "ES256"
	case x509.ECDSAWithSHA384:
		alg = "ES384"
	case x509.ECDSAWithSHA512:
		alg = "ES512"
	case x509.SHA256WithRSAPSS:
		alg = "PS256"
	case x509.SHA384WithRSAPSS:
		alg = "PS384"
	case x509.SHA512WithRSAPSS:
		alg = "PS512"
	case x509.PureEd25519:
		alg = "Ed25519"
	default:
		return "", fmt.Errorf("%wunknown certificate signing algorithm", joseerror.ErrUnsupportedAlgorithm)
	}
	return alg, nil
}
