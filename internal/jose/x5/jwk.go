package x5

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/x509"
	"fmt"
	"github.com/MichaelFraser99/go-jose/internal/algorithms/common"
	"github.com/MichaelFraser99/go-jose/joseerror"
)

func CertificateToJwk(certificate x509.Certificate) (map[string]any, error) {
	var jwk map[string]any

	switch certificate.PublicKeyAlgorithm {
	case x509.RSA:
		jwk = common.JwkFromRSAPublicKey(certificate.PublicKey.(*rsa.PublicKey))
	case x509.ECDSA:
		jwk = common.JwkFromECDSAPublicKey(certificate.PublicKey.(*ecdsa.PublicKey))
	case x509.Ed25519:
		jwk = common.JwkFromEdDSAPublicKey(certificate.PublicKey.(*ed25519.PublicKey))
	case x509.DSA:
		return nil, fmt.Errorf("%wcertificates signed with the DSA algorithm are not supported", joseerror.ErrApplicationError)
	default:
		return nil, fmt.Errorf("%wunknown / unsupported certificate public key algorithm: %s", joseerror.ErrUnsupportedAlgorithm, certificate.PublicKeyAlgorithm)
	}

	alg, err := CertificateSigningAlgorithmToJoseIdentifier(certificate.SignatureAlgorithm)
	if err != nil {
		return nil, err
	}

	jwk["alg"] = alg
	return jwk, nil
}

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
