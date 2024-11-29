package x5

import (
	"crypto"
	"crypto/x509"
	"encoding/base64"
	"fmt"
	"github.com/MichaelFraser99/go-jose/internal/httputils"
	"github.com/MichaelFraser99/go-jose/internal/jose/jsonutils"
	"github.com/MichaelFraser99/go-jose/joseerror"
	"github.com/MichaelFraser99/go-jose/model"
	"io"
	"net/http"
	"strings"
)

var (
	ValidateCertificateChain = jsonutils.Validator[[]string](func(jsonInput map[string]any, certificateChain []string) error {
		if len(certificateChain) == 0 {
			return nil
		}

		var decodedCertificateStrings []string
		for _, entry := range certificateChain {
			decodedCertificate, err := base64.StdEncoding.DecodeString(entry) // certificates are base64 encoded DER - not base64url
			if err != nil {
				return fmt.Errorf("%wone or more entries in the chain is not a valid base64 string: %s", joseerror.MalformedClaim, err.Error())
			}
			decodedCertificateStrings = append(decodedCertificateStrings, string(decodedCertificate))
		}

		_, err := validateCertificateChain([]byte(strings.Join(decodedCertificateStrings, "")))
		return err
	})
)

func validateCertificateChain(certificateChain []byte) ([]*x509.Certificate, error) {
	certificates, err := x509.ParseCertificates(certificateChain)
	if err != nil {
		return nil, fmt.Errorf("%wone or more of the provided values is not a valid certificate: %s", joseerror.MalformedClaim, err.Error())
	}

	rootCertPool := x509.NewCertPool()
	intermediateCertPool := x509.NewCertPool()

	rootCertPool.AddCert(certificates[len(certificates)-1]) // treat last certificate in chain as root - if there is only one it'll validate as self-signed

	if len(certificates) > 2 { // treat any other certificates as intermediates
		for _, subsequentCertificate := range certificates[1:] {
			intermediateCertPool.AddCert(subsequentCertificate)
		}
	}

	_, err = certificates[0].Verify(x509.VerifyOptions{Roots: rootCertPool, Intermediates: intermediateCertPool})
	if err != nil {
		return nil, fmt.Errorf("%wone or more of the provided values is not a valid certificate chain: %s", joseerror.MalformedClaim, err.Error())
	}

	return certificates, nil
}

func InlineCertificate(certificateChain []string, x5t, x5ts256 *string, alg string) model.Retriever {
	return func() ([]crypto.PublicKey, error) {
		signingCertificate := certificateChain[0] //chain has already been validated
		decodedCertificate, err := base64.StdEncoding.DecodeString(signingCertificate)
		if err != nil {
			return nil, fmt.Errorf("%wfailed to decode certificate base64: %w", joseerror.ApplicationError, err)
		}

		parsedCertificate, err := x509.ParseCertificate(decodedCertificate)
		if err != nil {
			return nil, fmt.Errorf("%wfailed to parse decoded base64 as certificate: %w", joseerror.ApplicationError, err)
		}

		if x5t != nil {
			calculatedX5t := CalculateX5t(parsedCertificate.Raw)
			if calculatedX5t != *x5t {
				return nil, fmt.Errorf("%wcalculated x5t does not match value from jose header", joseerror.NoKeyIdentifierMatch)
			}
		}

		if x5ts256 != nil {
			calculatedX5tS256 := CalculateX5tS256(parsedCertificate.Raw)
			if calculatedX5tS256 != *x5ts256 {
				return nil, fmt.Errorf("%wcalculated x5ts256 does not match value from jose header", joseerror.NoKeyIdentifierMatch)
			}
		}

		certificateAlgorithm, err := CertificateSigningAlgorithmToJoseIdentifier(parsedCertificate.SignatureAlgorithm)
		if err != nil {
			return nil, err
		}

		if certificateAlgorithm != alg {
			return nil, fmt.Errorf("%wcertificate signing algorithm does not match jwk algorithm", joseerror.NoKeyIdentifierMatch)
		}

		return []crypto.PublicKey{parsedCertificate.PublicKey}, nil
	}
}

func RetrieveX5U(x5u string, client *http.Client, x5t, x5ts256 *string, alg string) model.Retriever {
	return func() ([]crypto.PublicKey, error) {
		response, err := httputils.RetrieveResource(client, x5u, "x5u")
		if err != nil {
			return nil, err
		}

		if response.Body == nil {
			return nil, fmt.Errorf("%wfailed to retrieve x5u: response body is nil", joseerror.ApplicationError)
		}

		responseBytes, err := io.ReadAll(response.Body)
		if err != nil {
			return nil, fmt.Errorf("%wfailed to read x5u response: %w", joseerror.ApplicationError, err)
		}

		err = response.Body.Close()
		if err != nil {
			return nil, fmt.Errorf("%wfailed to close x5u response: %w", joseerror.ApplicationError, err)
		}

		certificates, err := validateCertificateChain(responseBytes)
		if err != nil {
			return nil, fmt.Errorf("%wunable to parse retrieved x5u response as a certificate chain: %w", joseerror.ApplicationError, err)
		}

		if len(certificates) == 0 {
			return nil, nil //no certificates referenced, lets just ignore
		}

		parsedCertificate := certificates[0]

		if x5t != nil {
			calculatedX5t := CalculateX5t(parsedCertificate.Raw)
			if calculatedX5t != *x5t {
				return nil, fmt.Errorf("%wcalculated x5t does not match value from jose header", joseerror.NoKeyIdentifierMatch)
			}
		}

		if x5ts256 != nil {
			calculatedX5tS256 := CalculateX5tS256(parsedCertificate.Raw)
			if calculatedX5tS256 != *x5ts256 {
				return nil, fmt.Errorf("%wcalculated x5ts256 does not match value from jose header", joseerror.NoKeyIdentifierMatch)
			}
		}

		certificateAlgorithm, err := CertificateSigningAlgorithmToJoseIdentifier(parsedCertificate.SignatureAlgorithm)
		if err != nil {
			return nil, err
		}

		if certificateAlgorithm != alg {
			return nil, fmt.Errorf("%wcertificate signing algorithm does not match jwk algorithm", joseerror.NoKeyIdentifierMatch)
		}

		return []crypto.PublicKey{parsedCertificate.PublicKey}, nil
	}
}
