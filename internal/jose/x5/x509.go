package x5

import (
	"crypto"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"github.com/MichaelFraser99/go-jose/internal/httputils"
	"github.com/MichaelFraser99/go-jose/internal/jose/jsonutils"
	"github.com/MichaelFraser99/go-jose/joseerror"
	"github.com/MichaelFraser99/go-jose/model"
	"io"
	"net/http"
	"unicode/utf8"
)

var (
	ValidateCertificateChain = jsonutils.Validator[[]string](func(jsonInput map[string]any, certificateChain []string) error {
		if len(certificateChain) == 0 {
			return fmt.Errorf("%wthe 'x5c' array carries no certificate", joseerror.ErrMalformedClaim)
		}

		certificates, err := parseCertificateChain(certificateChain)
		if err != nil {
			return err
		}
		if len(certificates) == 0 {
			return fmt.Errorf("%wthe provided values carry no certificate", joseerror.ErrMalformedClaim)
		}
		return nil
	})
)

// CertificateChainStrings reads an x5c claim as the base64-encoded DER strings RFC
// 7515 section 4.1.6 defines, refusing an entry that is not a string.
//
// Both shapes a caller can hold are accepted. A header decoded from JSON yields
// []any for an array, while one built in Go commonly holds []string, and which of
// the two arrives is not something this library should care about.
func CertificateChainStrings(value any) ([]string, error) {
	switch values := value.(type) {
	case []string:
		return values, nil
	case []any:
		chain := make([]string, 0, len(values))
		for i, entry := range values {
			text, ok := entry.(string)
			if !ok {
				return nil, fmt.Errorf("%wentry %d of the 'x5c' array is not a string", joseerror.ErrMalformedClaim, i)
			}
			chain = append(chain, text)
		}
		return chain, nil
	default:
		return nil, fmt.Errorf("%wthe 'x5c' claim must be an array of base64-encoded certificates", joseerror.ErrMalformedClaim)
	}
}

func parseCertificateChain(certificateChain []string) ([]*x509.Certificate, error) {
	certificates := make([]*x509.Certificate, 0, len(certificateChain))
	for i, entry := range certificateChain {
		der, err := base64.StdEncoding.DecodeString(entry)
		if err != nil {
			return nil, fmt.Errorf("%wone or more entries in the chain is not a valid base64 string: %s", joseerror.ErrMalformedClaim, err.Error())
		}
		certificate, err := x509.ParseCertificate(der)
		if err != nil {
			return nil, fmt.Errorf("%wentry %d of the chain is not exactly one certificate: %s", joseerror.ErrMalformedClaim, i, err.Error())
		}
		certificates = append(certificates, certificate)
	}
	return certificates, nil
}

// certificatesFromX5uBody reads an x5u resource, which RFC 7515 section 4.1.5
// requires to be PEM. A body that parses as DER certificates is read as DER.
// Any other body must be UTF-8 text, as RFC 7468 PEM is, and its CERTIFICATE
// blocks are read in order.
func certificatesFromX5uBody(body []byte) ([]*x509.Certificate, error) {
	if certificates, err := x509.ParseCertificates(body); err == nil {
		return certificates, nil
	}
	if !utf8.Valid(body) {
		return nil, fmt.Errorf("%wthe retrieved resource is neither DER certificates nor PEM text", joseerror.ErrMalformedClaim)
	}

	var der []byte
	rest := body
	for {
		var block *pem.Block
		block, rest = pem.Decode(rest)
		if block == nil {
			break
		}
		if block.Type == "CERTIFICATE" {
			der = append(der, block.Bytes...)
		}
	}

	if len(der) == 0 {
		return nil, fmt.Errorf("%wthe retrieved resource carries no PEM certificate block", joseerror.ErrMalformedClaim)
	}
	return x509.ParseCertificates(der)
}

func validateCertificateChain(certificates []*x509.Certificate, roots *x509.CertPool) error {
	if roots == nil {
		return fmt.Errorf("%wno x509 trust anchors are configured, so a certificate chain cannot be validated", joseerror.ErrKeystoreError)
	}
	if len(certificates) == 0 {
		return fmt.Errorf("%wthe provided values carry no certificate", joseerror.ErrMalformedClaim)
	}

	intermediateCertPool := x509.NewCertPool()
	for _, intermediate := range certificates[1:] {
		intermediateCertPool.AddCert(intermediate)
	}

	_, err := certificates[0].Verify(x509.VerifyOptions{
		Roots:         roots,
		Intermediates: intermediateCertPool,
		KeyUsages:     []x509.ExtKeyUsage{x509.ExtKeyUsageAny},
	})
	if err != nil {
		return fmt.Errorf("%wthe certificate chain does not validate against the configured trust anchors: %s", joseerror.ErrNoKeyIdentifierMatch, err.Error())
	}
	return nil
}

func keyFromValidatedChain(certificates []*x509.Certificate, x5t, x5ts256 *string, roots *x509.CertPool) ([]crypto.PublicKey, error) {
	if err := validateCertificateChain(certificates, roots); err != nil {
		return nil, err
	}

	signingCertificate := certificates[0]
	if x5t != nil && CalculateX5t(signingCertificate.Raw) != *x5t {
		return nil, fmt.Errorf("%wcalculated x5t does not match value from jose header", joseerror.ErrNoKeyIdentifierMatch)
	}
	if x5ts256 != nil && CalculateX5tS256(signingCertificate.Raw) != *x5ts256 {
		return nil, fmt.Errorf("%wcalculated x5ts256 does not match value from jose header", joseerror.ErrNoKeyIdentifierMatch)
	}

	return []crypto.PublicKey{signingCertificate.PublicKey}, nil
}

func InlineCertificate(certificateChain []string, x5t, x5ts256 *string, roots *x509.CertPool) model.Retriever {
	return func() ([]crypto.PublicKey, error) {
		if len(certificateChain) == 0 {
			return nil, fmt.Errorf("%wthe certificate chain carries no certificate", joseerror.ErrMalformedClaim)
		}

		certificates, err := parseCertificateChain(certificateChain)
		if err != nil {
			return nil, err
		}
		return keyFromValidatedChain(certificates, x5t, x5ts256, roots)
	}
}

func RetrieveX5U(x5u string, client *http.Client, x5t, x5ts256 *string, roots *x509.CertPool) model.Retriever {
	return func() ([]crypto.PublicKey, error) {
		response, err := httputils.RetrieveResource(client, x5u, "x5u")
		if err != nil {
			return nil, err
		}

		if response.Body == nil {
			return nil, fmt.Errorf("%wfailed to retrieve x5u: response body is nil", joseerror.ErrApplicationError)
		}

		responseBytes, err := io.ReadAll(response.Body)
		if err != nil {
			return nil, fmt.Errorf("%wfailed to read x5u response: %w", joseerror.ErrApplicationError, err)
		}

		err = response.Body.Close()
		if err != nil {
			return nil, fmt.Errorf("%wfailed to close x5u response: %w", joseerror.ErrApplicationError, err)
		}
		if int64(len(responseBytes)) > httputils.MaxBodyBytes {
			return nil, fmt.Errorf("%wx5u response exceeded the %d byte limit", joseerror.ErrApplicationError, httputils.MaxBodyBytes)
		}

		certificates, err := certificatesFromX5uBody(responseBytes)
		if err != nil {
			return nil, fmt.Errorf("%wunable to parse retrieved x5u response as a certificate chain: %w", joseerror.ErrApplicationError, err)
		}
		return keyFromValidatedChain(certificates, x5t, x5ts256, roots)
	}
}
