package x5

import (
	"crypto"
	"crypto/x509"
	"encoding/asn1"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"github.com/MichaelFraser99/go-jose/internal/httputils"
	"github.com/MichaelFraser99/go-jose/internal/jose/jsonutils"
	"github.com/MichaelFraser99/go-jose/joseerror"
	"github.com/MichaelFraser99/go-jose/model"
	"strings"
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
		if strings.ContainsAny(entry, "\r\n") {
			return nil, fmt.Errorf("%wentry %d of the chain holds a line break, which is outside the base64 alphabet", joseerror.ErrMalformedClaim, i)
		}
		der, err := base64.StdEncoding.Strict().DecodeString(entry)
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

var (
	oidExtensionKeyUsage         = asn1.ObjectIdentifier{2, 5, 29, 15}
	oidExtensionExtendedKeyUsage = asn1.ObjectIdentifier{2, 5, 29, 37}
)

func hasExtension(certificate *x509.Certificate, oid asn1.ObjectIdentifier) bool {
	for _, extension := range certificate.Extensions {
		if extension.Id.Equal(oid) {
			return true
		}
	}
	return false
}

func namesAnyExtendedKeyUsage(certificate *x509.Certificate) bool {
	for _, usage := range certificate.ExtKeyUsage {
		if usage == x509.ExtKeyUsageAny {
			return true
		}
	}
	return false
}

func validateCertificateChain(certificates []*x509.Certificate, roots *x509.CertPool, extKeyUsages []x509.ExtKeyUsage) error {
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

	keyUsages := extKeyUsages
	if len(keyUsages) == 0 {
		keyUsages = []x509.ExtKeyUsage{x509.ExtKeyUsageAny}
	}
	signingCertificate := certificates[0]
	_, err := signingCertificate.Verify(x509.VerifyOptions{
		Roots:         roots,
		Intermediates: intermediateCertPool,
		KeyUsages:     keyUsages,
	})
	if err != nil {
		return fmt.Errorf("%wthe certificate chain does not validate against the configured trust anchors: %s", joseerror.ErrNoKeyIdentifierMatch, err.Error())
	}
	extendedKeyUsagePresent := hasExtension(signingCertificate, oidExtensionExtendedKeyUsage)
	if extendedKeyUsagePresent && len(signingCertificate.ExtKeyUsage) == 0 && len(signingCertificate.UnknownExtKeyUsage) == 0 {
		return fmt.Errorf("%wthe signing certificate's extended key usage extension names no purpose", joseerror.ErrNoKeyIdentifierMatch)
	}
	if len(extKeyUsages) == 0 && extendedKeyUsagePresent && !namesAnyExtendedKeyUsage(signingCertificate) {
		return fmt.Errorf("%wthe signing certificate's extended key usage names no purpose the caller accepts", joseerror.ErrNoKeyIdentifierMatch)
	}
	if hasExtension(signingCertificate, oidExtensionKeyUsage) && signingCertificate.KeyUsage&(x509.KeyUsageDigitalSignature|x509.KeyUsageContentCommitment) == 0 {
		return fmt.Errorf("%wthe signing certificate's key usage asserts neither digitalSignature nor nonRepudiation", joseerror.ErrNoKeyIdentifierMatch)
	}
	return nil
}

func keyFromValidatedChain(certificates []*x509.Certificate, x5t, x5ts256 *string, roots *x509.CertPool, extKeyUsages []x509.ExtKeyUsage) ([]crypto.PublicKey, error) {
	if err := validateCertificateChain(certificates, roots, extKeyUsages); err != nil {
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

// InlineCertificate yields the key of the first certificate of an x5c chain once the
// chain validates against roots and that certificate may verify a signature, under
// RFC 7515 section 4.1.6 and RFC 5280 sections 4.2.1.3 and 4.2.1.12.
func InlineCertificate(certificateChain []string, x5t, x5ts256 *string, roots *x509.CertPool, extKeyUsages []x509.ExtKeyUsage) model.Retriever {
	return func() ([]crypto.PublicKey, error) {
		if len(certificateChain) == 0 {
			return nil, fmt.Errorf("%wthe certificate chain carries no certificate", joseerror.ErrMalformedClaim)
		}

		certificates, err := parseCertificateChain(certificateChain)
		if err != nil {
			return nil, err
		}
		return keyFromValidatedChain(certificates, x5t, x5ts256, roots, extKeyUsages)
	}
}

// RetrieveX5U fetches an x5u chain and holds it to the same checks as InlineCertificate.
func RetrieveX5U(x5u string, fetch httputils.Fetch, x5t, x5ts256 *string, roots *x509.CertPool, extKeyUsages []x509.ExtKeyUsage) model.Retriever {
	return func() ([]crypto.PublicKey, error) {
		response, err := fetch(x5u, "x5u")
		if err != nil {
			return nil, err
		}

		responseBytes, err := httputils.ReadBody(response, "x5u")
		if err != nil {
			return nil, err
		}

		certificates, err := certificatesFromX5uBody(responseBytes)
		if err != nil {
			return nil, fmt.Errorf("%wunable to parse retrieved x5u response as a certificate chain: %w", joseerror.ErrApplicationError, err)
		}
		return keyFromValidatedChain(certificates, x5t, x5ts256, roots, extKeyUsages)
	}
}
