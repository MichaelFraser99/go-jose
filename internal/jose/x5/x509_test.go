package x5

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"errors"
	"fmt"
	"github.com/MichaelFraser99/go-jose/joseerror"
	"math/big"
	"testing"
	"time"
)

func Test_validateCertificateChain(t *testing.T) {
	certs, err := generateCertificateChain(t, 5)
	if err != nil {
		t.Fatalf("failed to generate certificate chain: %v", err)
	}

	var encodedCerts []string
	for _, cert := range certs {
		encodedCerts = append(encodedCerts, base64.StdEncoding.EncodeToString(cert))
	}

	tests := map[string]struct {
		certificates []string
		errMsg       string
		errTypes     []error
	}{
		"happy path - single certificate - root": {
			certificates: []string{encodedCerts[0]},
		},
		"happy path - single certificate - intermediate": {
			certificates: []string{encodedCerts[1]},
		},
		"happy path - single certificate - leaf": {
			certificates: []string{encodedCerts[4]},
		},
		"happy path - two certificates - root and intermediate": {
			certificates: []string{encodedCerts[1], encodedCerts[0]},
		},
		"happy path - two certificates - intermediate and leaf": {
			certificates: []string{encodedCerts[4], encodedCerts[3]},
		},
		"happy path - full chain": {
			certificates: []string{encodedCerts[4], encodedCerts[3], encodedCerts[2], encodedCerts[1], encodedCerts[0]},
		},
		"malformed entry": {
			certificates: []string{encodedCerts[3], "foo-bar", encodedCerts[1], encodedCerts[0]},
			errMsg:       "one or more entries in the chain is not a valid base64 string: illegal base64 data at input byte 3",
			errTypes:     []error{joseerror.MalformedClaim},
		},
		"empty slice": {
			certificates: []string{},
		},
		"nil slice": {
			certificates: nil,
		},
		"broken chain": {
			certificates: []string{encodedCerts[3], encodedCerts[0]},
			errMsg:       "one or more of the provided values is not a valid certificate chain: x509: certificate signed by unknown authority",
			errTypes:     []error{joseerror.MalformedClaim},
		},
	}

	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			err := ValidateCertificateChain(map[string]any{}, test.certificates)
			validateTestError(t, err, test.errMsg, test.errTypes)
		})
	}
}

func validateTestError(t *testing.T, producedError error, expectedMsg string, expectedTypes []error) {
	if producedError != nil {
		if expectedMsg == "" {
			t.Fatalf("unexpected error: %v", producedError)
		}
		if expectedMsg != producedError.Error() {
			t.Fatalf("expected error text %s, got %s", expectedMsg, producedError.Error())
		}
		for _, errType := range expectedTypes {
			if !errors.Is(producedError, errType) {
				t.Fatalf("thrown error does not have all types expected")
			}
		}
	} else {
		if expectedMsg != "" {
			t.Fatalf("expected error %s, got nil", expectedMsg)
		}
	}
}

func generateCertificateChain(t *testing.T, numCerts int) ([][]byte, error) {
	t.Helper()
	rootKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("failed to generate root key: %v", err)
	}

	rootDistinguishedName := pkix.Name{
		Country:            []string{"GB"},
		Organization:       []string{"My Organization"},
		OrganizationalUnit: []string{"My Organizational Unit"},
		Locality:           []string{"My Locality"},
		Province:           []string{"My Province"},
		StreetAddress:      []string{"My Street Address"},
		PostalCode:         []string{"My Postal Code"},
		SerialNumber:       "My Serial Number",
		CommonName:         "My Common Name",
		Names:              nil,
		ExtraNames:         nil,
	}

	rootTemplate := x509.Certificate{
		SerialNumber:          big.NewInt(2019),
		Subject:               rootDistinguishedName,
		NotBefore:             time.Now(),
		NotAfter:              time.Now().AddDate(10, 0, 0),
		IsCA:                  true,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
	}

	rootBytes, err := x509.CreateCertificate(rand.Reader, &rootTemplate, &rootTemplate, rootKey.Public(), rootKey)
	if err != nil {
		t.Fatalf("failed to create root certificate: %v", err)
	}

	parentKey := rootKey
	parent := rootTemplate
	var intermediates [][]byte
	for i := 1; i < numCerts; i++ {
		certKey, err := rsa.GenerateKey(rand.Reader, 2048)
		if err != nil {
			t.Fatalf("failed to generate intermediate %d key: %v", i, err)
		}

		certDistinguishedName := pkix.Name{
			Country:            []string{"GB"},
			Organization:       []string{fmt.Sprintf("My Organization %d", i)},
			OrganizationalUnit: []string{fmt.Sprintf("My Organizational Unit Intermediate %d", i)},
			Locality:           []string{fmt.Sprintf("My Locality %d", i)},
			Province:           []string{fmt.Sprintf("My Province %d", i)},
			StreetAddress:      []string{fmt.Sprintf("My Street Address %d", i)},
			PostalCode:         []string{fmt.Sprintf("My Postal Code %d", i)},
			SerialNumber:       fmt.Sprintf("My Serial Number %d", i),
			CommonName:         fmt.Sprintf("My Common Name %d", i),
			Names:              nil,
			ExtraNames:         nil,
		}

		certTemplate := x509.Certificate{
			SerialNumber:          big.NewInt(int64(2019 + i)),
			Subject:               certDistinguishedName,
			NotBefore:             time.Now(),
			NotAfter:              time.Now().AddDate(1, 0, 0),
			IsCA:                  i != numCerts-1,
			ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},
			KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
			BasicConstraintsValid: true,
		}

		certBytes, err := x509.CreateCertificate(rand.Reader, &certTemplate, &parent, certKey.Public(), parentKey)
		if err != nil {
			t.Fatalf("failed to create intermediate %d certificate: %v", i, err)
		}
		intermediates = append(intermediates, certBytes)
		parent = certTemplate
		parentKey = certKey
	}

	return append([][]byte{rootBytes}, intermediates...), nil
}
