package jws_test

import (
	"context"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/MichaelFraser99/go-jose/jwa"
	"github.com/MichaelFraser99/go-jose/jws"
	"github.com/MichaelFraser99/go-jose/model"
)

func TestVerifyCompactSerialization_AnX5cOrX5uCertificateMustBeUsableForSigning(t *testing.T) {
	ca := rootCA(t, p256Key(t))
	certified := func(usage x509.KeyUsage, extUsage ...x509.ExtKeyUsage) *issuedCertificate {
		return issue(t, &x509.Certificate{Subject: pkix.Name{CommonName: "leaf"}, KeyUsage: usage, ExtKeyUsage: extUsage}, p256Key(t), ca)
	}
	keyCertSignOnly := issue(t, &x509.Certificate{
		Subject:               pkix.Name{CommonName: "intermediate"},
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign,
	}, p256Key(t), ca)

	tests := map[string]struct {
		reference    string
		cert         *issuedCertificate
		extKeyUsages []x509.ExtKeyUsage
		verifies     bool
	}{
		"a leaf restricted to TLS server authentication": {
			reference: "RFC 5280 4.2.1.12", cert: certified(x509.KeyUsageDigitalSignature, x509.ExtKeyUsageServerAuth),
		},
		"a leaf restricted to code signing": {
			reference: "RFC 5280 4.2.1.12", cert: certified(x509.KeyUsageDigitalSignature, x509.ExtKeyUsageCodeSigning),
		},
		"a leaf restricted to code signing, which the caller accepts": {
			reference: "JoseOptions.X509ExtKeyUsages", cert: certified(x509.KeyUsageDigitalSignature, x509.ExtKeyUsageCodeSigning),
			extKeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageCodeSigning}, verifies: true,
		},
		"a leaf with no extended key usage": {
			reference: "RFC 5280 4.2.1.12", cert: certified(x509.KeyUsageDigitalSignature), verifies: true,
		},
		"a leaf whose key usage is keyAgreement only": {
			reference: "RFC 5280 4.2.1.3", cert: certified(x509.KeyUsageKeyAgreement),
		},
		"a CA certificate whose key usage is keyCertSign only": {
			reference: "RFC 5280 4.2.1.3", cert: keyCertSignOnly,
		},
	}

	for name, tc := range tests {
		pemBody := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: tc.cert.cert.Raw})
		server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			if _, err := w.Write(pemBody); err != nil {
				return
			}
		}))
		t.Cleanup(server.Close)

		headers := map[string]map[string]any{
			"x5c": {"x5c": []string{der64(tc.cert)}},
			"x5u": {"x5u": server.URL},
		}
		for source, header := range headers {
			t.Run(source+" "+name, func(t *testing.T) {
				token := signWithHeader(t, jwa.ES256, tc.cert.key, header)
				opts := &model.JoseOptions{X509Roots: roots(ca), HttpClient: server.Client(), X509ExtKeyUsages: tc.extKeyUsages}
				_, _, err := jws.VerifyCompactSerialization(context.Background(), token, nil, opts)
				if tc.verifies && err != nil {
					t.Errorf("[%s] %s may verify a JWS, got %v", tc.reference, name, err)
				}
				if !tc.verifies && err == nil {
					t.Errorf("[%s] %s must not be used to verify a JWS", tc.reference, name)
				}
			})
		}
	}
}
