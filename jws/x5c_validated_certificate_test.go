package jws_test

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"math/big"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/MichaelFraser99/go-jose/jwa"
	"github.com/MichaelFraser99/go-jose/jws"
	"github.com/MichaelFraser99/go-jose/model"
)

type issuedCertificate struct {
	cert *x509.Certificate
	key  crypto.Signer
}

func issue(t *testing.T, tmpl *x509.Certificate, key crypto.Signer, parent *issuedCertificate) *issuedCertificate {
	t.Helper()
	tmpl.SerialNumber = big.NewInt(time.Now().UnixNano())
	tmpl.NotBefore = time.Now().Add(-time.Hour)
	tmpl.NotAfter = time.Now().Add(time.Hour)
	parentCert, parentKey := tmpl, key
	if parent != nil {
		parentCert, parentKey = parent.cert, parent.key
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, parentCert, key.Public(), parentKey)
	if err != nil {
		t.Fatalf("failed to create a certificate: %v", err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("failed to parse a certificate: %v", err)
	}
	return &issuedCertificate{cert: cert, key: key}
}

func rootCA(t *testing.T, key crypto.Signer) *issuedCertificate {
	return issue(t, &x509.Certificate{
		Subject:               pkix.Name{CommonName: "root"},
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
	}, key, nil)
}

func leaf(t *testing.T, key crypto.Signer, ca *issuedCertificate) *issuedCertificate {
	return issue(t, &x509.Certificate{Subject: pkix.Name{CommonName: "leaf"}, KeyUsage: x509.KeyUsageDigitalSignature}, key, ca)
}

func p256Key(t *testing.T) *ecdsa.PrivateKey {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return key
}

func signWithX5c(t *testing.T, alg jwa.Algorithm, key crypto.PrivateKey, x5c []string) string {
	t.Helper()
	return signWithHeader(t, alg, key, map[string]any{"x5c": x5c})
}

func signWithHeader(t *testing.T, alg jwa.Algorithm, key crypto.PrivateKey, header map[string]any) string {
	t.Helper()
	header["alg"] = alg.String()
	head, err := json.Marshal(header)
	if err != nil {
		t.Fatal(err)
	}
	input := base64.RawURLEncoding.EncodeToString(head) + "." + base64.RawURLEncoding.EncodeToString([]byte(`{"sub":"test"}`))
	signer, err := jws.GetSignerFromPrivateKey(alg, key)
	if err != nil {
		t.Fatalf("failed to build a signer: %v", err)
	}
	signature, err := signer.Sign(rand.Reader, []byte(input), nil)
	if err != nil {
		t.Fatalf("failed to sign: %v", err)
	}
	return input + "." + base64.RawURLEncoding.EncodeToString(signature)
}

func roots(certs ...*issuedCertificate) *x509.CertPool {
	pool := x509.NewCertPool()
	for _, c := range certs {
		pool.AddCert(c.cert)
	}
	return pool
}

func der64(c *issuedCertificate) string {
	return base64.StdEncoding.EncodeToString(c.cert.Raw)
}

func TestVerifyCompactSerialization_AnX5cCertificateCannotBorrowTrustFromAPemCertificateItEmbeds(t *testing.T) {
	ca := rootCA(t, p256Key(t))
	trusted := leaf(t, p256Key(t), ca)
	embedded := "\n" + string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: trusted.cert.Raw}))

	attackerKey := p256Key(t)
	forged := issue(t, &x509.Certificate{
		Subject: pkix.Name{CommonName: "attacker"},
		ExtraExtensions: []pkix.Extension{{
			Id:    asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 99999, 1},
			Value: []byte(embedded),
		}},
	}, attackerKey, nil)

	token := signWithX5c(t, jwa.ES256, attackerKey, []string{der64(forged)})
	if _, _, err := jws.VerifyCompactSerialization(token, nil, &model.JoseOptions{X509Roots: roots(ca)}); err == nil {
		t.Error("[RFC 7515 4.1.6] the recipient MUST validate the chain whose first certificate holds the signing key, so a self-signed certificate that only embeds a trusted one as PEM text must not verify")
	}
}

func TestVerifyCompactSerialization_AnX5cEntryIsExactlyOneCertificate(t *testing.T) {
	ca := rootCA(t, p256Key(t))
	signingKey := p256Key(t)
	signingLeaf := leaf(t, signingKey, ca)

	twoInOne := base64.StdEncoding.EncodeToString(append(append([]byte{}, signingLeaf.cert.Raw...), ca.cert.Raw...))
	token := signWithX5c(t, jwa.ES256, signingKey, []string{twoInOne})
	if _, _, err := jws.VerifyCompactSerialization(token, nil, &model.JoseOptions{X509Roots: roots(ca)}); err == nil {
		t.Error("[RFC 7515 4.1.6] each string in the x5c array is one base64-encoded DER certificate, so an entry holding two must be refused")
	}
}

func TestVerifyCompactSerialization_AnX5cLeafIsUsableWhateverAlgorithmItsIssuerSignedWith(t *testing.T) {
	rsaRootKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	tests := map[string]struct {
		ca  *issuedCertificate
		alg jwa.Algorithm
	}{
		"an ES256 leaf under an RSA root": {ca: rootCA(t, rsaRootKey), alg: jwa.ES256},
		"an ES256 leaf under an EC root":  {ca: rootCA(t, p256Key(t)), alg: jwa.ES256},
	}

	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			signingKey := p256Key(t)
			signingLeaf := leaf(t, signingKey, test.ca)
			token := signWithX5c(t, test.alg, signingKey, []string{der64(signingLeaf)})
			if _, _, err := jws.VerifyCompactSerialization(token, nil, &model.JoseOptions{X509Roots: roots(test.ca)}); err != nil {
				t.Errorf("[RFC 7515 4.1.6] the first certificate holds the signing key, and the algorithm its issuer signed it with says nothing about that key, got %v", err)
			}
		})
	}
}

func TestVerifyCompactSerialization_AnX5cEntryHoldingPemIsRefused(t *testing.T) {
	ca := rootCA(t, p256Key(t))
	signingKey := p256Key(t)
	signingLeaf := leaf(t, signingKey, ca)

	entry := base64.StdEncoding.EncodeToString(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: signingLeaf.cert.Raw}))
	token := signWithX5c(t, jwa.ES256, signingKey, []string{entry})
	if _, _, err := jws.VerifyCompactSerialization(token, nil, &model.JoseOptions{X509Roots: roots(ca)}); err == nil {
		t.Error("[RFC 7515 4.1.6] each x5c entry is base64-encoded DER, so an entry holding base64 of PEM text must be refused")
	}
}

func TestVerifyCompactSerialization_AnX5uDerBodyIsNotReplacedByAPemCertificateItEmbeds(t *testing.T) {
	ca := rootCA(t, p256Key(t))
	trustedKey := p256Key(t)
	trusted := leaf(t, trustedKey, ca)
	served := issue(t, &x509.Certificate{
		Subject: pkix.Name{CommonName: "outer"},
		ExtraExtensions: []pkix.Extension{{
			Id:    asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 99999, 1},
			Value: append([]byte("\n"), pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: trusted.cert.Raw})...),
		}},
	}, p256Key(t), nil)

	tests := map[string]struct {
		body   []byte
		accept bool
	}{
		"the trusted certificate itself":           {body: trusted.cert.Raw, accept: true},
		"one raw DER certificate":                  {body: served.cert.Raw},
		"one raw DER certificate and a stray byte": {body: append(append([]byte{}, served.cert.Raw...), 0)},
	}

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				if _, err := w.Write(tc.body); err != nil {
					return
				}
			}))
			defer server.Close()

			token := signWithHeader(t, jwa.ES256, trustedKey, map[string]any{"x5u": server.URL})
			_, _, err := jws.VerifyCompactSerialization(token, nil, &model.JoseOptions{X509Roots: roots(ca), HttpClient: server.Client()})
			if tc.accept {
				if err != nil {
					t.Errorf("[RFC 7515 4.1.5] %s holds the signing key and chains to the root, so it must verify, got %v", name, err)
				}
				return
			}
			if err == nil {
				t.Errorf("[RFC 7515 4.1.5] the token is signed with a key only the certificate embedded as PEM text holds, so %s must not verify with that embedded certificate's key", name)
			}
		})
	}
}
