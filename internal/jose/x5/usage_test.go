package x5

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"math/big"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/MichaelFraser99/go-jose/internal/httputils"
	"github.com/MichaelFraser99/go-jose/joseerror"
)

type issued struct {
	cert *x509.Certificate
	key  crypto.Signer
}

func issueCertificate(t *testing.T, template *x509.Certificate, parent *issued) *issued {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate a key: %v", err)
	}
	template.SerialNumber = big.NewInt(time.Now().UnixNano())
	template.NotBefore = time.Now().Add(-time.Hour)
	template.NotAfter = time.Now().Add(time.Hour)
	parentCert, parentKey := template, crypto.Signer(key)
	if parent != nil {
		parentCert, parentKey = parent.cert, parent.key
	}
	der, err := x509.CreateCertificate(rand.Reader, template, parentCert, key.Public(), parentKey)
	if err != nil {
		t.Fatalf("failed to create a certificate: %v", err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("failed to parse a certificate: %v", err)
	}
	return &issued{cert: cert, key: key}
}

func caTemplate(name string, usage x509.KeyUsage, extUsage ...x509.ExtKeyUsage) *x509.Certificate {
	return &x509.Certificate{
		Subject:               pkix.Name{CommonName: name},
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              usage,
		ExtKeyUsage:           extUsage,
	}
}

func leafTemplate(usage x509.KeyUsage, extUsage ...x509.ExtKeyUsage) *x509.Certificate {
	return &x509.Certificate{Subject: pkix.Name{CommonName: "leaf"}, KeyUsage: usage, ExtKeyUsage: extUsage}
}

func withExtension(template *x509.Certificate, extension pkix.Extension) *x509.Certificate {
	template.ExtraExtensions = append(template.ExtraExtensions, extension)
	return template
}

func encodedChain(chain ...*issued) []string {
	encoded := make([]string, len(chain))
	for i, c := range chain {
		encoded[i] = base64.StdEncoding.EncodeToString(c.cert.Raw)
	}
	return encoded
}

func pemChain(chain ...*issued) []byte {
	var out []byte
	for _, c := range chain {
		out = append(out, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: c.cert.Raw})...)
	}
	return out
}

func poolOfIssued(certs ...*issued) *x509.CertPool {
	pool := x509.NewCertPool()
	for _, c := range certs {
		pool.AddCert(c.cert)
	}
	return pool
}

type usageCase struct {
	reference    string
	chain        func(t *testing.T, root *issued) []*issued
	extKeyUsages []x509.ExtKeyUsage
	rootUsage    x509.KeyUsage
	rootExtras   []pkix.Extension
	accept       bool
}

func leafOf(template *x509.Certificate) func(t *testing.T, root *issued) []*issued {
	return func(t *testing.T, root *issued) []*issued {
		return []*issued{issueCertificate(t, template, root)}
	}
}

func assertUsageCases(t *testing.T, tests map[string]usageCase) {
	t.Helper()
	sources := map[string]func(t *testing.T, chain []*issued, roots *x509.CertPool, extKeyUsages []x509.ExtKeyUsage) ([]crypto.PublicKey, error){
		"x5c": func(t *testing.T, chain []*issued, roots *x509.CertPool, extKeyUsages []x509.ExtKeyUsage) ([]crypto.PublicKey, error) {
			return InlineCertificate(encodedChain(chain...), nil, nil, roots, extKeyUsages)()
		},
		"x5u": func(t *testing.T, chain []*issued, roots *x509.CertPool, extKeyUsages []x509.ExtKeyUsage) ([]crypto.PublicKey, error) {
			body := pemChain(chain...)
			server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				if _, err := w.Write(body); err != nil {
					return
				}
			}))
			defer server.Close()
			return RetrieveX5U(server.URL, httputils.Fetcher(context.Background(), server.Client(), 0), nil, nil, roots, extKeyUsages)()
		},
	}

	for name, tc := range tests {
		for source, retrieve := range sources {
			t.Run(source+" "+name, func(t *testing.T) {
				rootUsage := tc.rootUsage
				if rootUsage == 0 {
					rootUsage = x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature
				}
				rootTemplate := caTemplate("root", rootUsage)
				rootTemplate.ExtraExtensions = tc.rootExtras
				root := issueCertificate(t, rootTemplate, nil)
				chain := tc.chain(t, root)
				keys, err := retrieve(t, chain, poolOfIssued(root), tc.extKeyUsages)
				if tc.accept {
					if err != nil {
						t.Fatalf("[%s] %s must yield its key, got %v", tc.reference, name, err)
					}
					if len(keys) != 1 || !chain[0].cert.PublicKey.(*ecdsa.PublicKey).Equal(keys[0]) {
						t.Errorf("[%s] expected the first certificate's key, got %d keys", tc.reference, len(keys))
					}
					return
				}
				if err == nil {
					t.Fatalf("[%s] %s must not be used to verify a JWS, got %d keys", tc.reference, name, len(keys))
				}
				if !errors.Is(err, joseerror.ErrNoKeyIdentifierMatch) {
					t.Errorf("[%s] the refusal must match ErrNoKeyIdentifierMatch, as a chain that does not validate does, got %v", tc.reference, err)
				}
				if len(keys) != 0 {
					t.Errorf("[%s] no key may be returned, got %d", tc.reference, len(keys))
				}
			})
		}
	}
}

func TestKeyFromValidatedChain_AnExtendedKeyUsageMustCoverTheUse(t *testing.T) {
	signing := x509.KeyUsageDigitalSignature
	unknownPurpose := asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 99999, 1}
	noPurpose := pkix.Extension{Id: asn1.ObjectIdentifier{2, 5, 29, 37}, Value: []byte{0x30, 0x00}}

	assertUsageCases(t, map[string]usageCase{
		"a leaf with no extended key usage": {
			reference: "RFC 5280 4.2.1.12", chain: leafOf(leafTemplate(signing)), accept: true,
		},
		"a leaf naming anyExtendedKeyUsage": {
			reference: "RFC 5280 4.2.1.12", chain: leafOf(leafTemplate(signing, x509.ExtKeyUsageAny)), accept: true,
		},
		"a leaf naming TLS server and anyExtendedKeyUsage": {
			reference: "RFC 5280 4.2.1.12", chain: leafOf(leafTemplate(signing, x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageAny)), accept: true,
		},
		"a leaf restricted to TLS server authentication": {
			reference: "RFC 5280 4.2.1.12", chain: leafOf(leafTemplate(signing, x509.ExtKeyUsageServerAuth)),
		},
		"a leaf restricted to TLS client authentication": {
			reference: "RFC 5280 4.2.1.12", chain: leafOf(leafTemplate(signing, x509.ExtKeyUsageClientAuth)),
		},
		"a leaf restricted to TLS server and client authentication": {
			reference: "RFC 5280 4.2.1.12", chain: leafOf(leafTemplate(signing, x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth)),
		},
		"a leaf restricted to a purpose Go does not name": {
			reference: "RFC 5280 4.2.1.12",
			chain: func(t *testing.T, root *issued) []*issued {
				template := leafTemplate(signing)
				template.UnknownExtKeyUsage = []asn1.ObjectIdentifier{unknownPurpose}
				return []*issued{issueCertificate(t, template, root)}
			},
		},
		"a leaf restricted to a purpose Go does not name when the caller named anyExtendedKeyUsage": {
			reference:    "JoseOptions.X509ExtKeyUsages",
			extKeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageAny},
			chain: func(t *testing.T, root *issued) []*issued {
				template := leafTemplate(signing)
				template.UnknownExtKeyUsage = []asn1.ObjectIdentifier{unknownPurpose}
				return []*issued{issueCertificate(t, template, root)}
			},
			accept: true,
		},
		"a leaf whose extended key usage names no purpose": {
			reference: "RFC 5280 4.2.1.12", chain: leafOf(withExtension(leafTemplate(signing), noPurpose)),
		},
		"a leaf whose extended key usage names no purpose when the caller named a purpose": {
			reference: "RFC 5280 4.2.1.12", chain: leafOf(withExtension(leafTemplate(signing), noPurpose)),
			extKeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageCodeSigning},
		},
		"a leaf whose extended key usage names no purpose when the caller named anyExtendedKeyUsage": {
			reference: "RFC 5280 4.2.1.12", chain: leafOf(withExtension(leafTemplate(signing), noPurpose)),
			extKeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageAny},
		},
		"a leaf restricted to a purpose the caller named": {
			reference: "JoseOptions.X509ExtKeyUsages", chain: leafOf(leafTemplate(signing, x509.ExtKeyUsageCodeSigning)),
			extKeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageCodeSigning}, accept: true,
		},
		"a leaf restricted to one of several purposes the caller named": {
			reference: "JoseOptions.X509ExtKeyUsages", chain: leafOf(leafTemplate(signing, x509.ExtKeyUsageClientAuth)),
			extKeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageCodeSigning, x509.ExtKeyUsageClientAuth}, accept: true,
		},
		"a leaf restricted to a purpose the caller did not name": {
			reference: "RFC 5280 4.2.1.12", chain: leafOf(leafTemplate(signing, x509.ExtKeyUsageServerAuth)),
			extKeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageCodeSigning},
		},
		"a leaf restricted to TLS server authentication when the caller named anyExtendedKeyUsage": {
			reference: "JoseOptions.X509ExtKeyUsages", chain: leafOf(leafTemplate(signing, x509.ExtKeyUsageServerAuth)),
			extKeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageAny}, accept: true,
		},
		"a leaf with no extended key usage when the caller named a purpose": {
			reference: "RFC 5280 4.2.1.12", chain: leafOf(leafTemplate(signing)),
			extKeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageCodeSigning}, accept: true,
		},
		"a leaf naming anyExtendedKeyUsage when the caller named a purpose": {
			reference: "RFC 5280 4.2.1.12", chain: leafOf(leafTemplate(signing, x509.ExtKeyUsageAny)),
			extKeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageCodeSigning}, accept: true,
		},
		"a leaf under an intermediate restricted to code signing, when the caller named nothing": {
			reference: "RFC 5280 4.2.1.12",
			chain: func(t *testing.T, root *issued) []*issued {
				intermediate := issueCertificate(t, caTemplate("intermediate", x509.KeyUsageCertSign, x509.ExtKeyUsageCodeSigning), root)
				return []*issued{issueCertificate(t, leafTemplate(signing), intermediate), intermediate}
			},
			accept: true,
		},
		"a leaf under an intermediate whose extended key usage names no purpose, when the caller named its purpose": {
			reference:    "RFC 5280 4.2.1.12",
			extKeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageCodeSigning},
			chain: func(t *testing.T, root *issued) []*issued {
				intermediate := issueCertificate(t, withExtension(caTemplate("intermediate", x509.KeyUsageCertSign), noPurpose), root)
				return []*issued{issueCertificate(t, leafTemplate(signing, x509.ExtKeyUsageCodeSigning), intermediate), intermediate}
			},
		},
		"a leaf under an intermediate whose extended key usage names no purpose, when the caller named nothing": {
			reference: "RFC 5280 4.2.1.12",
			chain: func(t *testing.T, root *issued) []*issued {
				intermediate := issueCertificate(t, withExtension(caTemplate("intermediate", x509.KeyUsageCertSign), noPurpose), root)
				return []*issued{issueCertificate(t, leafTemplate(signing), intermediate), intermediate}
			},
		},
		"a leaf under an intermediate whose extended key usage names no purpose, when the caller named anyExtendedKeyUsage": {
			reference:    "RFC 5280 4.2.1.12",
			extKeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageAny},
			chain: func(t *testing.T, root *issued) []*issued {
				intermediate := issueCertificate(t, withExtension(caTemplate("intermediate", x509.KeyUsageCertSign), noPurpose), root)
				return []*issued{issueCertificate(t, leafTemplate(signing), intermediate), intermediate}
			},
		},
		"a leaf under two intermediates of one key, only one naming no purpose": {
			reference:    "RFC 5280 6.1",
			extKeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageCodeSigning},
			chain: func(t *testing.T, root *issued) []*issued {
				clean, empty := sameKeyIntermediates(t, root, noPurpose)
				return []*issued{issueCertificate(t, leafTemplate(signing, x509.ExtKeyUsageCodeSigning), clean), empty, clean}
			},
			accept: true,
		},
		"a leaf offered only through the one of two intermediates that names no purpose": {
			reference:    "RFC 5280 4.2.1.12",
			extKeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageCodeSigning},
			chain: func(t *testing.T, root *issued) []*issued {
				clean, empty := sameKeyIntermediates(t, root, noPurpose)
				return []*issued{issueCertificate(t, leafTemplate(signing, x509.ExtKeyUsageCodeSigning), clean), empty}
			},
		},
		"a leaf under a clean intermediate and a trust anchor whose extended key usage names no purpose": {
			reference:    "RFC 5280 6.1.1",
			extKeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageCodeSigning},
			rootExtras:   []pkix.Extension{noPurpose},
			chain: func(t *testing.T, root *issued) []*issued {
				intermediate := issueCertificate(t, caTemplate("intermediate", x509.KeyUsageCertSign), root)
				return []*issued{issueCertificate(t, leafTemplate(signing, x509.ExtKeyUsageCodeSigning), intermediate), intermediate}
			},
			accept: true,
		},
		"a leaf under an intermediate restricted to a purpose the caller did not name": {
			reference:    "JoseOptions.X509ExtKeyUsages",
			extKeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageCodeSigning},
			chain: func(t *testing.T, root *issued) []*issued {
				intermediate := issueCertificate(t, caTemplate("intermediate", x509.KeyUsageCertSign, x509.ExtKeyUsageServerAuth), root)
				return []*issued{issueCertificate(t, leafTemplate(signing, x509.ExtKeyUsageCodeSigning), intermediate), intermediate}
			},
		},
	})
}

func TestKeyFromValidatedChain_AKeyUsageMustAllowVerifyingASignature(t *testing.T) {
	assertUsageCases(t, map[string]usageCase{
		"a leaf with no key usage": {
			reference: "RFC 5280 4.2.1.3", chain: leafOf(leafTemplate(0)), accept: true,
		},
		"a leaf asserting digitalSignature": {
			reference: "RFC 5280 4.2.1.3", chain: leafOf(leafTemplate(x509.KeyUsageDigitalSignature)), accept: true,
		},
		"a leaf asserting only nonRepudiation": {
			reference: "RFC 5280 4.2.1.3", chain: leafOf(leafTemplate(x509.KeyUsageContentCommitment)), accept: true,
		},
		"a leaf whose key usage asserts no bit": {
			reference: "RFC 5280 4.2.1.3",
			chain:     leafOf(withExtension(leafTemplate(0), pkix.Extension{Id: asn1.ObjectIdentifier{2, 5, 29, 15}, Critical: true, Value: []byte{0x03, 0x01, 0x00}})),
		},
		"a leaf asserting only keyAgreement": {
			reference: "RFC 5280 4.2.1.3", chain: leafOf(leafTemplate(x509.KeyUsageKeyAgreement)),
		},
		"a leaf asserting every bit but the two that verify a signature": {
			reference: "RFC 5280 4.2.1.3",
			chain: leafOf(leafTemplate(x509.KeyUsageKeyEncipherment | x509.KeyUsageDataEncipherment | x509.KeyUsageKeyAgreement |
				x509.KeyUsageCRLSign | x509.KeyUsageEncipherOnly | x509.KeyUsageDecipherOnly)),
		},
		"a leaf under an intermediate whose key usage asserts no bit": {
			reference: "RFC 5280 6.1.4(n)",
			chain: func(t *testing.T, root *issued) []*issued {
				intermediate := issueCertificate(t, withExtension(caTemplate("intermediate", 0), emptyKeyUsage), root)
				return []*issued{issueCertificate(t, leafTemplate(x509.KeyUsageDigitalSignature), intermediate), intermediate}
			},
		},
		"a leaf under an intermediate whose key usage asserts no bit, when the caller named a purpose": {
			reference:    "RFC 5280 6.1.4(n)",
			extKeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageCodeSigning},
			chain: func(t *testing.T, root *issued) []*issued {
				intermediate := issueCertificate(t, withExtension(caTemplate("intermediate", 0), emptyKeyUsage), root)
				return []*issued{issueCertificate(t, leafTemplate(x509.KeyUsageDigitalSignature, x509.ExtKeyUsageCodeSigning), intermediate), intermediate}
			},
		},
		"a leaf under an intermediate asserting only digitalSignature": {
			reference: "RFC 5280 6.1.4(n)",
			chain: func(t *testing.T, root *issued) []*issued {
				intermediate := issueCertificate(t, caTemplate("intermediate", x509.KeyUsageDigitalSignature), root)
				return []*issued{issueCertificate(t, leafTemplate(x509.KeyUsageDigitalSignature), intermediate), intermediate}
			},
		},
		"a leaf under an intermediate with no key usage extension": {
			reference: "RFC 5280 4.2.1.3",
			chain: func(t *testing.T, root *issued) []*issued {
				intermediate := issueCertificate(t, caTemplate("intermediate", 0), root)
				if hasExtension(intermediate.cert, oidExtensionKeyUsage) {
					t.Fatal("the intermediate must carry no key usage extension")
				}
				return []*issued{issueCertificate(t, leafTemplate(x509.KeyUsageDigitalSignature), intermediate), intermediate}
			},
			accept: true,
		},
		"a leaf under an intermediate asserting keyCertSign": {
			reference: "RFC 5280 6.1.4(n)",
			chain: func(t *testing.T, root *issued) []*issued {
				intermediate := issueCertificate(t, caTemplate("intermediate", x509.KeyUsageCertSign), root)
				return []*issued{issueCertificate(t, leafTemplate(x509.KeyUsageDigitalSignature), intermediate), intermediate}
			},
			accept: true,
		},
		"a leaf under two intermediates of one key, only one asserting no key usage bit": {
			reference: "RFC 5280 6.1",
			chain: func(t *testing.T, root *issued) []*issued {
				clean, empty := sameKeyIntermediates(t, root, emptyKeyUsage)
				return []*issued{issueCertificate(t, leafTemplate(x509.KeyUsageDigitalSignature), clean), empty, clean}
			},
			accept: true,
		},
		"a leaf offered only through the one of two intermediates asserting no key usage bit": {
			reference: "RFC 5280 6.1.4(n)",
			chain: func(t *testing.T, root *issued) []*issued {
				clean, empty := sameKeyIntermediates(t, root, emptyKeyUsage)
				return []*issued{issueCertificate(t, leafTemplate(x509.KeyUsageDigitalSignature), clean), empty}
			},
		},
		"a leaf under a clean intermediate and a trust anchor whose key usage asserts no bit": {
			reference:  "RFC 5280 6.1.1",
			rootExtras: []pkix.Extension{emptyKeyUsage},
			chain: func(t *testing.T, root *issued) []*issued {
				intermediate := issueCertificate(t, caTemplate("intermediate", x509.KeyUsageCertSign), root)
				return []*issued{issueCertificate(t, leafTemplate(x509.KeyUsageDigitalSignature), intermediate), intermediate}
			},
			accept: true,
		},
		"an intermediate CA asserting only keyCertSign as the first certificate": {
			reference: "RFC 5280 4.2.1.3",
			chain: func(t *testing.T, root *issued) []*issued {
				return []*issued{issueCertificate(t, caTemplate("intermediate", x509.KeyUsageCertSign), root)}
			},
		},
		"a root CA asserting only keyCertSign as the first certificate": {
			reference: "RFC 5280 4.2.1.3",
			rootUsage: x509.KeyUsageCertSign,
			chain: func(t *testing.T, root *issued) []*issued {
				return []*issued{root}
			},
		},
		"an intermediate CA asserting keyCertSign and digitalSignature": {
			reference: "RFC 5280 4.2.1.3",
			chain: func(t *testing.T, root *issued) []*issued {
				return []*issued{issueCertificate(t, caTemplate("intermediate", x509.KeyUsageCertSign|x509.KeyUsageDigitalSignature), root)}
			},
			accept: true,
		},
	})
}

var emptyKeyUsage = pkix.Extension{Id: asn1.ObjectIdentifier{2, 5, 29, 15}, Critical: true, Value: []byte{0x03, 0x01, 0x00}}

func sameKeyIntermediates(t *testing.T, root *issued, extension pkix.Extension) (clean, withExtra *issued) {
	t.Helper()
	clean = issueCertificate(t, caTemplate("intermediate", x509.KeyUsageCertSign), root)
	template := withExtension(caTemplate("intermediate", x509.KeyUsageCertSign), extension)
	template.SerialNumber = big.NewInt(time.Now().UnixNano())
	template.NotBefore = time.Now().Add(-time.Hour)
	template.NotAfter = time.Now().Add(time.Hour)
	der, err := x509.CreateCertificate(rand.Reader, template, root.cert, clean.key.Public(), root.key)
	if err != nil {
		t.Fatalf("failed to create a certificate: %v", err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("failed to parse a certificate: %v", err)
	}
	return clean, &issued{cert: cert, key: clean.key}
}
