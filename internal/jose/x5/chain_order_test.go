package x5

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/MichaelFraser99/go-jose/internal/httputils"
	"github.com/MichaelFraser99/go-jose/joseerror"
)

func certificateSources() map[string]func(t *testing.T, chain []*issued, roots *x509.CertPool) ([]crypto.PublicKey, error) {
	return map[string]func(t *testing.T, chain []*issued, roots *x509.CertPool) ([]crypto.PublicKey, error){
		"x5c": func(t *testing.T, chain []*issued, roots *x509.CertPool) ([]crypto.PublicKey, error) {
			return InlineCertificate(encodedChain(chain...), nil, nil, roots, nil)()
		},
		"x5u": func(t *testing.T, chain []*issued, roots *x509.CertPool) ([]crypto.PublicKey, error) {
			return retrieveX5UServing(t, pemChain(chain...), roots)
		},
	}
}

func retrieveX5UServing(t *testing.T, body []byte, roots *x509.CertPool) ([]crypto.PublicKey, error) {
	t.Helper()
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		if _, err := w.Write(body); err != nil {
			return
		}
	}))
	defer server.Close()
	return RetrieveX5U(server.URL, httputils.Fetcher(context.Background(), server.Client(), 0), nil, nil, roots, nil)()
}

func intermediates(t *testing.T, root *issued, n int) []*issued {
	t.Helper()
	chain := make([]*issued, n)
	parent := root
	for i := n - 1; i >= 0; i-- {
		chain[i] = issueCertificate(t, caTemplate(fmt.Sprintf("intermediate %d", i), x509.KeyUsageCertSign), parent)
		parent = chain[i]
	}
	return chain
}

func chainOfLength(t *testing.T, root *issued, length int) []*issued {
	t.Helper()
	above := intermediates(t, root, length-1)
	issuer := root
	if len(above) > 0 {
		issuer = above[0]
	}
	return append([]*issued{issueCertificate(t, leafTemplate(x509.KeyUsageDigitalSignature), issuer)}, above...)
}

func TestKeyFromValidatedChain_EachCertificateIsTheOneThatCertifiedThePreviousOne(t *testing.T) {
	tests := map[string]struct {
		chain  func(t *testing.T, root *issued) []*issued
		accept bool
	}{
		"the leaf alone": {
			chain:  func(t *testing.T, root *issued) []*issued { return chainOfLength(t, root, 1) },
			accept: true,
		},
		"the leaf then its issuer": {
			chain:  func(t *testing.T, root *issued) []*issued { return chainOfLength(t, root, 2) },
			accept: true,
		},
		"the leaf, its issuer, then the root": {
			chain:  func(t *testing.T, root *issued) []*issued { return append(chainOfLength(t, root, 2), root) },
			accept: true,
		},
		"an unrelated certificate between the leaf and its issuer": {
			chain: func(t *testing.T, root *issued) []*issued {
				chain := chainOfLength(t, root, 2)
				junk := issueCertificate(t, caTemplate("unrelated", x509.KeyUsageCertSign), root)
				return []*issued{chain[0], junk, chain[1]}
			},
		},
		"the issuer and the root in reverse order": {
			chain: func(t *testing.T, root *issued) []*issued {
				chain := chainOfLength(t, root, 2)
				return []*issued{chain[0], root, chain[1]}
			},
		},
		"the leaf repeated after itself": {
			chain: func(t *testing.T, root *issued) []*issued {
				chain := chainOfLength(t, root, 1)
				return []*issued{chain[0], chain[0]}
			},
		},
		"a certificate whose name is the issuer's but whose key did not sign the leaf": {
			chain: func(t *testing.T, root *issued) []*issued {
				named := issueCertificate(t, caTemplate("intermediate", x509.KeyUsageCertSign), root)
				signer := issueCertificate(t, caTemplate("intermediate", x509.KeyUsageCertSign), root)
				return []*issued{issueCertificate(t, leafTemplate(x509.KeyUsageDigitalSignature), signer), named}
			},
		},
		"a certificate whose key signed the leaf under another issuer name": {
			chain: func(t *testing.T, root *issued) []*issued {
				signer := issueCertificate(t, caTemplate("intermediate", x509.KeyUsageCertSign), root)
				renamed := &issued{cert: &x509.Certificate{Subject: pkix.Name{CommonName: "renamed"}}, key: signer.key}
				return []*issued{issueCertificate(t, leafTemplate(x509.KeyUsageDigitalSignature), renamed), signer}
			},
		},
		"sixteen certificates in order": {
			chain:  func(t *testing.T, root *issued) []*issued { return chainOfLength(t, root, 16) },
			accept: true,
		},
		"seventeen certificates in order": {
			chain: func(t *testing.T, root *issued) []*issued { return chainOfLength(t, root, 17) },
		},
	}

	for name, tc := range tests {
		for source, retrieve := range certificateSources() {
			t.Run(source+" "+name, func(t *testing.T) {
				root := issueCertificate(t, caTemplate("root", x509.KeyUsageCertSign), nil)
				chain := tc.chain(t, root)
				keys, err := retrieve(t, chain, poolOfIssued(root))
				if tc.accept {
					if err != nil {
						t.Fatalf("[RFC 7515 4.1.5, 4.1.6] %s follows the leaf with the certificates that certified it, so it must yield the leaf's key, got %v", name, err)
					}
					if len(keys) != 1 {
						t.Errorf("[RFC 7515 4.1.5, 4.1.6] expected the leaf's key alone, got %d keys", len(keys))
					}
					return
				}
				if !errors.Is(err, joseerror.ErrMalformedClaim) {
					t.Fatalf("[RFC 7515 4.1.5, 4.1.6] each certificate after the first must be the one used to certify the previous one, so %s must be refused with ErrMalformedClaim, got %v", name, err)
				}
				if len(keys) != 0 {
					t.Errorf("[RFC 7515 4.1.5, 4.1.6] no key may be returned, got %d", len(keys))
				}
			})
		}
	}
}

func TestValidateCertificateChain_RefusesMoreThanSixteenEntriesWhateverTheRoots(t *testing.T) {
	root := issueCertificate(t, caTemplate("root", x509.KeyUsageCertSign), nil)
	for length, accept := range map[int]bool{16: true, 17: false} {
		err := ValidateCertificateChain(map[string]any{}, encodedChain(chainOfLength(t, root, length)...))
		if accept && err != nil {
			t.Errorf("[RFC 7515 4.1.6] a chain of %d certificates is within the bound, got %v", length, err)
		}
		if !accept && !errors.Is(err, joseerror.ErrMalformedClaim) {
			t.Errorf("[RFC 7515 4.1.6] a chain of %d certificates exceeds the bound of 16, so it must be refused with ErrMalformedClaim, got %v", length, err)
		}
	}
}

func certificateWithURI(t *testing.T, root *issued, uri string) []byte {
	t.Helper()
	names, err := asn1.Marshal([]asn1.RawValue{{Class: asn1.ClassContextSpecific, Tag: 6, Bytes: []byte(uri)}})
	if err != nil {
		t.Fatal(err)
	}
	template := withExtension(leafTemplate(x509.KeyUsageDigitalSignature), pkix.Extension{Id: asn1.ObjectIdentifier{2, 5, 29, 17}, Value: names})
	template.SerialNumber = big.NewInt(1)
	template.NotBefore = time.Now().Add(-time.Hour)
	template.NotAfter = time.Now().Add(time.Hour)
	der, err := x509.CreateCertificate(rand.Reader, template, root.cert, root.key.Public(), root.key)
	if err != nil {
		t.Fatal(err)
	}
	return der
}

func TestParsingAChain_DoesNotEchoAPeersCertificateUnbounded(t *testing.T) {
	root := issueCertificate(t, caTemplate("root", x509.KeyUsageCertSign), nil)
	long := strings.Repeat("a", 50_000)
	unparsable := certificateWithURI(t, root, "https://"+long+"/%zz")
	if _, err := x509.ParseCertificate(unparsable); err == nil || !strings.Contains(err.Error(), long) {
		t.Fatalf("the fixture must be a certificate crypto/x509 refuses while quoting its SAN in full, got %v", err)
	}

	errorsFrom := map[string]func() error{
		"x5c header": func() error {
			return ValidateCertificateChain(map[string]any{}, []string{base64.StdEncoding.EncodeToString(unparsable)})
		},
		"x5u PEM body": func() error {
			_, err := retrieveX5UServing(t, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: unparsable}), poolOfIssued(root))
			return err
		},
	}
	for name, produce := range errorsFrom {
		t.Run(name, func(t *testing.T) {
			err := produce()
			if err == nil {
				t.Fatal("[RFC 7515 4.1.6] a certificate crypto/x509 cannot parse must be refused")
			}
			if strings.Contains(err.Error(), strings.Repeat("a", 65)) || len(err.Error()) > 512 {
				t.Errorf("[README Errors] an echoed value is cut to 64 characters, so the error must not carry the %d-byte SAN, got %d bytes", len(long), len(err.Error()))
			}
		})
	}
}
