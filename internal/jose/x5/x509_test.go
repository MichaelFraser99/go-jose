package x5

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"fmt"
	"github.com/MichaelFraser99/go-jose/joseerror"
	"math/big"
	"net/http"
	"net/http/httptest"
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
			errTypes:     []error{joseerror.ErrMalformedClaim},
		},
		"empty slice": {
			certificates: []string{},
			errMsg:       "the 'x5c' array carries no certificate",
			errTypes:     []error{joseerror.ErrMalformedClaim},
		},
		"nil slice": {
			certificates: nil,
			errMsg:       "the 'x5c' array carries no certificate",
			errTypes:     []error{joseerror.ErrMalformedClaim},
		},
		"an entry that decodes to no certificate": {
			certificates: []string{""},
			errMsg:       "entry 0 of the chain is not exactly one certificate: x509: malformed certificate",
			errTypes:     []error{joseerror.ErrMalformedClaim},
		},
		"a chain whose links do not join still parses": {
			certificates: []string{encodedCerts[3], encodedCerts[0]},
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
		want := expectedMsg
		if len(expectedTypes) > 0 {
			want = expectedTypes[0].Error() + expectedMsg
		}
		if want != producedError.Error() {
			t.Fatalf("expected error text %s, got %s", want, producedError.Error())
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

func x5tPair(t *testing.T, cert []byte) (string, string) {
	t.Helper()
	sha1Sum := sha1.Sum(cert)
	sha256Sum := sha256.Sum256(cert)
	return base64.RawURLEncoding.EncodeToString(sha1Sum[:]), base64.RawURLEncoding.EncodeToString(sha256Sum[:])
}

func TestInlineCertificate_AcceptsTheThumbprintTheRFCDefines(t *testing.T) {
	certs, err := generateCertificateChain(t, 1)
	if err != nil {
		t.Fatalf("failed to generate certificate chain: %v", err)
	}
	cert := certs[0]
	parsed, err := x509.ParseCertificate(cert)
	if err != nil {
		t.Fatalf("failed to parse the generated certificate: %v", err)
	}
	x5t, x5ts256 := x5tPair(t, cert)

	tests := map[string]struct {
		reference string
		x5t       *string
		x5ts256   *string
	}{
		"neither thumbprint":           {reference: "RFC 7515 4.1.7, 4.1.8"},
		"the SHA-1 thumbprint alone":   {reference: "RFC 7515 4.1.7", x5t: &x5t},
		"the SHA-256 thumbprint alone": {reference: "RFC 7515 4.1.8", x5ts256: &x5ts256},
		"both thumbprints":             {reference: "RFC 7515 4.1.7, 4.1.8", x5t: &x5t, x5ts256: &x5ts256},
	}

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			keys, err := InlineCertificate([]string{base64.StdEncoding.EncodeToString(cert)}, tc.x5t, tc.x5ts256, poolOf(t, cert))()
			if err != nil {
				t.Fatalf("[%s] a header carrying the thumbprint this clause defines must be accepted, got %v", tc.reference, err)
			}
			if len(keys) != 1 {
				t.Fatalf("[%s] expected the certificate's key, got %d keys", tc.reference, len(keys))
			}
			if !parsed.PublicKey.(*rsa.PublicKey).Equal(keys[0]) {
				t.Errorf("[%s] the key returned must be the one the certificate carries", tc.reference)
			}
		})
	}
}

func TestInlineCertificate_RefusesAThumbprintThatDoesNotMatch(t *testing.T) {
	certs, err := generateCertificateChain(t, 2)
	if err != nil {
		t.Fatalf("failed to generate certificate chain: %v", err)
	}
	cert, other := certs[0], certs[1]
	correctX5t, correctX5tS256 := x5tPair(t, cert)
	otherX5t, otherX5tS256 := x5tPair(t, other)
	empty := ""
	legacy := base64.RawURLEncoding.EncodeToString(append(append([]byte{}, cert...), sha256.New().Sum(nil)...))

	tests := map[string]struct {
		reference string
		x5t       *string
		x5ts256   *string
	}{
		"a SHA-1 thumbprint of another certificate":   {reference: "RFC 7515 4.1.7", x5t: &otherX5t},
		"a SHA-256 thumbprint of another certificate": {reference: "RFC 7515 4.1.8", x5ts256: &otherX5tS256},
		"a SHA-256 thumbprint where SHA-1 belongs":    {reference: "RFC 7515 4.1.7", x5t: &correctX5tS256},
		"a SHA-1 thumbprint where SHA-256 belongs":    {reference: "RFC 7515 4.1.8", x5ts256: &correctX5t},
		"an empty SHA-1 thumbprint":                   {reference: "RFC 7515 4.1.7", x5t: &empty},
		"an empty SHA-256 thumbprint":                 {reference: "RFC 7515 4.1.8", x5ts256: &empty},
		"the certificate itself":                      {reference: "RFC 7515 4.1.8", x5ts256: &legacy},
		"a correct SHA-1 beside a wrong SHA-256":      {reference: "RFC 7515 4.1.8", x5t: &correctX5t, x5ts256: &otherX5tS256},
		"a wrong SHA-1 beside a correct SHA-256":      {reference: "RFC 7515 4.1.7", x5t: &otherX5t, x5ts256: &correctX5tS256},
	}

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			keys, err := InlineCertificate([]string{base64.StdEncoding.EncodeToString(cert)}, tc.x5t, tc.x5ts256, poolOf(t, cert))()
			if err == nil {
				t.Fatalf("[%s] a thumbprint that is not this certificate's must be refused, got %d keys", tc.reference, len(keys))
			}
			if !errors.Is(err, joseerror.ErrNoKeyIdentifierMatch) {
				t.Errorf("[%s] the refusal must name the key identifier mismatch, got %v", tc.reference, err)
			}
			if len(keys) != 0 {
				t.Errorf("[%s] no key may be returned when the thumbprint does not match, got %d", tc.reference, len(keys))
			}
		})
	}
}

func TestRetrieveX5U_HoldsTheCertificateToItsThumbprint(t *testing.T) {
	certs, err := generateCertificateChain(t, 2)
	if err != nil {
		t.Fatalf("failed to generate certificate chain: %v", err)
	}
	cert, other := certs[0], certs[1]
	correctX5t, correctX5tS256 := x5tPair(t, cert)
	otherX5t, otherX5tS256 := x5tPair(t, other)

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		if _, err := w.Write(cert); err != nil {
			t.Errorf("failed to serve the certificate: %v", err)
		}
	}))
	defer server.Close()

	tests := map[string]struct {
		reference string
		x5t       *string
		x5ts256   *string
		accept    bool
	}{
		"the SHA-1 thumbprint":                  {reference: "RFC 7515 4.1.7", x5t: &correctX5t, accept: true},
		"the SHA-256 thumbprint":                {reference: "RFC 7515 4.1.8", x5ts256: &correctX5tS256, accept: true},
		"both thumbprints":                      {reference: "RFC 7515 4.1.7, 4.1.8", x5t: &correctX5t, x5ts256: &correctX5tS256, accept: true},
		"neither thumbprint":                    {reference: "RFC 7515 4.1.7, 4.1.8", accept: true},
		"another certificate's SHA-1":           {reference: "RFC 7515 4.1.7", x5t: &otherX5t},
		"another certificate's SHA-256":         {reference: "RFC 7515 4.1.8", x5ts256: &otherX5tS256},
		"a correct SHA-1 beside a wrong SHA256": {reference: "RFC 7515 4.1.8", x5t: &correctX5t, x5ts256: &otherX5tS256},
	}

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			keys, err := RetrieveX5U(server.URL, server.Client(), tc.x5t, tc.x5ts256, poolOf(t, cert))()
			if tc.accept {
				if err != nil {
					t.Fatalf("[%s] the certificate this URL serves carries that thumbprint, so it must be accepted, got %v", tc.reference, err)
				}
				if len(keys) != 1 {
					t.Errorf("[%s] expected the certificate's key, got %d keys", tc.reference, len(keys))
				}
				return
			}
			if err == nil {
				t.Fatalf("[%s] a thumbprint that is not the served certificate's must be refused, got %d keys", tc.reference, len(keys))
			}
			if !errors.Is(err, joseerror.ErrNoKeyIdentifierMatch) {
				t.Errorf("[%s] the refusal must name the key identifier mismatch, got %v", tc.reference, err)
			}
		})
	}
}

func poolOf(t *testing.T, der ...[]byte) *x509.CertPool {
	t.Helper()
	pool := x509.NewCertPool()
	for _, d := range der {
		parsed, err := x509.ParseCertificate(d)
		if err != nil {
			t.Fatalf("failed to parse a certificate for the pool: %v", err)
		}
		pool.AddCert(parsed)
	}
	return pool
}

func TestInlineCertificate_AChainIsValidatedAgainstTheConfiguredRootsNotItself(t *testing.T) {
	certs, err := generateCertificateChain(t, 5)
	if err != nil {
		t.Fatalf("failed to generate certificate chain: %v", err)
	}
	encoded := make([]string, len(certs))
	for i, c := range certs {
		encoded[i] = base64.StdEncoding.EncodeToString(c)
	}

	tests := map[string]struct {
		reference string
		chain     []string
		roots     *x509.CertPool
		accept    bool
	}{
		"a full chain reaching the configured root": {
			reference: "RFC 7515 4.1.6",
			chain:     []string{encoded[4], encoded[3], encoded[2], encoded[1], encoded[0]},
			roots:     poolOf(t, certs[0]),
			accept:    true,
		},
		"a chain whose links do not join": {
			reference: "RFC 5280 6.1",
			chain:     []string{encoded[3], encoded[0]},
			roots:     poolOf(t, certs[0]),
		},
		"a chain reaching a root that is not configured": {
			reference: "RFC 5280 6.1",
			chain:     []string{encoded[4], encoded[3], encoded[2], encoded[1], encoded[0]},
			roots:     x509.NewCertPool(),
		},
		"a leaf alone, with its own issuer not configured": {
			reference: "RFC 5280 6.1",
			chain:     []string{encoded[4]},
			roots:     x509.NewCertPool(),
		},
		"a self-signed root alone, not configured as a root": {
			reference: "RFC 5280 6.1",
			chain:     []string{encoded[0]},
			roots:     x509.NewCertPool(),
		},
		"no roots configured at all": {
			reference: "RFC 7515 4.1.6",
			chain:     []string{encoded[4], encoded[3], encoded[2], encoded[1], encoded[0]},
			roots:     nil,
		},
	}

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			keys, err := InlineCertificate(tc.chain, nil, nil, tc.roots)()
			if tc.accept {
				if err != nil {
					t.Fatalf("[%s] a chain that validates to a configured trust anchor must yield its key, got %v", tc.reference, err)
				}
				if len(keys) != 1 {
					t.Errorf("[%s] expected the signing certificate's key, got %d", tc.reference, len(keys))
				}
				return
			}
			if err == nil {
				t.Fatalf("[%s] path validation takes the trust anchor as an input, so a chain that does not reach a configured one must not yield a key, got %d", tc.reference, len(keys))
			}
			if len(keys) != 0 {
				t.Errorf("[%s] no key may be returned, got %d", tc.reference, len(keys))
			}
		})
	}
}

func TestCertificateChainStrings_EveryShapeThatIsNotAnArrayOfStringsIsRefused(t *testing.T) {
	tests := map[string]struct {
		reference string
		raw       any
	}{
		"a null claim":                {reference: "RFC 7515 4.1.6", raw: nil},
		"a bare string":               {reference: "RFC 7515 4.1.6", raw: ""},
		"a non-empty bare string":     {reference: "RFC 7515 4.1.6", raw: "AA"},
		"an object":                   {reference: "RFC 7515 4.1.6", raw: map[string]any{}},
		"a number":                    {reference: "RFC 7515 4.1.6", raw: 7},
		"a boolean":                   {reference: "RFC 7515 4.1.6", raw: true},
		"an array holding null":       {reference: "RFC 7515 4.1.6", raw: []any{nil}},
		"an array holding a number":   {reference: "RFC 7515 4.1.6", raw: []any{7}},
		"an array holding an object":  {reference: "RFC 7515 4.1.6", raw: []any{map[string]any{}}},
		"a nested array":              {reference: "RFC 7515 4.1.6", raw: []any{[]any{"AA"}}},
		"an empty array of any":       {reference: "RFC 7515 4.1.6", raw: []any{}},
		"an empty array of string":    {reference: "RFC 7515 4.1.6", raw: []string{}},
		"a nil array of string":       {reference: "RFC 7515 4.1.6", raw: []string(nil)},
		"an array holding only empty": {reference: "RFC 7515 4.1.6", raw: []any{""}},
	}

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			chain, err := CertificateChainStrings(tc.raw)
			if err != nil {
				if !errors.Is(err, joseerror.ErrMalformedClaim) {
					t.Errorf("[%s] a claim shape the peer chose is the peer's fault, got %v", tc.reference, err)
				}
				return
			}
			if err := ValidateCertificateChain(map[string]any{}, chain); err == nil {
				t.Errorf("[%s] %s names no certificate, so it must be refused by conversion or by validation, got %d accepted entries", tc.reference, name, len(chain))
			}
		})
	}
}

func TestCertificateChainStrings_BothArrayShapesAreRead(t *testing.T) {
	certs, err := generateCertificateChain(t, 2)
	if err != nil {
		t.Fatalf("failed to generate certificate chain: %v", err)
	}
	first := base64.StdEncoding.EncodeToString(certs[0])
	second := base64.StdEncoding.EncodeToString(certs[1])

	tests := map[string]struct {
		reference string
		raw       any
	}{
		"the []any a JSON decode produces":  {reference: "RFC 7515 4.1.6", raw: []any{first, second}},
		"the []string a Go caller may hold": {reference: "RFC 7515 4.1.6", raw: []string{first, second}},
	}

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			chain, err := CertificateChainStrings(tc.raw)
			if err != nil {
				t.Fatalf("[%s] %s must be readable, got %v", tc.reference, name, err)
			}
			if len(chain) != 2 || chain[0] != first || chain[1] != second {
				t.Errorf("[%s] expected the two entries in order, got %v", tc.reference, chain)
			}
		})
	}
}

func TestRetrieveX5U_ReadsThePemEncodingTheClauseRequires(t *testing.T) {
	certs, err := generateCertificateChain(t, 3)
	if err != nil {
		t.Fatalf("failed to generate certificate chain: %v", err)
	}
	roots := poolOf(t, certs[0])

	pemChain := func(order ...int) []byte {
		var out []byte
		for _, i := range order {
			out = append(out, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certs[i]})...)
		}
		return out
	}
	derChain := func(order ...int) []byte {
		var out []byte
		for _, i := range order {
			out = append(out, certs[i]...)
		}
		return out
	}

	tests := map[string]struct {
		reference string
		body      []byte
		accept    bool
	}{
		"PEM, leaf first, as the clause requires": {reference: "RFC 7515 4.1.5", body: pemChain(2, 1, 0), accept: true},
		"PEM with the leaf alone":                 {reference: "RFC 7515 4.1.5", body: pemChain(0), accept: true},
		"DER, which some servers send anyway":     {reference: "RFC 7515 4.1.5", body: derChain(2, 1, 0), accept: true},
		"PEM carrying no certificate block":       {reference: "RFC 7515 4.1.5", body: []byte("-----BEGIN PRIVATE KEY-----\nAA==\n-----END PRIVATE KEY-----\n")},
		"a body that is neither":                  {reference: "RFC 7515 4.1.5", body: []byte("not a certificate at all")},
	}

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				if _, err := w.Write(tc.body); err != nil {
					return
				}
			}))
			defer server.Close()

			keys, err := RetrieveX5U(server.URL, server.Client(), nil, nil, roots)()
			if tc.accept {
				if err != nil {
					t.Fatalf("[%s] the clause requires the resource be PEM-encoded, so %s must be read, got %v", tc.reference, name, err)
				}
				if len(keys) != 1 {
					t.Errorf("[%s] expected the signing certificate's key, got %d", tc.reference, len(keys))
				}
				return
			}
			if err == nil {
				t.Errorf("[%s] %s names no certificate, so it must be refused, got %d keys", tc.reference, name, len(keys))
			}
		})
	}
}
