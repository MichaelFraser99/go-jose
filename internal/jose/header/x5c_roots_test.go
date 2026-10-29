package header

import (
	"context"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"

	"github.com/MichaelFraser99/go-jose/internal/jose/jsonutils"
	"github.com/MichaelFraser99/go-jose/model"
)

func jsonDecodedHeader(t *testing.T, head map[string]any) map[string]any {
	t.Helper()
	raw, err := json.Marshal(head)
	if err != nil {
		t.Fatalf("failed to encode the header: %v", err)
	}
	decoded, err := jsonutils.DecodeBase64urlMap(base64.RawURLEncoding.EncodeToString(raw))
	if err != nil {
		t.Fatalf("failed to decode the header: %v", err)
	}
	return decoded
}

func TestValidateHeader_AnX5cSurvivesTheJsonBoundary(t *testing.T) {
	certs, err := generateCertificateChainOnly(t, 2)
	if err != nil {
		t.Fatalf("failed to build a chain: %v", err)
	}
	encoded := make([]string, len(certs))
	for i, c := range certs {
		encoded[i] = base64.StdEncoding.EncodeToString(c)
	}

	roots := x509.NewCertPool()
	parsed, err := x509.ParseCertificate(certs[len(certs)-1])
	if err != nil {
		t.Fatalf("failed to parse the root: %v", err)
	}
	roots.AddCert(parsed)

	head := jsonDecodedHeader(t, map[string]any{"alg": "RS256", "x5c": encoded})

	retrievers, err := ValidateHeader(context.Background(), head, nil, &model.JoseOptions{X509Roots: roots})
	if err != nil {
		t.Fatalf("[RFC 7515 4.1.6] a header carrying x5c must be readable after a JSON decode, got %v", err)
	}
	if len(retrievers) == 0 {
		t.Fatal("[RFC 7515 4.1.6] an x5c with roots configured must yield a retriever")
	}
}

func TestValidateHeader_AnX5cEntryThatIsNotAStringIsRefused(t *testing.T) {
	tests := map[string]any{
		"a number in the array":  []any{7},
		"an object in the array": []any{map[string]any{}},
		"null in the array":      []any{nil},
		"a nested array":         []any{[]any{"AA"}},
	}

	roots := x509.NewCertPool()
	for name, x5c := range tests {
		t.Run(name, func(t *testing.T) {
			head := jsonDecodedHeader(t, map[string]any{"alg": "RS256", "x5c": x5c})
			if _, err := ValidateHeader(context.Background(), head, nil, &model.JoseOptions{X509Roots: roots}); err == nil {
				t.Errorf("[RFC 7515 4.1.6] each entry is a base64-encoded DER string, so %s must be refused", name)
			}
		})
	}
}

func TestValidateHeader_WithoutRootsTheCertificateHeadersYieldNoRetriever(t *testing.T) {
	certs, err := generateCertificateChainOnly(t, 2)
	if err != nil {
		t.Fatalf("failed to build a chain: %v", err)
	}
	encoded := []string{base64.StdEncoding.EncodeToString(certs[0]), base64.StdEncoding.EncodeToString(certs[1])}

	tests := map[string]map[string]any{
		"x5c": {"alg": "RS256", "x5c": encoded},
		"x5u": {"alg": "RS256", "x5u": "https://example.com/certs"},
	}

	for name, head := range tests {
		t.Run(name, func(t *testing.T) {
			retrievers, err := ValidateHeader(context.Background(), jsonDecodedHeader(t, head), nil, nil)
			if err != nil {
				t.Fatalf("[RFC 7515 4.1.6] a well-formed header must not be refused merely because no roots are configured, got %v", err)
			}
			if len(retrievers) != 0 {
				t.Errorf("[RFC 7515 4.1.6] the recipient MUST validate the chain per RFC 5280, which needs a trust anchor, so with no roots configured %s must yield no retriever, got %d", name, len(retrievers))
			}
		})
	}
}

func TestValidateHeader_AMalformedX5cIsRefusedWhetherOrNotRootsAreConfigured(t *testing.T) {
	pools := map[string]*x509.CertPool{"with roots": x509.NewCertPool(), "without roots": nil}

	for name, roots := range pools {
		t.Run(name, func(t *testing.T) {
			head := jsonDecodedHeader(t, map[string]any{"alg": "RS256", "x5c": []any{"!!!not base64!!!"}})
			_, err := ValidateHeader(context.Background(), head, nil, &model.JoseOptions{X509Roots: roots})
			if err == nil {
				t.Fatal("[RFC 7515 4.1.6] an entry that is not base64 is malformed regardless of trust configuration")
			}
			if !strings.Contains(err.Error(), "base64") {
				t.Errorf("the refusal must name the encoding fault, got %v", err)
			}
		})
	}
}

func TestValidateHeader_AChainThatDoesNotReachTheConfiguredRootsIsNotTrusted(t *testing.T) {
	chain, err := generateCertificateChainOnly(t, 2)
	if err != nil {
		t.Fatalf("failed to build a chain: %v", err)
	}
	other, err := generateCertificateChainOnly(t, 2)
	if err != nil {
		t.Fatalf("failed to build a second chain: %v", err)
	}

	roots := x509.NewCertPool()
	unrelated, err := x509.ParseCertificate(other[len(other)-1])
	if err != nil {
		t.Fatalf("failed to parse the unrelated root: %v", err)
	}
	roots.AddCert(unrelated)

	encoded := make([]string, len(chain))
	for i, c := range chain {
		encoded[i] = base64.StdEncoding.EncodeToString(c)
	}
	head := jsonDecodedHeader(t, map[string]any{"alg": "RS256", "x5c": encoded})

	retrievers, err := ValidateHeader(context.Background(), head, nil, &model.JoseOptions{X509Roots: roots})
	if err == nil && len(retrievers) > 0 {
		for _, retrieve := range retrievers {
			if keys, rerr := retrieve(); rerr == nil && len(keys) > 0 {
				t.Fatal("[RFC 7515 4.1.6] a chain that does not reach a configured trust anchor must not yield a key, so a self-signed chain cannot vouch for itself")
			}
		}
	}
}

func generateCertificateChainOnly(t *testing.T, numCerts int) ([][]byte, error) {
	t.Helper()
	certs, _, err := generateCertificateChain(t, numCerts)
	return certs, err
}
