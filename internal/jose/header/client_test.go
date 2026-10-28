package header

import (
	"crypto/x509"
	"testing"

	"github.com/MichaelFraser99/go-jose/model"
)

func TestValidateHeader_WithoutAClientTheRemoteHeadersYieldNoRetriever(t *testing.T) {
	tests := map[string]map[string]any{
		"jku": {"alg": "RS256", "jku": "https://example.com/jwks"},
		"x5u": {"alg": "RS256", "x5u": "https://example.com/certs"},
	}

	for name, head := range tests {
		t.Run(name, func(t *testing.T) {
			opts := &model.JoseOptions{X509Roots: x509.NewCertPool()}
			retrievers, err := ValidateHeader(jsonDecodedHeader(t, head), nil, model.JWS, opts)
			if err != nil {
				t.Fatalf("[JoseOptions.HttpClient] a well-formed header must not be refused merely because no client is configured, got %v", err)
			}
			if len(retrievers) != 0 {
				t.Errorf("[JoseOptions.HttpClient] with no client, %s contributes no key, so it must yield no retriever, got %d", name, len(retrievers))
			}
		})
	}
}
