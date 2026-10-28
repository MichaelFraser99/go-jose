package header

import (
	"crypto/x509"
	"testing"

	"github.com/MichaelFraser99/go-jose/model"
)

func TestValidateHeader_WithoutAClientTheRemoteHeadersYieldNoRetriever(t *testing.T) {
	tests := map[string]struct {
		head map[string]any
		opts *model.JoseOptions
	}{
		"jku": {
			head: map[string]any{"alg": "RS256", "jku": "https://example.com/jwks"},
			opts: &model.JoseOptions{UseTokenProvidedKeys: true},
		},
		"x5u": {
			head: map[string]any{"alg": "RS256", "x5u": "https://example.com/certs"},
			opts: &model.JoseOptions{X509Roots: x509.NewCertPool()},
		},
	}

	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			retrievers, err := ValidateHeader(jsonDecodedHeader(t, test.head), nil, model.JWS, test.opts)
			if err != nil {
				t.Fatalf("[JoseOptions.HttpClient] a well-formed header must not be refused merely because no client is configured, got %v", err)
			}
			if len(retrievers) != 0 {
				t.Errorf("[JoseOptions.HttpClient] with no client, %s contributes no key, so it must yield no retriever, got %d", name, len(retrievers))
			}
		})
	}
}
