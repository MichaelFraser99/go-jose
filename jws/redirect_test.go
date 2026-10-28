package jws

import (
	"context"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"

	"github.com/MichaelFraser99/go-jose/internal/algorithms/common"
	"github.com/MichaelFraser99/go-jose/model"
)

func TestVerifyCompactSerialization_ARemoteKeyServedInClearAfterARedirectIsRefused(t *testing.T) {
	rootKey, leafKey := p256(t), p256(t)
	root := certificate(t, "root", rootKey, nil, nil)
	leaf := certificate(t, "leaf", leafKey, root, rootKey)
	roots := x509.NewCertPool()
	roots.AddCert(root)

	keySet, err := json.Marshal(map[string]any{"keys": []any{mustJwk(t)(common.JwkFromECDSAPublicKey(&leafKey.PublicKey))}})
	if err != nil {
		t.Fatal(err)
	}

	tests := map[string]struct {
		reference string
		header    string
		body      []byte
		opts      func(client *http.Client) *model.JoseOptions
	}{
		"a jku": {
			reference: "RFC 7515 4.1.2",
			header:    "jku",
			body:      keySet,
			opts: func(client *http.Client) *model.JoseOptions {
				return &model.JoseOptions{UseTokenProvidedKeys: true, HttpClient: client}
			},
		},
		"an x5u": {
			reference: "RFC 7515 4.1.5",
			header:    "x5u",
			body:      pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: leaf.Raw}),
			opts: func(client *http.Client) *model.JoseOptions {
				return &model.JoseOptions{X509Roots: roots, HttpClient: client}
			},
		},
	}

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			var plainHits atomic.Int64
			plain := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				plainHits.Add(1)
				if _, err := w.Write(tc.body); err != nil {
					return
				}
			}))
			defer plain.Close()
			secure := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				http.Redirect(w, r, plain.URL, http.StatusFound)
			}))
			defer secure.Close()

			token := es256Token(t, leafKey, map[string]any{tc.header: secure.URL})
			if _, _, err := VerifyCompactSerialization(context.Background(), token, nil, tc.opts(secure.Client())); err == nil {
				t.Errorf("[%s] an HTTP GET to retrieve the resource MUST use TLS, so %s redirected to plain http must yield no key", tc.reference, name)
			}
			if got := plainHits.Load(); got != 0 {
				t.Errorf("[%s] the redirected request must not be sent in clear, but the plain http server saw %d", tc.reference, got)
			}
		})
	}
}
