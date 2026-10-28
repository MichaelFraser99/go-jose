package jws

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/MichaelFraser99/go-jose/jwa"
	"github.com/MichaelFraser99/go-jose/model"
)

func TestVerifyCompactSerialization_AStallingRemoteHeaderCannotHoldVerificationOpen(t *testing.T) {
	bounds := map[string]struct {
		fetchTimeout time.Duration
		ctxTimeout   time.Duration
		reference    string
	}{
		"bounded by FetchTimeout":     {fetchTimeout: 100 * time.Millisecond, ctxTimeout: time.Hour, reference: "JoseOptions.FetchTimeout"},
		"bounded by the caller's ctx": {fetchTimeout: time.Hour, ctxTimeout: 100 * time.Millisecond, reference: "the ctx passed to VerifyCompactSerialization"},
	}

	for _, header := range []string{"jku", "x5u"} {
		for name, bound := range bounds {
			t.Run(header+", "+name, func(t *testing.T) {
				token, client := stallingRemoteHeader(t, header)
				ctx, cancel := context.WithTimeout(context.Background(), bound.ctxTimeout)
				defer cancel()

				start := time.Now()
				_, _, err := VerifyCompactSerialization(ctx, token, nil, &model.JoseOptions{
					UseTokenProvidedKeys: true,
					HttpClient:           client,
					FetchTimeout:         bound.fetchTimeout,
					X509Roots:            x509.NewCertPool(),
				})
				elapsed := time.Since(start)

				if err == nil {
					t.Fatalf("a %s resource that never finishes arriving yields no key, so the token must not verify", header)
				}
				if elapsed > 2*time.Second {
					t.Errorf("[%s] a peer-chosen %s must not hold verification open past the bound, took %v", bound.reference, header, elapsed)
				}
				if !errors.Is(err, context.DeadlineExceeded) {
					t.Errorf("[%s] a fetch cut off by its bound must match context.DeadlineExceeded, got %v", bound.reference, err)
				}
			})
		}
	}
}

func stallingRemoteHeader(t *testing.T, header string) (string, *http.Client) {
	t.Helper()
	release := make(chan struct{})
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		if _, err := w.Write([]byte(`{"keys":[`)); err != nil {
			return
		}
		w.(http.Flusher).Flush()
		select {
		case <-r.Context().Done():
		case <-release:
		}
	}))
	t.Cleanup(func() {
		close(release)
		server.Close()
	})

	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	signer, err := GetSignerFromPrivateKey(jwa.RS256, key)
	if err != nil {
		t.Fatal(err)
	}
	head, err := json.Marshal(map[string]any{"alg": "RS256", header: server.URL})
	if err != nil {
		t.Fatal(err)
	}
	input := base64.RawURLEncoding.EncodeToString(head) + "." + base64.RawURLEncoding.EncodeToString([]byte(`{}`))
	signature, err := signer.Sign(rand.Reader, []byte(input), nil)
	if err != nil {
		t.Fatal(err)
	}

	client := server.Client()
	client.Timeout = 0
	return input + "." + base64.RawURLEncoding.EncodeToString(signature), client
}
