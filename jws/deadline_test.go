package jws

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/MichaelFraser99/go-jose/jwa"
	"github.com/MichaelFraser99/go-jose/model"
)

func TestVerifyCompactSerialization_AStallingRemoteHeaderCannotHoldVerificationOpen(t *testing.T) {
	for _, header := range []string{"jku", "x5u"} {
		t.Run(header, func(t *testing.T) {
			stallingRemoteHeader(t, header)
		})
	}
}

func stallingRemoteHeader(t *testing.T, header string) {
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
	defer func() {
		close(release)
		server.Close()
	}()

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
	token := input + "." + base64.RawURLEncoding.EncodeToString(signature)

	client := server.Client()
	client.Timeout = 0

	start := time.Now()
	_, _, err = VerifyCompactSerialization(context.Background(), token, nil, &model.JoseOptions{
		UseTokenProvidedKeys: true,
		HttpClient:           client,
		FetchTimeout:         100 * time.Millisecond,
		X509Roots:            x509.NewCertPool(),
	})
	elapsed := time.Since(start)

	if err == nil {
		t.Fatalf("a %s resource that never finishes arriving yields no key, so the token must not verify", header)
	}
	if elapsed > 2*time.Second {
		t.Errorf("[JoseOptions.FetchTimeout] a peer-chosen %s must not hold verification open past the fetch timeout, took %v", header, elapsed)
	}
}
