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
	"sync/atomic"
	"testing"

	"github.com/MichaelFraser99/go-jose/internal/algorithms/common"
	"github.com/MichaelFraser99/go-jose/jwa"
	"github.com/MichaelFraser99/go-jose/model"
)

func signedWithInlineJwk(t *testing.T) string {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("failed to generate a key: %v", err)
	}
	signer, err := GetSignerFromPrivateKey(jwa.RS256, key)
	if err != nil {
		t.Fatalf("failed to build a signer: %v", err)
	}

	head := map[string]any{"alg": "RS256", "typ": "JWT", "jwk": common.JwkFromRSAPublicKey(key.Public().(*rsa.PublicKey))}
	headBytes, err := json.Marshal(head)
	if err != nil {
		t.Fatalf("failed to encode the header: %v", err)
	}
	bodyBytes, err := json.Marshal(map[string]any{"a": "b"})
	if err != nil {
		t.Fatalf("failed to encode the body: %v", err)
	}

	input := base64.RawURLEncoding.EncodeToString(headBytes) + "." + base64.RawURLEncoding.EncodeToString(bodyBytes)
	signature, err := signer.Sign(rand.Reader, []byte(input), nil)
	if err != nil {
		t.Fatalf("failed to sign: %v", err)
	}
	return input + "." + base64.RawURLEncoding.EncodeToString(signature)
}

func TestVerifyCompactSerialization_ATokenCarriesNoTrustedKeyUnlessTheCallerOptsIn(t *testing.T) {
	token := signedWithInlineJwk(t)

	tests := map[string]struct {
		opts     *model.JoseOptions
		verifies bool
	}{
		"no options at all":                   {opts: nil},
		"an empty options struct":             {opts: &model.JoseOptions{}},
		"options set for an unrelated reason": {opts: &model.JoseOptions{X509Roots: x509.NewCertPool()}},
		"options set to allow this algorithm": {opts: &model.JoseOptions{AllowedSigningAlgorithms: []jwa.Algorithm{jwa.RS256}}},
		"options set to accept a type":        {opts: &model.JoseOptions{AcceptedTypes: []string{"JWT"}}},
		"the token's keys turned on":          {opts: &model.JoseOptions{UseTokenProvidedKeys: true}, verifies: true},
		"turned on alongside another option":  {opts: &model.JoseOptions{UseTokenProvidedKeys: true, AcceptedTypes: []string{"JWT"}}, verifies: true},
		"turned off explicitly":               {opts: &model.JoseOptions{UseTokenProvidedKeys: false}},
	}

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			_, _, err := VerifyCompactSerialization(context.Background(), token, nil, tc.opts)
			if tc.verifies {
				if err != nil {
					t.Errorf("[JoseOptions.UseTokenProvidedKeys] a caller who opted in must have the token's own key used, got %v", err)
				}
				return
			}
			if err == nil {
				t.Errorf("[RFC 7515 10.3] a key must be authenticated as belonging to the signer, and a token naming its own key authenticates nothing, so it must not verify unless the caller opts in")
			}
		})
	}
}

func TestVerifyCompactSerialization_AJkuIsFetchedWithTheConfiguredClient(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("failed to generate a key: %v", err)
	}
	publicJwk := common.JwkFromRSAPublicKey(key.Public().(*rsa.PublicKey))
	publicJwk["kid"] = "served"
	publicJwk["alg"] = "RS256"

	var fetched atomic.Int64
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		fetched.Add(1)
		w.Header().Set("Content-Type", "application/json")
		raw, err := json.Marshal(model.Jwks{Keys: []map[string]any{publicJwk}})
		if err != nil {
			return
		}
		if _, err := w.Write(raw); err != nil {
			return
		}
	}))
	defer server.Close()

	signer, err := GetSignerFromPrivateKey(jwa.RS256, key)
	if err != nil {
		t.Fatalf("failed to build a signer: %v", err)
	}
	head := map[string]any{"alg": "RS256", "kid": "served", "jku": server.URL}
	headBytes, err := json.Marshal(head)
	if err != nil {
		t.Fatalf("failed to encode the header: %v", err)
	}
	bodyBytes, err := json.Marshal(map[string]any{"a": "b"})
	if err != nil {
		t.Fatalf("failed to encode the body: %v", err)
	}
	input := base64.RawURLEncoding.EncodeToString(headBytes) + "." + base64.RawURLEncoding.EncodeToString(bodyBytes)
	signature, err := signer.Sign(rand.Reader, []byte(input), nil)
	if err != nil {
		t.Fatalf("failed to sign: %v", err)
	}
	token := input + "." + base64.RawURLEncoding.EncodeToString(signature)

	t.Run("with a client configured", func(t *testing.T) {
		_, _, err := VerifyCompactSerialization(context.Background(), token, nil, &model.JoseOptions{HttpClient: server.Client(), UseTokenProvidedKeys: true})
		if err != nil {
			t.Fatalf("[RFC 7515 4.1.2] a jku names where the key set lives, so a caller supplying a client must have it fetched, got %v", err)
		}
		if got := fetched.Load(); got == 0 {
			t.Error("the key set was never fetched")
		}
	})

	t.Run("with a client configured but the token's keys not opted in to", func(t *testing.T) {
		before := fetched.Load()
		_, _, err := VerifyCompactSerialization(context.Background(), token, nil, &model.JoseOptions{HttpClient: server.Client()})
		if err == nil {
			t.Error("[JoseOptions.UseTokenProvidedKeys] a jku is a key the token names for itself, so it must not verify the token unless the caller opts in")
		}
		if got := fetched.Load(); got != before {
			t.Error("[JoseOptions.UseTokenProvidedKeys] a caller who has not opted in must not have a peer-chosen URL fetched at all")
		}
	})

	t.Run("with no client configured", func(t *testing.T) {
		_, _, err := VerifyCompactSerialization(context.Background(), token, nil, &model.JoseOptions{UseTokenProvidedKeys: true})
		if err == nil {
			t.Fatal("[RFC 7515 4.1.2] with no client the key set cannot be fetched, so the token must not verify")
		}
	})
}
