package jws

import (
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

func TestVerifyCompactSerialization_SettingOneOptionDoesNotDisableTheKeysATokenCarries(t *testing.T) {
	token := signedWithInlineJwk(t)

	tests := map[string]struct {
		reference string
		opts      *model.JoseOptions
		verifies  bool
	}{
		"no options at all": {
			reference: "the documented default", opts: nil, verifies: true,
		},
		"an empty options struct": {
			reference: "the documented default", opts: &model.JoseOptions{}, verifies: true,
		},
		"options set for an unrelated reason": {
			reference: "the documented default",
			opts:      &model.JoseOptions{X509Roots: x509.NewCertPool()},
			verifies:  true,
		},
		"options set to allow this algorithm": {
			reference: "the documented default",
			opts:      &model.JoseOptions{AllowedSigningAlgorithms: []jwa.Algorithm{jwa.RS256}},
			verifies:  true,
		},
		"options set to accept a type": {
			reference: "the documented default",
			opts:      &model.JoseOptions{AcceptedTypes: []string{"JWT"}},
			verifies:  true,
		},
		"the keys a token carries turned off explicitly": {
			reference: "opt out",
			opts:      &model.JoseOptions{IgnoreTokenProvidedKeys: true},
		},
		"turned off alongside another option": {
			reference: "opt out",
			opts:      &model.JoseOptions{IgnoreTokenProvidedKeys: true, X509Roots: x509.NewCertPool()},
		},
	}

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			_, _, err := VerifyCompactSerialization(token, nil, tc.opts)
			if tc.verifies {
				if err != nil {
					t.Errorf("[%s] a key the token carries is used unless the caller opts out, so setting an unrelated option must not silently disable it, got %v", tc.reference, err)
				}
				return
			}
			if err == nil {
				t.Errorf("[%s] a caller who opted out must not have the token's own key used", tc.reference)
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
		_, _, err := VerifyCompactSerialization(token, nil, &model.JoseOptions{HttpClient: server.Client()})
		if err != nil {
			t.Fatalf("[RFC 7515 4.1.2] a jku names where the key set lives, so a caller supplying a client must have it fetched, got %v", err)
		}
		if got := fetched.Load(); got == 0 {
			t.Error("the key set was never fetched")
		}
	})

	t.Run("with no client configured", func(t *testing.T) {
		_, _, err := VerifyCompactSerialization(token, nil, nil)
		if err == nil {
			t.Fatal("[RFC 7515 4.1.2] with no client the key set cannot be fetched, so the token must not verify")
		}
	})
}
