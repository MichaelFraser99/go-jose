package jwk

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/MichaelFraser99/go-jose/internal/algorithms/common"
	"github.com/MichaelFraser99/go-jose/internal/httputils"
	"github.com/MichaelFraser99/go-jose/joseerror"
	"github.com/MichaelFraser99/go-jose/model"
)

func serveKeySet(t *testing.T, keys ...map[string]any) *httptest.Server {
	t.Helper()
	raw, err := json.Marshal(model.Jwks{Keys: keys})
	if err != nil {
		t.Fatalf("failed to encode the key set: %v", err)
	}
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if _, err := w.Write(raw); err != nil {
			return
		}
	}))
	t.Cleanup(server.Close)
	return server
}

func usableRSAJwk(t *testing.T, kid string) (map[string]any, crypto.PublicKey) {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("failed to generate a key: %v", err)
	}
	jwk, err := common.JwkFromRSAPublicKey(&key.PublicKey)
	if err != nil {
		t.Fatalf("failed to build a jwk: %v", err)
	}
	jwk["kid"] = kid
	jwk["alg"] = "RS256"
	return jwk, &key.PublicKey
}

func unreadableMembers(kid string) map[string]map[string]any {
	return map[string]map[string]any{
		"a kty not understood":        {"kty": "nonsense", "kid": kid, "alg": "RS256"},
		"an RSA key missing n":        {"kty": "RSA", "kid": kid, "alg": "RS256", "e": "AQAB"},
		"an RSA key with a corrupt n": {"kty": "RSA", "kid": kid, "alg": "RS256", "n": "!!!", "e": "AQAB"},
		"an EC key missing x":         {"kty": "EC", "kid": kid, "alg": "RS256", "crv": "P-256", "y": "AA"},
		"an EC key on no known curve": {"kty": "EC", "kid": kid, "alg": "RS256", "crv": "P-999", "x": "AA", "y": "AA"},
		"a kty that is not a string":  {"kty": 7, "kid": kid, "alg": "RS256"},
	}
}

func TestRetrieveJKU_AMemberThatCannotBeReadIsSkipped(t *testing.T) {
	for name, unreadable := range unreadableMembers("shared") {
		t.Run(name, func(t *testing.T) {
			usable, want := usableRSAJwk(t, "shared")
			server := serveKeySet(t, unreadable, usable)

			kid := "shared"
			keys, err := RetrieveJKU(server.URL, httputils.Fetcher(context.Background(), server.Client(), 0), &kid, "RS256", false)()
			if err != nil {
				t.Fatalf("[RFC 7517 5] implementations SHOULD ignore a jwk they cannot use, so one unreadable member must not cost the set its usable key, got %v", err)
			}
			if len(keys) != 1 {
				t.Fatalf("[RFC 7517 5] expected only the usable key, got %d keys", len(keys))
			}
			if !want.(*rsa.PublicKey).Equal(keys[0]) {
				t.Error("[RFC 7517 5] the key returned must be the usable member of the set")
			}
		})
	}
}

func TestRetrieveJKU_ASetWithNoUsableMemberMatchesNoKey(t *testing.T) {
	members := make([]map[string]any, 0)
	for _, unreadable := range unreadableMembers("shared") {
		members = append(members, unreadable)
	}
	server := serveKeySet(t, members...)

	kid := "shared"
	keys, err := RetrieveJKU(server.URL, httputils.Fetcher(context.Background(), server.Client(), 0), &kid, "RS256", false)()
	if err == nil {
		t.Fatalf("[RFC 7517 5] a set whose every member is ignored yields no key, got %d keys", len(keys))
	}
	if !errors.Is(err, joseerror.ErrNoKeyIdentifierMatch) {
		t.Errorf("[RFC 7517 5] a set yielding no usable key must report that no key matched, so the next key source is tried, got %v", err)
	}
}
