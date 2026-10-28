package jws

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/MichaelFraser99/go-jose/jwa"
	"github.com/MichaelFraser99/go-jose/jwk"
	"github.com/MichaelFraser99/go-jose/model"
)

func TestAKeySetHoldingUnknownKeyTypesIsUsedForTheKeysItCanRead(t *testing.T) {
	signingKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	usable, err := jwk.PublicJwk(&signingKey.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	(*usable)["alg"] = "RS256"
	kid := (*usable)["kid"].(string)

	unknown := []map[string]any{
		{"kty": "AKP", "alg": "ML-DSA-65", "pub": "AQAB", "kid": "akp"},
		{"kty": "OKP", "crv": "X25519", "x": "hSDwCYkwp1R0i33ctD73Wg2_Og0mOBr066SpjqqbTmo", "kid": "x25519"},
		{"kty": "a-type-no-one-has-defined", "kid": "future"},
	}
	document, err := json.Marshal(map[string]any{"keys": append(unknown, *usable)})
	if err != nil {
		t.Fatal(err)
	}

	t.Run("decoding the set", func(t *testing.T) {
		var set model.Jwks
		if err := json.Unmarshal(document, &set); err != nil {
			t.Fatalf("[RFC 7517 5] a JWK Set holding key types this library does not understand must still decode, got %v", err)
		}
		if len(set.Keys) != 4 {
			t.Errorf("[RFC 7517 5] every member must be kept as decoded, got %d of 4", len(set.Keys))
		}
		keys, err := set.RetrieveByKeyID(kid)
		if err != nil || len(keys) != 1 {
			t.Errorf("[RFC 7517 4.5] the usable key must be found by its kid beside unknown types, got %d keys and %v", len(keys), err)
		}
	})

	t.Run("adding unknown types with unique kids enforced", func(t *testing.T) {
		set := model.Jwks{Opts: struct {
			EnforceUniqueKIDs bool
		}{EnforceUniqueKIDs: true}}
		for _, member := range append(unknown, *usable) {
			if err := set.Add(member); err != nil {
				t.Errorf("[RFC 7517 5] a key of a type this library does not understand must still be addable to a set, got %v for kty %v", err, member["kty"])
			}
		}
	})

	t.Run("verifying a token through a jku that serves the set", func(t *testing.T) {
		server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			if _, err := w.Write(document); err != nil {
				return
			}
		}))
		defer server.Close()

		signer, err := GetSignerFromPrivateKey(jwa.RS256, signingKey)
		if err != nil {
			t.Fatal(err)
		}
		head, err := json.Marshal(map[string]any{"alg": "RS256", "jku": server.URL})
		if err != nil {
			t.Fatal(err)
		}
		input := base64.RawURLEncoding.EncodeToString(head) + "." + base64.RawURLEncoding.EncodeToString([]byte(`{"sub":"test"}`))
		signature, err := signer.Sign(rand.Reader, []byte(input), nil)
		if err != nil {
			t.Fatal(err)
		}
		token := input + "." + base64.RawURLEncoding.EncodeToString(signature)

		if _, _, err := VerifyCompactSerialization(context.Background(), token, nil, &model.JoseOptions{UseTokenProvidedKeys: true, HttpClient: server.Client()}); err != nil {
			t.Errorf("[RFC 7517 5] implementations SHOULD ignore JWKs whose kty they do not understand, so the set's usable key must verify the token, got %v", err)
		}
	})
}
