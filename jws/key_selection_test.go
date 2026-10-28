package jws_test

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"math/big"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/MichaelFraser99/go-jose/jwa"
	"github.com/MichaelFraser99/go-jose/jws"
	"github.com/MichaelFraser99/go-jose/model"
)

func selectionJwk(public crypto.PublicKey, extra map[string]any) map[string]any {
	b64 := base64.RawURLEncoding.EncodeToString
	var jwk map[string]any
	switch k := public.(type) {
	case *ecdsa.PublicKey:
		jwk = map[string]any{"kty": "EC", "crv": "P-256", "x": b64(k.X.FillBytes(make([]byte, 32))), "y": b64(k.Y.FillBytes(make([]byte, 32)))}
	case *rsa.PublicKey:
		jwk = map[string]any{"kty": "RSA", "n": b64(k.N.Bytes()), "e": b64(big.NewInt(int64(k.E)).Bytes())}
	}
	for name, value := range extra {
		jwk[name] = value
	}
	return jwk
}

func selectionToken(t *testing.T, alg jwa.Algorithm, key crypto.PrivateKey, header map[string]any) string {
	t.Helper()
	header["alg"] = alg.String()
	head, err := json.Marshal(header)
	if err != nil {
		t.Fatal(err)
	}
	input := base64.RawURLEncoding.EncodeToString(head) + "." + base64.RawURLEncoding.EncodeToString([]byte(`{"sub":"attacker"}`))
	signer, err := jws.GetSignerFromPrivateKey(alg, key)
	if err != nil {
		t.Fatalf("failed to build a signer: %v", err)
	}
	signature, err := signer.Sign(rand.Reader, []byte(input), nil)
	if err != nil {
		t.Fatalf("failed to sign: %v", err)
	}
	return input + "." + base64.RawURLEncoding.EncodeToString(signature)
}

func TestVerifyCompactSerialization_SelectsAHeaderKeyByKidAlgAndUse(t *testing.T) {
	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	ecKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	tests := map[string]struct {
		jku          bool
		key          crypto.PrivateKey
		alg          jwa.Algorithm
		jwk          map[string]any
		kid          string
		ignoreKeyUse bool
		verifies     bool
		clause       string
	}{
		"a jku key published for RS256 does not verify a PS256 token": {
			jku: true, key: rsaKey, alg: jwa.PS256, jwk: map[string]any{"alg": "RS256", "kid": "k1"}, kid: "k1", clause: "RFC 8725 3.1",
		},
		"an inline key published for RS256 does not verify a PS256 token": {
			key: rsaKey, alg: jwa.PS256, jwk: map[string]any{"alg": "RS256"}, clause: "RFC 8725 3.1",
		},
		"a jku key whose kid differs from the header's does not verify": {
			jku: true, key: ecKey, alg: jwa.ES256, jwk: map[string]any{"kid": "issued"}, kid: "some-other-key", clause: "RFC 7515 4.1.4",
		},
		"a jku key with no kid or alg verifies a token naming a kid": {
			jku: true, key: ecKey, alg: jwa.ES256, jwk: map[string]any{}, kid: "k1", verifies: true, clause: "RFC 7517 4.5",
		},
		"a jku key marked use enc does not verify": {
			jku: true, key: ecKey, alg: jwa.ES256, jwk: map[string]any{"use": "enc"}, clause: "RFC 7517 4.2",
		},
		"an inline key whose key_ops lack verify does not verify": {
			key: ecKey, alg: jwa.ES256, jwk: map[string]any{"key_ops": []any{"encrypt"}}, clause: "RFC 7517 4.3",
		},
		"a jku key marked use enc verifies when key use is ignored": {
			jku: true, key: ecKey, alg: jwa.ES256, jwk: map[string]any{"use": "enc"}, ignoreKeyUse: true, verifies: true, clause: "RFC 7517 4.3",
		},
		"an inline key marked use enc verifies when key use is ignored": {
			key: ecKey, alg: jwa.ES256, jwk: map[string]any{"use": "enc", "key_ops": []any{"encrypt"}}, ignoreKeyUse: true, verifies: true, clause: "RFC 7517 4.3",
		},
	}

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			public := tc.key.(crypto.Signer).Public()
			jwk := selectionJwk(public, tc.jwk)
			header := map[string]any{}
			if tc.kid != "" {
				header["kid"] = tc.kid
			}
			opts := &model.JoseOptions{UseTokenProvidedKeys: true, IgnoreKeyUse: tc.ignoreKeyUse}
			if tc.jku {
				server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
					w.Header().Set("Content-Type", "application/json")
					if err := json.NewEncoder(w).Encode(map[string]any{"keys": []any{jwk}}); err != nil {
						return
					}
				}))
				defer server.Close()
				header["jku"] = server.URL
				opts.HttpClient = server.Client()
			} else {
				header["jwk"] = jwk
			}
			token := selectionToken(t, tc.alg, tc.key, header)

			_, _, err := jws.VerifyCompactSerialization(context.Background(), token, nil, opts)
			if tc.verifies && err != nil {
				t.Errorf("[%s] expected the token to verify, got %v", tc.clause, err)
			}
			if !tc.verifies && err == nil {
				t.Errorf("[%s] the header's key must not verify this token", tc.clause)
			}
		})
	}
}
