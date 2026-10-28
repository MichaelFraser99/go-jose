package jws

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"errors"
	"testing"

	"github.com/MichaelFraser99/go-jose/joseerror"
	"github.com/MichaelFraser99/go-jose/jwa"
	"github.com/MichaelFraser99/go-jose/model"
)

func TestVerifyCompactSerialization_ARemoteHeaderWithoutAClientCannotTurnARefusalIntoAnApplicationError(t *testing.T) {
	signingKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("failed to generate a key: %v", err)
	}
	callersKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("failed to generate a key: %v", err)
	}
	signer, err := GetSignerFromPrivateKey(jwa.RS256, signingKey)
	if err != nil {
		t.Fatalf("failed to build a signer: %v", err)
	}

	tests := map[string]map[string]any{
		"jku": {"alg": "RS256", "jku": "https://example.com/jwks"},
		"x5u": {"alg": "RS256", "x5u": "https://example.com/certs"},
	}

	for name, head := range tests {
		t.Run(name, func(t *testing.T) {
			headBytes, err := json.Marshal(head)
			if err != nil {
				t.Fatalf("failed to encode the header: %v", err)
			}
			input := base64.RawURLEncoding.EncodeToString(headBytes) + "." + base64.RawURLEncoding.EncodeToString([]byte(`{"a":"b"}`))
			signature, err := signer.Sign(rand.Reader, []byte(input), nil)
			if err != nil {
				t.Fatalf("failed to sign: %v", err)
			}
			token := input + "." + base64.RawURLEncoding.EncodeToString(signature)

			callersRetriever := func() ([]crypto.PublicKey, error) { return []crypto.PublicKey{&callersKey.PublicKey}, nil }
			_, _, err = VerifyCompactSerialization(token, callersRetriever, &model.JoseOptions{X509Roots: x509.NewCertPool()})
			if err == nil {
				t.Fatal("a token signed by a key the caller does not hold must not verify")
			}
			if errors.Is(err, joseerror.ErrApplicationError) {
				t.Errorf("[JoseOptions.HttpClient] with no client, %s contributes no key, so naming one must not turn a bad signature into an application error, got %v", name, err)
			}
			if !errors.Is(err, joseerror.ErrInvalidSignature) {
				t.Errorf("the caller's key does not verify the token, so the refusal is an invalid signature, got %v", err)
			}
		})
	}
}
