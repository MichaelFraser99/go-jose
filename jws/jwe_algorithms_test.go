package jws_test

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"github.com/MichaelFraser99/go-jose/joseerror"
	"github.com/MichaelFraser99/go-jose/jwa"
	"github.com/MichaelFraser99/go-jose/jwk"
	"github.com/MichaelFraser99/go-jose/jws"
	"github.com/MichaelFraser99/go-jose/model"
)

var jweKeyManagementAlgorithms = []jwa.Algorithm{jwa.RSAOAEP, jwa.RSAOAEP256, jwa.RSAOAEP384, jwa.RSAOAEP512, jwa.A128KW, jwa.A192KW, jwa.A256KW, jwa.Dir}

func TestAJWEKeyManagementAlgorithmCannotSignOrVerifyAJWS(t *testing.T) {
	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	publicJwk, err := jwk.PublicJwk(&rsaKey.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	for _, alg := range jweKeyManagementAlgorithms {
		t.Run(alg.String(), func(t *testing.T) {
			if signer, err := jws.GetSigner(alg, &model.Opts{SecretKey: model.Pointer(make([]byte, 64))}); !errors.Is(err, joseerror.ErrUnsupportedAlgorithm) || signer != nil {
				t.Errorf("[RFC 7518 4.1] %s is a key management algorithm, not a signature, so GetSigner must refuse it, got %#v and %v", alg, signer, err)
			}
			if signer, err := jws.GetSignerFromPrivateKey(alg, rsaKey); !errors.Is(err, joseerror.ErrUnsupportedAlgorithm) || signer != nil {
				t.Errorf("[RFC 7518 4.1] GetSignerFromPrivateKey must refuse %s, got %#v and %v", alg, signer, err)
			}
			if validator, err := jws.GetValidator(alg, &rsaKey.PublicKey); !errors.Is(err, joseerror.ErrUnsupportedAlgorithm) || validator != nil {
				t.Errorf("[RFC 7518 4.1] GetValidator must refuse %s, got %#v and %v", alg, validator, err)
			}
			if validator, err := jws.GetValidatorFromJwk(alg, *publicJwk); !errors.Is(err, joseerror.ErrUnsupportedAlgorithm) || validator != nil {
				t.Errorf("[RFC 7518 4.1] GetValidatorFromJwk must refuse %s, got %#v and %v", alg, validator, err)
			}
			called := false
			retriever := func() ([]crypto.PublicKey, error) {
				called = true
				return []crypto.PublicKey{&rsaKey.PublicKey}, nil
			}
			token := signWithHeader(t, jwa.RS256, rsaKey, map[string]any{})
			forged := retag(t, token, alg.String())
			if _, _, err := jws.Verify(context.Background(), forged, retriever, nil); !errors.Is(err, joseerror.ErrUnsupportedAlgorithm) {
				t.Errorf("[RFC 7515 5.2] a JWS naming %s has no validator, so it must be refused with ErrUnsupportedAlgorithm, got %v", alg, err)
			}
			if called {
				t.Errorf("[RFC 7515 5.2 step 5] a JWS naming %s must be refused before any key is sought", alg)
			}
		})
	}
}

func retag(t *testing.T, token, alg string) string {
	t.Helper()
	segments := strings.Split(token, ".")
	raw, err := base64.RawURLEncoding.DecodeString(segments[0])
	if err != nil {
		t.Fatal(err)
	}
	var head map[string]any
	if err := json.Unmarshal(raw, &head); err != nil {
		t.Fatal(err)
	}
	head["alg"] = alg
	encoded, err := json.Marshal(head)
	if err != nil {
		t.Fatal(err)
	}
	segments[0] = base64.RawURLEncoding.EncodeToString(encoded)
	return strings.Join(segments, ".")
}
