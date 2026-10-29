package jws

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"errors"
	"strconv"
	"strings"
	"testing"

	"github.com/MichaelFraser99/go-jose/internal/algorithms/common"
	"github.com/MichaelFraser99/go-jose/internal/jose/jsonutils"
	"github.com/MichaelFraser99/go-jose/joseerror"
	"github.com/MichaelFraser99/go-jose/jwa"
	"github.com/MichaelFraser99/go-jose/model"
)

func TestGetValidatorFromJwk_ARefusedAlgIsEchoedQuotedAndBounded(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	long := strings.Repeat("A", 1000) + "\r\nforged log line"

	tests := map[string]struct {
		alg      any
		mustHave string
	}{
		"a long string": {alg: long, mustHave: jsonutils.QuoteBounded(long)},
		"a large array": {alg: []any{strings.Repeat("A", 1000), strings.Repeat("B", 1000)}, mustHave: "not a string"},
		"an object":     {alg: map[string]any{"x": strings.Repeat("A", 1000)}, mustHave: "not a string"},
	}

	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			jwk, err := common.JwkFromRSAPublicKey(&key.PublicKey)
			if err != nil {
				t.Fatal(err)
			}
			jwk["alg"] = test.alg

			_, err = GetValidatorFromJwk(jwa.RS256, jwk)
			if err == nil {
				t.Fatal("[RFC 8725 3.1] a jwk whose alg is not RS256 must not build an RS256 validator")
			}
			if strings.ContainsAny(err.Error(), "\r\n") || len(err.Error()) > 300 {
				t.Errorf("a peer's value must be quoted and capped, got %d bytes: %q", len(err.Error()), err.Error())
			}
			if !strings.Contains(err.Error(), test.mustHave) {
				t.Errorf("expected the error to contain %q, got %q", test.mustHave, err.Error())
			}
		})
	}
}

func TestVerify_AnAlgTheOptionsDoNotAllowIsEchoedInDoubleQuotes(t *testing.T) {
	signer, err := GetSigner(jwa.ES256, nil)
	if err != nil {
		t.Fatal(err)
	}
	head := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"ES256"}`))
	input := head + "." + base64.RawURLEncoding.EncodeToString([]byte(`{}`))
	signature, err := signer.Sign(rand.Reader, []byte(input), nil)
	if err != nil {
		t.Fatal(err)
	}
	token := input + "." + base64.RawURLEncoding.EncodeToString(signature)

	_, _, err = Verify(context.Background(), token, func() ([]crypto.PublicKey, error) { return []crypto.PublicKey{signer.Public()}, nil }, &model.JoseOptions{AllowedSigningAlgorithms: []jwa.Algorithm{jwa.RS256}})
	if !errors.Is(err, joseerror.ErrUnsupportedAlgorithm) {
		t.Fatalf("[JoseOptions.AllowedSigningAlgorithms] an alg not allowed must be refused with ErrUnsupportedAlgorithm, got %v", err)
	}
	if !strings.Contains(err.Error(), strconv.Quote("ES256")) || strings.Contains(err.Error(), "'ES256'") {
		t.Errorf("a header value echoed in an error is double quoted, as every other header refusal does, got %q", err.Error())
	}
}
