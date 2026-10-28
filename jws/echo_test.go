package jws

import (
	"crypto/rand"
	"crypto/rsa"
	"strings"
	"testing"

	"github.com/MichaelFraser99/go-jose/internal/algorithms/common"
	"github.com/MichaelFraser99/go-jose/internal/jose/jsonutils"
	"github.com/MichaelFraser99/go-jose/jwa"
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
