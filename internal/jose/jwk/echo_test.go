package jwk

import (
	"crypto/rand"
	"crypto/rsa"
	"strings"
	"testing"

	"github.com/MichaelFraser99/go-jose/internal/algorithms/common"
	"github.com/MichaelFraser99/go-jose/internal/jose/jsonutils"
)

func TestInlineJWK_ARefusedUseIsEchoedQuotedAndBounded(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	jwk, err := common.JwkFromRSAPublicKey(&key.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	jwk["use"] = strings.Repeat("e", 1000) + "\r\nforged log line"

	_, err = InlineJWK(jwk, nil, "RS256", false)()
	if err == nil {
		t.Fatal("[RFC 7517 4.2] a key whose use is not sig must not verify")
	}
	if strings.ContainsAny(err.Error(), "\r\n") {
		t.Errorf("a peer's value must be quoted, so a line break cannot reach a log, got %q", err.Error())
	}
	if !strings.Contains(err.Error(), jsonutils.QuoteBounded(jwk["use"].(string))) {
		t.Errorf("a peer's value must be echoed through QuoteBounded, capped at %d runes, got %q", jsonutils.MaxEchoedRunes, err.Error())
	}
}
