package jws_test

import (
	"context"
	"crypto"
	"encoding/base64"
	"errors"
	"strings"
	"testing"

	"github.com/MichaelFraser99/go-jose/joseerror"
	"github.com/MichaelFraser99/go-jose/jwa"
	"github.com/MichaelFraser99/go-jose/jws"
	"github.com/MichaelFraser99/go-jose/model"
)

const maxBoundedErrorBytes = 512

var millionDigits = strings.Repeat("9", 1_000_000)

func noKeys() ([]crypto.PublicKey, error) { return nil, nil }

func assertBoundedEcho(t *testing.T, err error, want ...error) {
	t.Helper()
	if err == nil {
		t.Fatal("[RFC 8259 6] a number beyond the float64 range must be refused")
	}
	for _, sentinel := range want {
		if !errors.Is(err, sentinel) {
			t.Errorf("the refusal must still match %q, got %q", sentinel, err)
		}
	}
	if len(err.Error()) > maxBoundedErrorBytes || strings.Contains(err.Error(), strings.Repeat("9", 100)) {
		t.Errorf("a decoder error must echo a bounded prefix of the peer's octets, got %d bytes", len(err.Error()))
	}
}

func TestVerify_ADecoderErrorEchoesABoundedPrefixOfTheToken(t *testing.T) {
	b64 := func(s string) string { return base64.RawURLEncoding.EncodeToString([]byte(s)) }
	headerNumber := b64(`{"alg":"ES256","n":`+millionDigits+`}`) + "." + b64(`{}`) + ".AAAA"
	payloadNumber := b64(`{"alg":"ES256"}`) + "." + b64(`{"n":`+millionDigits+`}`) + ".AAAA"

	_, _, err := jws.Verify(context.Background(), headerNumber, noKeys, nil)
	assertBoundedEcho(t, err, joseerror.ErrMalformedToken)

	for name, token := range map[string]string{"a header": headerNumber, "a payload": payloadNumber} {
		t.Run(name, func(t *testing.T) {
			_, _, err := jws.VerifyCompactSerialization(context.Background(), token, noKeys, nil)
			assertBoundedEcho(t, err, joseerror.ErrMalformedToken)
		})
	}
}

func TestVerifyCompactSerialization_AJkuSetThatDoesNotDecodeIsEchoedBounded(t *testing.T) {
	keys := newRemoteKeys(t)
	server := servingBody(t, []byte(`{"keys":[{"kty":"EC","n":`+millionDigits+`}]}`))
	token := es256Token(t, keys.signingKey, map[string]any{"jku": server.URL})
	_, _, err := jws.VerifyCompactSerialization(context.Background(), token, nil, &model.JoseOptions{UseTokenProvidedKeys: true, HttpClient: server.Client(), AllowedSigningAlgorithms: []jwa.Algorithm{jwa.ES256}})
	assertBoundedEcho(t, err, joseerror.ErrApplicationError, joseerror.ErrKeystoreError)
}
