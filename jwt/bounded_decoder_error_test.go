package jwt

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"strings"
	"testing"

	"github.com/MichaelFraser99/go-jose/internal/algorithms/es256"
	"github.com/MichaelFraser99/go-jose/joseerror"
	"github.com/MichaelFraser99/go-jose/jwa"
	"github.com/MichaelFraser99/go-jose/jwe"
	"github.com/MichaelFraser99/go-jose/model"
)

func TestValidate_ADecoderErrorEchoesABoundedPrefixOfEveryShape(t *testing.T) {
	shared := recipientFor(t, jwa.A128KW)
	signer, err := es256.NewSigner()
	if err != nil {
		t.Fatal(err)
	}
	b64 := func(s string) string { return base64.RawURLEncoding.EncodeToString([]byte(s)) }
	sign := func(head, payload string) string {
		input := b64(head) + "." + b64(payload)
		signature, err := signer.Sign(rand.Reader, []byte(input), nil)
		if err != nil {
			t.Fatal(err)
		}
		return input + "." + base64.RawURLEncoding.EncodeToString(signature)
	}
	encrypt := func(plaintext string, head map[string]any) string {
		token, err := jwe.Encrypt(shared.encrypter, jwa.A128GCM, []byte(plaintext), head)
		if err != nil {
			t.Fatal(err)
		}
		return token
	}
	huge := strings.Repeat("9", 1_000_000)
	headerNumber := sign(`{"alg":"ES256","n":`+huge+`}`, `{}`)
	payloadNumber := sign(`{"alg":"ES256"}`, `{"n":`+huge+`}`)

	for name, token := range map[string]string{
		"a signed JWT's header":        headerNumber,
		"a signed JWT's claims":        payloadNumber,
		"a JWE's header":               b64(`{"alg":"A128KW","enc":"A128GCM","n":`+huge+`}`) + ".AAAA.AAAA.AAAA.AAAA",
		"an encrypt-only JWT's claims": encrypt(`{"n":`+huge+`}`, nil),
		"a nested JWT's inner header":  encrypt(headerNumber, map[string]any{"cty": "JWT"}),
		"a nested JWT's inner claims":  encrypt(payloadNumber, map[string]any{"cty": "JWT"}),
	} {
		t.Run(name, func(t *testing.T) {
			_, err := Validate(context.Background(), token, newTestRetriever(signer.Public()), []model.Decrypter{shared.decrypter}, nil, nil)
			if !errors.Is(err, joseerror.ErrMalformedToken) {
				t.Fatalf("[RFC 8259 6] %s holding a number beyond the float64 range must be refused with ErrMalformedToken, got %v", name, err)
			}
			if len(err.Error()) > 512 || strings.Contains(err.Error(), strings.Repeat("9", 100)) {
				t.Errorf("the error for %s must echo a bounded prefix of the peer's octets, got %d bytes", name, len(err.Error()))
			}
		})
	}
}

func TestEncrypt_AHeaderDecoderErrorEchoesABoundedPrefix(t *testing.T) {
	shared := recipientFor(t, jwa.A128KW)
	head := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"ES256","n":` + strings.Repeat("9", 1_000_000) + `}`))
	_, err := Encrypt(shared.encrypter, jwa.A128GCM, head+".e30.AAAA", nil)
	if !errors.Is(err, joseerror.ErrMalformedToken) {
		t.Fatalf("[RFC 8259 6] a signed JWT whose header holds a number beyond the float64 range must be refused with ErrMalformedToken, got %v", err)
	}
	if len(err.Error()) > 512 || strings.Contains(err.Error(), strings.Repeat("9", 100)) {
		t.Errorf("the error must echo a bounded prefix of the header, got %d bytes", len(err.Error()))
	}
}
