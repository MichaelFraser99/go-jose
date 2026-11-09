package jws

import (
	"context"
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
	"errors"
	"testing"

	"github.com/MichaelFraser99/go-jose/joseerror"
	"github.com/MichaelFraser99/go-jose/jwa"
	"github.com/MichaelFraser99/go-jose/model"
)

func signedToken(t *testing.T, signer model.Signer) string {
	t.Helper()
	input := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"ES256"}`)) + "." + base64.RawURLEncoding.EncodeToString([]byte(`{"sub":"a"}`))
	signature, err := signer.Sign(rand.Reader, []byte(input), nil)
	if err != nil {
		t.Fatal(err)
	}
	return input + "." + base64.RawURLEncoding.EncodeToString(signature)
}

func TestVerify_AVerifierWithNoKeySourceIsAConfigurationFault(t *testing.T) {
	signer, err := GetSigner(jwa.ES256, nil)
	if err != nil {
		t.Fatal(err)
	}
	signed := signedToken(t, signer)
	inline := signedWithInlineJwk(t)
	for _, c := range []struct {
		name      string
		token     string
		opts      *model.JoseOptions
		want      error
		notWanted error
		clause    string
	}{
		{name: "no retriever and no options", token: signed, want: joseerror.ErrInvalidOptions, notWanted: joseerror.ErrMalformedToken, clause: "RFC 7515 5.2 step 8"},
		{name: "no retriever and options that allow no token key", token: signed, opts: &model.JoseOptions{AllowedSigningAlgorithms: []jwa.Algorithm{jwa.ES256}}, want: joseerror.ErrInvalidOptions, notWanted: joseerror.ErrMalformedToken, clause: "RFC 7515 5.2 step 8"},
		{name: "no retriever, and a token whose jwk the options do not allow", token: inline, want: joseerror.ErrInvalidOptions, notWanted: joseerror.ErrMalformedToken, clause: "RFC 7515 10.3"},
		{name: "token keys allowed, and a token naming none", token: signed, opts: &model.JoseOptions{UseTokenProvidedKeys: true}, want: joseerror.ErrNoKeyIdentifierMatch, notWanted: joseerror.ErrInvalidOptions, clause: "RFC 7515 4.1.4"},
		{name: "trust anchors set, and a token naming no certificate", token: signed, opts: &model.JoseOptions{X509Roots: x509.NewCertPool()}, want: joseerror.ErrNoKeyIdentifierMatch, notWanted: joseerror.ErrInvalidOptions, clause: "RFC 7515 4.1.6"},
	} {
		t.Run(c.name, func(t *testing.T) {
			head, payload, err := Verify(context.Background(), c.token, nil, c.opts)
			if !errors.Is(err, c.want) || errors.Is(err, c.notWanted) || head != nil || payload != nil {
				t.Errorf("[%s] want %v and not %v, got %v", c.clause, c.want, c.notWanted, err)
			}
		})
	}
	if _, _, err := Verify(context.Background(), inline, nil, &model.JoseOptions{UseTokenProvidedKeys: true}); err != nil {
		t.Errorf("[RFC 7515 4.1.3] with token keys allowed, a token carrying its own jwk must verify with no retriever, got %v", err)
	}
}
