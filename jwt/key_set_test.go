package jwt

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/MichaelFraser99/go-jose/joseerror"
	"github.com/MichaelFraser99/go-jose/jwa"
	"github.com/MichaelFraser99/go-jose/jwk"
	"github.com/MichaelFraser99/go-jose/jws"
	"github.com/MichaelFraser99/go-jose/model"
)

func keySetJWT(t *testing.T, kid string) (string, map[string]any) {
	t.Helper()
	signer, err := jws.GetSigner(jwa.ES256, nil)
	if err != nil {
		t.Fatal(err)
	}
	token, err := New(signer, map[string]any{"typ": "JWT", "kid": kid}, map[string]any{"sub": "alice"}, Opts{})
	if err != nil {
		t.Fatal(err)
	}
	member, err := jwk.PublicJwk(signer.Public())
	if err != nil {
		t.Fatal(err)
	}
	(*member)["kid"] = kid
	return *token, *member
}

func TestValidate_KeySetVerifiesASignedAndANestedJWT(t *testing.T) {
	signed, member := keySetJWT(t, "issuer-key")
	_, other := keySetJWT(t, "other-key")
	r := recipientFor(t, jwa.RSAOAEP256)
	nested, err := Encrypt(r.encrypter, jwa.A128GCM, signed, nil)
	if err != nil {
		t.Fatal(err)
	}

	tests := map[string]struct {
		token      string
		decrypters []model.Decrypter
	}{
		"signed with no decrypters":     {token: signed},
		"signed with decrypters":        {token: signed, decrypters: []model.Decrypter{r.decrypter}},
		"nested inside an RSA-OAEP JWE": {token: nested, decrypters: []model.Decrypter{r.decrypter}},
	}
	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			opts := &model.JoseOptions{KeySet: &model.Jwks{Keys: []map[string]any{other, member}}, MaxKeysTried: 1}
			validated, err := Validate(context.Background(), tc.token, nil, tc.decrypters, opts, nil)
			if err != nil {
				t.Fatalf("[RFC 7519 7.2] the member of the caller's key set the kid names must verify the JWT, got %v", err)
			}
			if validated.Claims["sub"] != "alice" || validated.SignatureHeader["kid"] != "issuer-key" {
				t.Errorf("[RFC 7519 7.2] want the signed claims and header, got %+v", validated)
			}

			opts = &model.JoseOptions{KeySet: &model.Jwks{Keys: []map[string]any{other}}}
			_, err = Validate(context.Background(), tc.token, nil, tc.decrypters, opts, nil)
			if errors.Is(err, joseerror.ErrInvalidOptions) || !errors.Is(err, joseerror.ErrInvalidSignature) || !errors.Is(err, joseerror.ErrNoKeyIdentifierMatch) {
				t.Fatalf("[RFC 7515 4.1.4] a JWT the key set holds no key for is an invalid signature matching ErrNoKeyIdentifierMatch, got %v", err)
			}
			if strings.Contains(err.Error(), "only a key the token names") {
				t.Errorf("[JoseOptions.KeySet] with a key set, the refusal must not say that only a key the token names can pass, got %v", err)
			}
		})
	}
}
