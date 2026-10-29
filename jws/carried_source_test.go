package jws_test

import (
	"context"
	"encoding/base64"
	"errors"
	"maps"
	"testing"

	"github.com/MichaelFraser99/go-jose/joseerror"
	"github.com/MichaelFraser99/go-jose/jwk"
	"github.com/MichaelFraser99/go-jose/jws"
	"github.com/MichaelFraser99/go-jose/model"
)

func TestVerifyCompactSerialization_AKeyTheTokenCarriesThatCannotBeUsedRefusesTheToken(t *testing.T) {
	keys := newRemoteKeys(t)
	jku := servingBody(t, keys.jwks)
	carried, err := jwk.PublicJwk(&keys.signingKey.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	x, err := base64.RawURLEncoding.DecodeString((*carried)["x"].(string))
	if err != nil {
		t.Fatal(err)
	}
	with := func(member string, value any) map[string]any {
		altered := maps.Clone(*carried)
		altered[member] = value
		return altered
	}

	tests := map[string]map[string]any{
		"an x that is not base64url": with("x", "!!!"),
		"an x one octet short":       with("x", base64.RawURLEncoding.EncodeToString(x[1:])),
		"a crv this library lacks":   with("crv", "P-999"),
	}
	for name, inline := range tests {
		t.Run(name, func(t *testing.T) {
			token := es256Token(t, keys.signingKey, map[string]any{"jwk": inline, "jku": jku.URL})
			opts := &model.JoseOptions{UseTokenProvidedKeys: true, HttpClient: jku.Client()}
			if _, _, err := jws.VerifyCompactSerialization(context.Background(), token, nil, opts); err == nil {
				t.Errorf("[RFC 7515 4.1.3] a jwk with %s is in the signed header and cannot be used every time, so it must refuse the token rather than give way to the jku", name)
			}
		})
	}
}

func TestVerifyCompactSerialization_AKeyTheTokenCarriesThatIsNotSelectedGivesWay(t *testing.T) {
	keys := newRemoteKeys(t)
	jku := servingBody(t, keys.jwks)
	carried, err := jwk.PublicJwk(&p256Key(t).PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	(*carried)["kid"] = "another"
	served, err := jwk.PublicJwk(&keys.signingKey.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	unanchored := leaf(t, p256Key(t), rootCA(t, p256Key(t)))

	tests := map[string]map[string]any{
		"a jwk whose kid differs from the header's":    {"jwk": *carried, "kid": (*served)["kid"], "jku": jku.URL},
		"an x5c chain that reaches no configured root": {"x5c": []string{der64(unanchored)}, "jku": jku.URL},
	}
	for name, head := range tests {
		t.Run(name, func(t *testing.T) {
			token := es256Token(t, keys.signingKey, head)
			opts := &model.JoseOptions{UseTokenProvidedKeys: true, HttpClient: jku.Client(), X509Roots: roots(keys.root)}
			_, _, err := jws.VerifyCompactSerialization(context.Background(), token, nil, opts)
			if err != nil && !errors.Is(err, joseerror.ErrNoKeyIdentifierMatch) {
				t.Fatalf("unexpected error class: %v", err)
			}
			if err != nil {
				t.Errorf("[RFC 7515 4.1.4, 4.1.6] %s selects no key, which is not a fault in the key, so the jku's key must still verify the token, got %v", name, err)
			}
		})
	}
}
