package jws_test

import (
	"context"
	"errors"
	"testing"

	"github.com/MichaelFraser99/go-jose/joseerror"
	"github.com/MichaelFraser99/go-jose/jwk"
	"github.com/MichaelFraser99/go-jose/jws"
	"github.com/MichaelFraser99/go-jose/model"
)

func TestVerifyCompactSerialization_AMalformedKeyTheTokenCarriesStopsVerification(t *testing.T) {
	keys := newRemoteKeys(t)
	jku := servingBody(t, keys.jwks)

	malformedJwk, err := jwk.PublicJwk(&keys.signingKey.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	(*malformedJwk)["kid"] = 5

	unrelated := leaf(t, p256Key(t), rootCA(t, p256Key(t)))
	signer := leaf(t, keys.signingKey, keys.root)

	tests := map[string]map[string]any{
		"a jwk whose kid is a number":                     {"jwk": *malformedJwk, "jku": jku.URL},
		"an x5c whose second entry is no CA of the first": {"x5c": []string{der64(signer), der64(unrelated)}, "jku": jku.URL},
	}
	for name, head := range tests {
		t.Run(name, func(t *testing.T) {
			token := es256Token(t, keys.signingKey, head)
			opts := &model.JoseOptions{UseTokenProvidedKeys: true, X509Roots: roots(keys.root), HttpClient: jku.Client()}
			_, _, err := jws.VerifyCompactSerialization(context.Background(), token, nil, opts)
			if !errors.Is(err, joseerror.ErrMalformedClaim) {
				t.Errorf("[RFC 7515 4.1.3, 4.1.6] %s is wrong in the signed header itself, every time, so it must refuse the token with ErrMalformedClaim rather than give way to the jku, got %v", name, err)
			}
		})
	}
}

func TestVerifyCompactSerialization_ACallersRetrieverReportingAMalformedClaimGivesWay(t *testing.T) {
	keys := newRemoteKeys(t)
	jku := servingBody(t, keys.jwks)
	token := es256Token(t, keys.signingKey, map[string]any{"jku": jku.URL})
	opts := &model.JoseOptions{UseTokenProvidedKeys: true, HttpClient: jku.Client()}

	_, _, err := jws.VerifyCompactSerialization(context.Background(), token, retrieverFailingWith(joseerror.ErrMalformedClaim), opts)
	if err != nil {
		t.Errorf("[JoseOptions.UseTokenProvidedKeys] the caller's own retriever failing says nothing about the token, so the token's jku must still be tried, got %v", err)
	}
}
