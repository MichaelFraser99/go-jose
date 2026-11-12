package jws_test

import (
	"context"
	"encoding/base64"
	"errors"
	"testing"

	"github.com/MichaelFraser99/go-jose/joseerror"
	"github.com/MichaelFraser99/go-jose/jwa"
	"github.com/MichaelFraser99/go-jose/jws"
	"github.com/MichaelFraser99/go-jose/model"
)

func TestVerifyCompactSerialization_AnX5cWithoutRootsContributesNoKey(t *testing.T) {
	signingKey := p256Key(t)
	root := rootCA(t, p256Key(t))
	chain := []string{base64.StdEncoding.EncodeToString(leaf(t, signingKey, root).cert.Raw)}
	token := signWithX5c(t, jwa.ES256, signingKey, chain)

	tests := map[string]struct {
		retriever model.Retriever
		opts      *model.JoseOptions
		want      error
		reason    string
	}{
		"the caller's retriever verifies": {
			retriever: retrieving(&signingKey.PublicKey),
			want:      nil,
			reason:    "another key source verifies the token",
		},
		"the caller's retriever holds another key": {
			retriever: retrieving(&p256Key(t).PublicKey),
			want:      joseerror.ErrInvalidSignature,
			reason:    "the retriever's keys were tried and none verified",
		},
		"no retriever and no token keys allowed": {
			want:   joseerror.ErrInvalidOptions,
			reason: "no key source can exist",
		},
		"no retriever and UseTokenProvidedKeys on": {
			opts:   &model.JoseOptions{UseTokenProvidedKeys: true},
			want:   joseerror.ErrNoKeyIdentifierMatch,
			reason: "the token names no key this verifier may use",
		},
	}
	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			_, _, err := jws.VerifyCompactSerialization(context.Background(), token, tc.retriever, tc.opts)
			if tc.want == nil && err != nil || tc.want != nil && !errors.Is(err, tc.want) {
				t.Errorf("[RFC 7515 4.1.6] with no X509Roots an x5c contributes no key, and %s, so the result must be %v, got %v", tc.reason, tc.want, err)
			}
			if errors.Is(err, joseerror.ErrMalformedToken) {
				t.Errorf("[RFC 7515 4.1.6] the header is well formed, so the result must not be ErrMalformedToken, got %v", err)
			}
		})
	}
}
