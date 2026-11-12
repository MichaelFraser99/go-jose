package jwt

import (
	"context"
	"errors"
	"testing"

	"github.com/MichaelFraser99/go-jose/joseerror"
	"github.com/MichaelFraser99/go-jose/model"
)

func TestValidate_AnAllowedKeyURLsEntryNoHeaderCanMatchIsRefused(t *testing.T) {
	entries := map[string]string{
		"an empty entry":         "",
		"a relative reference":   "/jwks",
		"plain http":             "http://keys.example/jwks",
		"text that is not a URL": "not a url",
	}
	tokens := map[string]string{
		"a signed JWT shape":     "e30.e30.e30",
		"an encrypted JWT shape": "e30.e30.e30.e30.e30",
		"text that is not a JWT": "not-a-token",
	}
	for name, entry := range entries {
		for shape, token := range tokens {
			t.Run(name+" with "+shape, func(t *testing.T) {
				opts := &model.JoseOptions{UseTokenProvidedKeys: true, AllowedKeyURLs: []string{"https://keys.example/jwks", entry}}
				_, err := Validate(context.Background(), token, nil, nil, opts, nil)
				if !errors.Is(err, joseerror.ErrInvalidOptions) {
					t.Errorf("[RFC 7515 4.1.2, 4.1.5] a jku or x5u must be https, so the entry %q can match none and Validate must refuse every token with ErrInvalidOptions, got %v", entry, err)
				}
			})
		}
	}
}
