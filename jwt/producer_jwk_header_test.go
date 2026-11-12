package jwt

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"maps"
	"testing"

	"github.com/MichaelFraser99/go-jose/internal/algorithms/es256"
	"github.com/MichaelFraser99/go-jose/joseerror"
	"github.com/MichaelFraser99/go-jose/jwa"
	"github.com/MichaelFraser99/go-jose/jwk"
	"github.com/MichaelFraser99/go-jose/model"
)

func TestNew_RefusesAJwkHeaderThatValidateRefusesAsMalformed(t *testing.T) {
	signer, err := es256.NewSigner()
	if err != nil {
		t.Fatal(err)
	}
	public, err := jwk.PublicJwk(signer.Public())
	if err != nil {
		t.Fatal(err)
	}
	carrying := func(members map[string]any) map[string]any {
		key := maps.Clone(*public)
		delete(key, "kid")
		for name, value := range members {
			key[name] = value
		}
		return key
	}

	tests := map[string]struct {
		members map[string]any
		clause  string
	}{
		"a kid that is a number":                {members: map[string]any{"kid": 123}, clause: "RFC 7517 4.5"},
		"an alg that is a number":               {members: map[string]any{"alg": 256}, clause: "RFC 7517 4.4"},
		"a use that is a number":                {members: map[string]any{"use": 1}, clause: "RFC 7517 4.2"},
		"a key_ops that is a string":            {members: map[string]any{"key_ops": "verify"}, clause: "RFC 7517 4.3"},
		"a key_ops holding a number":            {members: map[string]any{"key_ops": []any{"verify", 1}}, clause: "RFC 7517 4.3"},
		"a key_ops listing verify twice":        {members: map[string]any{"key_ops": []any{"verify", "verify"}}, clause: "RFC 7517 4.3"},
		"a use of sig beside key_ops encrypt":   {members: map[string]any{"use": "sig", "key_ops": []any{"encrypt"}}, clause: "RFC 7517 4.3"},
		"a use of sig beside verify and unwrap": {members: map[string]any{"use": "sig", "key_ops": []any{"verify", "unwrapKey"}}, clause: "RFC 7517 4.3"},
		"a use of enc beside key_ops verify":    {members: map[string]any{"use": "enc", "key_ops": []any{"verify"}}, clause: "RFC 7517 4.3"},
	}
	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			head := map[string]any{"jwk": carrying(tc.members)}

			token, err := New(signer, head, map[string]any{"sub": "a"}, Opts{})
			if !errors.Is(err, joseerror.ErrMalformedClaim) || token != nil {
				t.Errorf("[%s] New must not sign a jwk header that Validate refuses as malformed, got %v and %v", tc.clause, token, err)
			}

			head["alg"] = jwa.ES256.String()
			headBytes, err := json.Marshal(head)
			if err != nil {
				t.Fatal(err)
			}
			input := base64.RawURLEncoding.EncodeToString(headBytes) + "." + base64.RawURLEncoding.EncodeToString([]byte(`{"sub":"a"}`))
			signature, err := signer.Sign(rand.Reader, []byte(input), nil)
			if err != nil {
				t.Fatal(err)
			}
			handBuilt := input + "." + base64.RawURLEncoding.EncodeToString(signature)
			_, err = Validate(context.Background(), handBuilt, nil, nil, &model.JoseOptions{UseTokenProvidedKeys: true}, nil)
			if !errors.Is(err, joseerror.ErrMalformedClaim) || !errors.Is(err, joseerror.ErrMalformedToken) {
				t.Errorf("[%s] a jwk header that breaks RFC 7517 makes the header malformed, so Validate must refuse it with ErrMalformedToken and ErrMalformedClaim, got %v", tc.clause, err)
			}
		})
	}
}

func TestNew_SignsAJwkHeaderThatValidateAccepts(t *testing.T) {
	signer, err := es256.NewSigner()
	if err != nil {
		t.Fatal(err)
	}
	public, err := jwk.PublicJwk(signer.Public())
	if err != nil {
		t.Fatal(err)
	}
	for name, members := range map[string]map[string]any{
		"no use and no key_ops":            {},
		"a use of sig":                     {"use": "sig"},
		"a key_ops of verify":              {"key_ops": []any{"verify"}},
		"a use of sig beside verify":       {"use": "sig", "key_ops": []any{"verify"}},
		"a key_ops built as a Go []string": {"key_ops": []string{"sign", "verify"}},
	} {
		t.Run(name, func(t *testing.T) {
			key := maps.Clone(*public)
			for member, value := range members {
				key[member] = value
			}
			token, err := New(signer, map[string]any{"jwk": key}, map[string]any{"sub": "a"}, Opts{})
			if err != nil {
				t.Fatalf("[RFC 7517 4.3] a jwk header with %s keeps RFC 7517, so New must sign it, got %v", name, err)
			}
			if _, err := Validate(context.Background(), *token, nil, nil, &model.JoseOptions{UseTokenProvidedKeys: true}, nil); err != nil {
				t.Errorf("[RFC 7515 4.1.3] the token's own jwk must verify it, got %v", err)
			}
		})
	}
}
