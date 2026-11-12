package jwe

import (
	"encoding/base64"
	"errors"
	"strings"
	"testing"

	"github.com/MichaelFraser99/go-jose/joseerror"
	"github.com/MichaelFraser99/go-jose/jwa"
	"github.com/MichaelFraser99/go-jose/model"
)

func TestGetEncrypterFromJwk_ReadsAKeyOpsBuiltInGoAsAStringSlice(t *testing.T) {
	k := base64.RawURLEncoding.EncodeToString(make([]byte, 16))
	tests := map[string]struct {
		ops    any
		strict bool
		accept bool
		says   string
	}{
		"[]string of wrapKey":                    {ops: []string{"wrapKey"}, accept: true},
		"[]string of wrapKey and unwrapKey":      {ops: []string{"wrapKey", "unwrapKey"}, strict: true, accept: true},
		"[]string of sign":                       {ops: []string{"sign"}},
		"[]string listing wrapKey twice":         {ops: []string{"wrapKey", "wrapKey"}, says: "more than once"},
		"[]string of wrapKey and sign, strictly": {ops: []string{"wrapKey", "sign"}, strict: true},
		"[]int":                                  {ops: []int{1}, says: "array of strings"},
	}
	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			jwk := map[string]any{"kty": "oct", "k": k, "key_ops": tc.ops}
			encrypter, err := GetEncrypterFromJwk(jwa.A128KW, jwk, &model.JWEOptions{StrictKeyOperations: tc.strict})
			if tc.accept {
				if err != nil || encrypter == nil {
					t.Errorf("[RFC 7517 4.3] a key_ops of %s is an array of strings that permits wrapKey, so it must build an encrypter, got %v", name, err)
				}
				return
			}
			if !errors.Is(err, joseerror.ErrInvalidPublicKey) || encrypter != nil {
				t.Errorf("[RFC 7517 4.3] a key_ops of %s must be refused with ErrInvalidPublicKey, got %v and %v", name, encrypter, err)
			}
			if err != nil && !strings.Contains(err.Error(), tc.says) {
				t.Errorf("[RFC 7517 4.3] the refusal of a key_ops of %s must say it is malformed with %q, got %q", name, tc.says, err.Error())
			}
		})
	}
}
