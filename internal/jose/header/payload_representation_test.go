package header

import (
	"context"
	"errors"
	"testing"

	"github.com/MichaelFraser99/go-jose/joseerror"
	"github.com/MichaelFraser99/go-jose/model"
)

func TestNamesNestedJWT_ComparesCtyAsAMediaType(t *testing.T) {
	tests := map[string]struct {
		header map[string]any
		nested bool
	}{
		"JWT":                      {map[string]any{"cty": "JWT"}, true},
		"jwt":                      {map[string]any{"cty": "jwt"}, true},
		"application/JWT":          {map[string]any{"cty": "application/JWT"}, true},
		"APPLICATION/jwt":          {map[string]any{"cty": "APPLICATION/jwt"}, true},
		"no cty":                   {map[string]any{}, false},
		"cty of a number":          {map[string]any{"cty": 1}, false},
		"text/JWT":                 {map[string]any{"cty": "text/JWT"}, false},
		"example+jwt":              {map[string]any{"cty": "example+jwt"}, false},
		"JWT with a leading space": {map[string]any{"cty": " JWT"}, false},
	}
	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			if got := NamesNestedJWT(test.header); got != test.nested {
				t.Fatalf("[RFC 7515 4.1.10, RFC 7519 5.2] cty %v: nested = %t, want %t", test.header["cty"], got, test.nested)
			}
		})
	}
}

func TestValidateHeader_RefusesAnUnencodedPayloadWhateverTheCallerUnderstands(t *testing.T) {
	understood := &model.JoseOptions{UnderstoodCriticalHeaders: []string{"b64"}}
	tests := map[string]struct {
		header  map[string]any
		opts    *model.JoseOptions
		refused bool
	}{
		"b64 false, crit b64, caller lists b64": {map[string]any{"alg": "ES256", "b64": false, "crit": []any{"b64"}}, understood, true},
		"b64 false without crit":                {map[string]any{"alg": "ES256", "b64": false}, nil, true},
		"b64 true, crit b64, caller lists b64":  {map[string]any{"alg": "ES256", "b64": true, "crit": []any{"b64"}}, understood, false},
		"b64 true without crit":                 {map[string]any{"alg": "ES256", "b64": true}, nil, false},
	}
	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			_, err := ValidateHeader(context.Background(), test.header, nil, model.JWS, test.opts)
			if test.refused != errors.Is(err, joseerror.ErrMissingCriticalClaim) {
				t.Fatalf("[RFC 7797 3, 6, 8] header %v: refused = %t, want %t: %v", test.header, err != nil, test.refused, err)
			}
			if !test.refused && err != nil {
				t.Fatalf("[RFC 7797 3] header %v: %v", test.header, err)
			}
		})
	}
}
