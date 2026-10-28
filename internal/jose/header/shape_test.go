package header

import (
	"context"
	"errors"
	"testing"

	"github.com/MichaelFraser99/go-jose/joseerror"
	"github.com/MichaelFraser99/go-jose/model"
)

func TestValidateHeader_RefusesATypOrCtyThatIsNotAString(t *testing.T) {
	tests := map[string]struct {
		header map[string]any
		opts   *model.JoseOptions
		clause string
	}{
		"typ of a number":                        {map[string]any{"alg": "ES256", "typ": 5}, nil, "RFC 7515 4.1.9"},
		"typ of an array":                        {map[string]any{"alg": "ES256", "typ": []any{"JWT"}}, nil, "RFC 7515 4.1.9"},
		"typ of null":                            {map[string]any{"alg": "ES256", "typ": nil}, nil, "RFC 7515 4.1.9"},
		"typ of a number with AcceptedTypes set": {map[string]any{"alg": "ES256", "typ": 5}, &model.JoseOptions{AcceptedTypes: []string{"JWT"}}, "RFC 7515 4.1.9"},
		"cty of a number":                        {map[string]any{"alg": "ES256", "cty": 5}, nil, "RFC 7515 4.1.10"},
		"cty of an object":                       {map[string]any{"alg": "ES256", "cty": map[string]any{}}, nil, "RFC 7515 4.1.10"},
		"cty of a boolean":                       {map[string]any{"alg": "ES256", "cty": true}, nil, "RFC 7515 4.1.10"},
	}
	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			_, err := ValidateHeader(context.Background(), test.header, nil, model.JWS, test.opts)
			if !errors.Is(err, joseerror.ErrMalformedClaim) {
				t.Fatalf("[%s] a media type is a string, so header %v must be refused with ErrMalformedClaim, got %v", test.clause, test.header, err)
			}
		})
	}
}

func TestValidateHeader_AcceptsATypAndCtyThatAreStrings(t *testing.T) {
	header := map[string]any{"alg": "ES256", "typ": "JWT", "cty": "example"}
	if _, err := ValidateHeader(context.Background(), header, nil, model.JWS, nil); err != nil {
		t.Fatalf("[RFC 7515 4.1.9, 4.1.10] header %v holds string media types and must be accepted, got %v", header, err)
	}
}
