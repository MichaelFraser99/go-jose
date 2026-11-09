package jws

import (
	"context"
	"errors"
	"testing"

	"github.com/MichaelFraser99/go-jose/joseerror"
	"github.com/MichaelFraser99/go-jose/jwa"
	"github.com/MichaelFraser99/go-jose/model"
)

func TestCheckOptions_RefusesValuesNoTokenCanMeet(t *testing.T) {
	refused := map[string]*model.JoseOptions{
		"a JWE alg in AllowedSigningAlgorithms":           {AllowedSigningAlgorithms: []jwa.Algorithm{jwa.ES256, jwa.RSAOAEP256}},
		"Unknown in AllowedSigningAlgorithms":             {AllowedSigningAlgorithms: []jwa.Algorithm{jwa.Unknown}},
		"a value outside jwa in AllowedSigningAlgorithms": {AllowedSigningAlgorithms: []jwa.Algorithm{jwa.Algorithm(999)}},
		"an empty AcceptedTypes entry":                    {AcceptedTypes: []string{""}},
		"a leading space":                                 {AcceptedTypes: []string{" at+jwt"}},
		"a trailing space":                                {AcceptedTypes: []string{"at+jwt "}},
		"a trailing CRLF":                                 {AcceptedTypes: []string{"at+jwt\r\n"}},
		"a wildcard":                                      {AcceptedTypes: []string{"*/*"}},
		"parameters with no type":                         {AcceptedTypes: []string{";v=1"}},
		"three parts":                                     {AcceptedTypes: []string{"application/at/jwt"}},
		"an empty subtype":                                {AcceptedTypes: []string{"application/"}},
		"an empty type":                                   {AcceptedTypes: []string{"/at+jwt"}},
		"a non-ASCII letter":                              {AcceptedTypes: []string{"ſecevent+jwt"}},
		"a first character that is a symbol":              {AcceptedTypes: []string{"+jwt"}},
		"one bad entry among good ones":                   {AcceptedTypes: []string{"at+jwt", ""}},
	}
	for name, opts := range refused {
		t.Run(name, func(t *testing.T) {
			if err := CheckOptions(opts); !errors.Is(err, joseerror.ErrInvalidOptions) {
				t.Errorf("[RFC 6838 4.2] these options can match no token, so want ErrInvalidOptions, got %v", err)
			}
			if _, _, err := Verify(context.Background(), "not a token", nil, opts); !errors.Is(err, joseerror.ErrInvalidOptions) || errors.Is(err, joseerror.ErrMalformedToken) {
				t.Errorf("[RFC 6838 4.2] options that are wrong whatever the token must be refused before the token is read, got %v", err)
			}
		})
	}
	accepted := map[string]*model.JoseOptions{
		"nil options":                   nil,
		"every signature alg":           {AllowedSigningAlgorithms: []jwa.Algorithm{jwa.ES256, jwa.ES384, jwa.ES512, jwa.RS256, jwa.PS512, jwa.HS256, jwa.EdDSA, jwa.Ed25519, jwa.MLDSA44}},
		"a bare subtype":                {AcceptedTypes: []string{"JWT"}},
		"a type and subtype":            {AcceptedTypes: []string{"application/at+jwt"}},
		"parameters":                    {AcceptedTypes: []string{"at+jwt; v=1"}},
		"a space before the parameters": {AcceptedTypes: []string{"at+jwt ;v=1"}},
		"every symbol RFC 6838 allows":  {AcceptedTypes: []string{"vnd.a1!#$&-^_.+jwt"}},
		"digits first":                  {AcceptedTypes: []string{"3gpp+jwt"}},
	}
	for name, opts := range accepted {
		t.Run(name, func(t *testing.T) {
			if err := CheckOptions(opts); err != nil {
				t.Errorf("[RFC 6838 4.2] these options are valid, got %v", err)
			}
		})
	}
}
