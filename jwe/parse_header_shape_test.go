package jwe

import (
	"context"
	"encoding/base64"
	"errors"
	"slices"
	"strings"
	"testing"

	"github.com/MichaelFraser99/go-jose/joseerror"
	"github.com/MichaelFraser99/go-jose/jwa"
)

func TestParseHeader_MakesTheShapeChecksDecryptMakes(t *testing.T) {
	encrypter, err := GetEncrypter(jwa.A256KW, randomBytes(t, 32))
	if err != nil {
		t.Fatal(err)
	}
	token, err := Encrypt(encrypter, jwa.A128GCM, []byte("p"), nil)
	if err != nil {
		t.Fatal(err)
	}
	parts := strings.Split(token, ".")
	with := func(i int, segment string) string {
		changed := slices.Clone(parts)
		changed[i] = segment
		return strings.Join(changed, ".")
	}
	if _, err := ParseHeader(token, nil); err != nil {
		t.Fatalf("[RFC 7516 9] a well-formed JWE must parse, got %v", err)
	}
	for name, malformed := range map[string]string{
		"an encrypted key that is not base64url":         with(1, "a=b"),
		"an initialization vector that is not base64url": with(2, "a=b"),
		"a ciphertext that is not base64url":             with(3, "a=b"),
		"an authentication tag that is not base64url":    with(4, "a=b"),
		"a 5-octet authentication tag":                   with(4, base64.RawURLEncoding.EncodeToString(make([]byte, 5))),
		"a 3-octet initialization vector":                with(2, base64.RawURLEncoding.EncodeToString(make([]byte, 3))),
		"a 3-octet encrypted key for A256KW":             with(1, base64.RawURLEncoding.EncodeToString(make([]byte, 3))),
	} {
		t.Run(name, func(t *testing.T) {
			_, _, _, decryptErr := Decrypt(context.Background(), malformed, nil, nil)
			if !errors.Is(decryptErr, joseerror.ErrMalformedToken) {
				t.Fatalf("[RFC 7516 9] the premise is that Decrypt refuses %s as malformed, got %v", name, decryptErr)
			}
			if header, err := ParseHeader(malformed, nil); !errors.Is(err, joseerror.ErrMalformedToken) || header != nil {
				t.Errorf("[RFC 7516 9] ParseHeader makes Decrypt's checks of the token's shape, so it must refuse %s as malformed, got %v", name, err)
			}
		})
	}
}
