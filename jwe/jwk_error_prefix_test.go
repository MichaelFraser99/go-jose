package jwe

import (
	"errors"
	"strings"
	"testing"

	"github.com/MichaelFraser99/go-jose/joseerror"
	"github.com/MichaelFraser99/go-jose/jwa"
)

func TestFromJwk_NamesItsSentinelOnce(t *testing.T) {
	badRSA := map[string]any{"kty": "RSA", "n": "AQAB", "e": "AQAB", "d": "AQAB"}
	if _, err := GetDecrypterFromJwk(jwa.RSAOAEP256, badRSA, nil); !errors.Is(err, joseerror.ErrInvalidPrivateKey) || strings.Count(err.Error(), "invalid private key: ") != 1 {
		t.Errorf("want ErrInvalidPrivateKey named once, got %v", err)
	}
	badEC := map[string]any{"kty": "EC", "crv": "P-256", "x": "AQAB", "y": "AQAB"}
	if _, err := GetEncrypterFromJwk(jwa.ECDHES, badEC, nil); !errors.Is(err, joseerror.ErrInvalidPublicKey) || strings.Count(err.Error(), "invalid public key: ") != 1 {
		t.Errorf("want ErrInvalidPublicKey named once, got %v", err)
	}
	notBase64 := map[string]any{"kty": "oct", "k": "a+b"}
	if _, err := GetDecrypterFromJwk(jwa.A128KW, notBase64, nil); !errors.Is(err, joseerror.ErrInvalidPrivateKey) || !errors.Is(err, joseerror.ErrMalformedClaim) {
		t.Errorf("a member that is not base64url must carry ErrInvalidPrivateKey and ErrMalformedClaim, got %v", err)
	}
}
