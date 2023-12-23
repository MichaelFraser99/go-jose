package es256

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"github.com/MichaelFraser99/go-jose/jwk"
	"testing"
)

func TestES256_Sign(t *testing.T) {
	body := map[string]any{
		"firstname": "john",
		"surname":   "smith",
		"address": map[string]string{
			"street": "Long Lane",
			"number": "15",
			"city":   "Edinburgh",
		},
	}

	headerKeys := map[string]string{
		"typ": "jwt",
		"alg": "ES256",
	}

	bBody, err := json.Marshal(body)
	if err != nil {
		t.Error("no error should be thrown:", err)
		t.FailNow()
	}
	bHeader, err := json.Marshal(headerKeys)
	if err != nil {
		t.Error("no error should be thrown:", err)
		t.FailNow()
	}

	b64Header := base64.RawURLEncoding.EncodeToString(bHeader)
	b64Body := base64.RawURLEncoding.EncodeToString(bBody)

	digest := fmt.Sprintf("%s.%s", b64Header, b64Body)

	es256, err := NewSigner()
	if err != nil {
		t.Error("no error should be thrown:", err)
		t.FailNow()
	}

	signature, err := es256.Sign(rand.Reader, []byte(digest), nil)
	if err != nil {
		t.Error("no error should be thrown:", err)
		t.FailNow()
	}
	if es256.Public() == nil {
		t.Error("public key should not be nil")
		t.FailNow()
	}

	validator, err := NewValidator(es256.Public())
	if err != nil {
		t.Error("no error should be thrown:", err)
		t.FailNow()
	}

	key, err := jwk.PublicJwk(validator.Public())
	if err != nil {
		t.Errorf("failed to extract jwk from public key: %s", err.Error())
	}
	jwkBytes, err := json.Marshal(key)
	if err != nil {
		t.Errorf("failed to marshal JWK as map: %s", err.Error())
		t.FailNow()
	}
	val, ok := (*key)["kty"]
	if !ok || val != "EC" {
		t.Errorf("kty key is missing or wrong")
	}
	_, ok = (*key)["x"]
	if !ok {
		t.Errorf("n key is missing")
	}
	_, ok = (*key)["y"]
	if !ok {
		t.Errorf("e key is missing")
	}
	crv, ok := (*key)["crv"]
	if !ok && crv != "P-256" {
		t.Errorf("crv key is missing or wrong")
	}

	t.Log(digest)
	t.Log(base64.RawURLEncoding.EncodeToString(signature))
	t.Log(string(jwkBytes))

	valid, err := validator.ValidateSignature([]byte(digest), signature)
	if err != nil {
		t.Error("no error should be thrown:", err)
	}
	if !valid {
		t.Error("signature is not valid")
	}

	val2, err := NewValidatorFromJwk(jwkBytes)
	if err != nil {
		t.Errorf("failed to create validator from public key jwk: %s", err.Error())
		t.FailNow()
	}

	valid, err = val2.ValidateSignature([]byte(digest), signature)
	if err != nil {
		t.Error("no error should be thrown:", err)
	}
	if !valid {
		t.Error("signature is not valid")
	}
}
