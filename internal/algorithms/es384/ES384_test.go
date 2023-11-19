package es384

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"testing"
)

func TestValidateSignatureES384(t *testing.T) {
	publicKey := "{\"kty\":\"EC\",\"crv\":\"P-384\",\"x\":\"AgQPgcqypazyTOW8CsQOhnN2jXSLrUha6YrkXAZES6sOWT44t_OSx68kEg-UQ1lo\",\"y\":\"uRYLEPxefzGME223BsBLDyhDJ7KZApkKdmXbvaZorFQol8beG6zfve3Z16Jq1Xrj\"}"

	token := "eyJhbGciOiJFUzM4NCIsInR5cCI6Imp3dCJ9.eyJhZGRyZXNzIjp7ImNpdHkiOiJFZGluYnVyZ2giLCJudW1iZXIiOiIxNSIsInN0cmVldCI6IkxvbmcgTGFuZSJ9LCJmaXJzdG5hbWUiOiJqb2huIiwic3VybmFtZSI6InNtaXRoIn0"

	signature := "T1wWViEJKvYoOIYTD3WtK69cJMJTAmaAXni54AcWBLmOmiYQCIigzynawj5Fe1L4MRqmiCHdRF7F3Uz_ab_QvDhQw925k7rHWTwL2eSmK8TRRIS598MEM0VbcBL7AAbN"

	validator, err := NewValidatorFromJwk([]byte(publicKey))
	if err != nil {
		t.Error("no error should be thrown:", err)
		t.FailNow()
	}

	decodedSignature := make([]byte, base64.RawURLEncoding.DecodedLen(len(signature)))
	base64.RawURLEncoding.Decode(decodedSignature, []byte(signature))

	valid, err := validator.ValidateSignature([]byte(token), decodedSignature)
	if err != nil {
		t.Error("no error should be thrown:", err)
	}
	if !valid {
		t.Error("signature is not valid")
	}
}

func TestES384_Sign(t *testing.T) {
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
		"alg": "ES384",
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

	es384, err := NewSigner()
	if err != nil {
		t.Error("no error should be thrown:", err)
		t.FailNow()
	}

	signature, err := es384.Sign(rand.Reader, []byte(digest), nil)
	if err != nil {
		t.Error("no error should be thrown:", err)
		t.FailNow()
	}
	if es384.Public() == nil {
		t.Error("public key should not be nil")
		t.FailNow()
	}

	validator, err := NewValidator(es384.Public())
	if err != nil {
		t.Error("no error should be thrown:", err)
		t.FailNow()
	}

	jwk := validator.Jwk()
	jwkBytes, err := json.Marshal(jwk)
	if err != nil {
		t.Errorf("failed to marshal JWK as map: %s", err.Error())
		t.FailNow()
	}
	val, ok := jwk["kty"]
	if !ok || val != "EC" {
		t.Errorf("kty key is missing or wrong")
	}
	_, ok = jwk["x"]
	if !ok {
		t.Errorf("n key is missing")
	}
	_, ok = jwk["y"]
	if !ok {
		t.Errorf("e key is missing")
	}
	crv, ok := jwk["crv"]
	if !ok && crv != "P-384" {
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
