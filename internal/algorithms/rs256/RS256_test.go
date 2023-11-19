package rs256

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"testing"
)

func TestValidateSignatureRS256(t *testing.T) {
	publicKey := "{\"e\":\"AQAB\",\"kid\":\"PublicJWK\",\"kty\":\"RSA\",\"n\":\"wdNpeQuzVo7SXPlejNOhwwOrSZH1vxkZ_jIXNPyuL90gLHyChm1qe9a9SQfySf8sUHbRcnZYolpzNV7AUZ84I1M8sN8QPnCMXfP4yYiB46iyIQahEw4aTKKY6Joxfknc3B-MDrFfG9x7ymaXOKHwZtsRm-6pYls_2_o2wdmNlh9RPSap0wIn4FAc1-Mmr-n6XKy8jRMbD348kCNJanHV8EvjP0MArK4RHgugQ1G-4z528lzLJaGlE9Iaj0r4evXle2qUAyWGSPUGsZmawmDYlVT6_cOXbUOxIzzVu9HDDkxma20OzKqkHeM2PySzkbqRLwvdggooKIWjPJ_0p0NAKw\"}"

	token := "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJhZGRyZXNzIjp7ImNpdHkiOiJFZGluYnVyZ2giLCJudW1iZXIiOiIxNSIsInN0cmVldCI6IkxvbmcgTGFuZSJ9LCJmaXJzdG5hbWUiOiJqb2huIiwic3VybmFtZSI6InNtaXRoIn0"

	signature := "NQ3xSeZ4Ap1ibFLRoIwIxqMj3haTazOjky2CK58LnTWaUK2vcS_j2SlN4904PIz_y9cDlhAH-hVH7jbCwyIYkD5QKUKKPg530JWbVfZlwTwvfTBn1euvq-i9TvfykzHHybY7tFOQJSM3O4TdJRh9ZysfFBkjHkUa1FLN_cdNzCukHSSEa1cekNEQinLlzoVHC9aDwFrMBdnND3w8Y_9wqpp3Un6i2LVgib95JPeVskh6x8_NFWp0Sy8xV0XCapE5KJVfKynJFFEODyfxAJSXyYX7PCMex8fGJG3MtEJZRuU0UKYdBO5idnlY1sK3BvalBNtNc3qb7oGU-JmjdbTdhw"

	validator, err := NewValidatorFromJwk([]byte(publicKey))
	if err != nil {
		t.Error("no error should be thrown:", err)
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

func TestRS256_Sign(t *testing.T) {
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
		"alg": "RS256",
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

	rs256, err := NewSigner(2048)
	if err != nil {
		t.Error("no error should be thrown:", err)
		t.FailNow()
	}

	signature, err := rs256.Sign(rand.Reader, []byte(digest), nil)
	if err != nil {
		t.Error("no error should be thrown:", err)
		t.FailNow()
	}
	if rs256.Public() == nil {
		t.Error("public key should not be nil")
		t.FailNow()
	}

	validator, err := NewValidator(rs256.Public())
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
	if !ok || val != "RSA" {
		t.Errorf("kty key is missing or wrong")
	}
	_, ok = jwk["n"]
	if !ok {
		t.Errorf("n key is missing")
	}
	_, ok = jwk["e"]
	if !ok {
		t.Errorf("e key is missing")
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
