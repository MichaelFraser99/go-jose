package es512

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"testing"
)

func TestValidateSignatureES512(t *testing.T) {
	publicKey := "{\"kty\":\"EC\",\"crv\":\"P-521\",\"x\":\"Ae9hYaIls2sRK8n1XddHMjeS592yBIanCf8skWNbPPgez00w1m_xVt9BANFrQnZQgzoE0kBhOSVidRazi1QcY-3k\",\"y\":\"AX7Q--gyprCTZUDDPv48nNLtlbhCvC1aXxtc4pYpLFQbBIkeDXz0aMbBTyqs6sJZU0tDjeKohDTjwg3-3dbZLCm4\"}"

	token := "eyJhbGciOiJFUzUxMiIsInR5cCI6Imp3dCJ9.eyJhZGRyZXNzIjp7ImNpdHkiOiJFZGluYnVyZ2giLCJudW1iZXIiOiIxNSIsInN0cmVldCI6IkxvbmcgTGFuZSJ9LCJmaXJzdG5hbWUiOiJqb2huIiwic3VybmFtZSI6InNtaXRoIn0"

	signature := "ADT4CJwauvGdsZ1739n9iT0_HYq0om0h-UirM5CZQEwAmfj6cGgHR-M2cDZCq5dDXvKISY5ZqBrOLk_uNeQv0ZzNAJ_6Jmz_Sa3sClp-uHLAGAiKOYx7l_aFSN4_rxq2vQFXbfsclREdQTv_8W-u5ax8SWLyNHxaNn7nYKpssmGaokTs"

	es512, err := NewValidatorFromJwk([]byte(publicKey))
	if err != nil {
		t.Error("no error should be thrown:", err)
	}

	decodedSignature := make([]byte, base64.RawURLEncoding.DecodedLen(len(signature)))
	base64.RawURLEncoding.Decode(decodedSignature, []byte(signature))

	valid, err := es512.ValidateSignature([]byte(token), decodedSignature)
	if err != nil {
		t.Error("no error should be thrown:", err)
	}
	if !valid {
		t.Error("signature is not valid")
	}
}

func TestES512_Sign(t *testing.T) {
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
		"alg": "ES512",
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

	es512, err := NewSigner()
	if err != nil {
		t.Error("no error should be thrown:", err)
		t.FailNow()
	}

	signature, err := es512.Sign(rand.Reader, []byte(digest), nil)
	if err != nil {
		t.Error("no error should be thrown:", err)
		t.FailNow()
	}
	if es512.Public() == nil {
		t.Error("public key should not be nil")
		t.FailNow()
	}

	validator, err := NewValidator(es512.Public())
	if err != nil {
		t.Error("no error should be thrown:", err)
		t.FailNow()
	}

	valid, err := validator.ValidateSignature([]byte(digest), signature)
	if err != nil {
		t.Error("no error should be thrown:", err)
	}
	if !valid {
		t.Error("signature is not valid")
	}
}
