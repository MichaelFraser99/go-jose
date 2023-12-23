package hs384

import (
	"bytes"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"testing"
)

func TestES384_Sign(t *testing.T) {
	body := map[string]any{
		"sub":  "1234567890",
		"name": "John Doe",
		"iat":  1516239022,
	}

	headerKeys := map[string]string{
		"alg": "HS384",
		"typ": "JWT",
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

	secretKey := []byte("your-384-bit-secret")
	hs384, err := NewSigner(&secretKey)
	if err != nil {
		t.Error("no error should be thrown:", err)
		t.FailNow()
	}

	signature, err := hs384.Sign(rand.Reader, []byte(digest), nil)
	if err != nil {
		t.Error("no error should be thrown:", err)
		t.FailNow()
	}
	if hs384.Public() == nil {
		t.Error("public key should not be nil")
		t.FailNow()
	}

	stringSignature := base64.RawURLEncoding.EncodeToString(signature)
	t.Log(fmt.Sprintf("%s.%s", digest, stringSignature))

	if stringSignature != "OIKd9Q0-kcZbDVhIUuXW6HKy5yfnCE6zZyue96IXXEAkNEnboTbPxbYw6E0dE0H_" {
		t.Errorf("unexpected signature produced: %s", stringSignature)
	}
}

func TestES384_SignGeneratedSecret(t *testing.T) {
	body := map[string]any{
		"sub":  "1234567890",
		"name": "John Doe",
		"iat":  1516239022,
	}

	headerKeys := map[string]string{
		"alg": "HS384",
		"typ": "JWT",
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

	hs384, err := NewSigner(nil)
	if err != nil {
		t.Error("no error should be thrown:", err)
		t.FailNow()
	}

	signature, err := hs384.Sign(rand.Reader, []byte(digest), nil)
	if err != nil {
		t.Error("no error should be thrown:", err)
		t.FailNow()
	}
	if hs384.Public() == nil {
		t.Error("public key should not be nil")
		t.FailNow()
	}

	stringSignature := base64.RawURLEncoding.EncodeToString(signature)
	t.Log(fmt.Sprintf("%s.%s", digest, stringSignature))

	secretKey := hs384.Public().(SecretKey)

	hs3842, err := NewSigner((*[]byte)(&secretKey))
	if err != nil {
		t.Fatal("no error should be thrown:", err)
	}

	signature2, err := hs3842.Sign(rand.Reader, []byte(digest), nil)
	if err != nil {
		t.Error("no error should be thrown:", err)
		t.FailNow()
	}
	if hs384.Public() == nil {
		t.Error("public key should not be nil")
		t.FailNow()
	}

	stringSignature = base64.RawURLEncoding.EncodeToString(signature2)
	t.Log(fmt.Sprintf("%s.%s", digest, stringSignature))

	if !bytes.Equal(signature, signature2) {
		t.Error("two signatures should match")
	}
}
