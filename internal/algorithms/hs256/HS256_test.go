package hs256

import (
	"bytes"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"github.com/MichaelFraser99/go-jose/internal/algorithms/common"
	"testing"
)

func TestES256_Sign(t *testing.T) {
	body := map[string]any{
		"sub":  "1234567890",
		"name": "John Doe",
		"iat":  1516239022,
	}

	headerKeys := map[string]string{
		"alg": "HS256",
		"typ": "JWT",
	}

	bBody, err := json.Marshal(body)
	if err != nil {
		t.Fatal("no error should be thrown:", err)
	}
	bHeader, err := json.Marshal(headerKeys)
	if err != nil {
		t.Fatal("no error should be thrown:", err)
	}

	b64Header := base64.RawURLEncoding.EncodeToString(bHeader)
	b64Body := base64.RawURLEncoding.EncodeToString(bBody)

	digest := fmt.Sprintf("%s.%s", b64Header, b64Body)

	secretKey := []byte("your-256-bit-secret")
	hs256, err := NewSigner(&secretKey)
	if err != nil {
		t.Fatal("no error should be thrown:", err)
	}

	signature, err := hs256.Sign(rand.Reader, []byte(digest), nil)
	if err != nil {
		t.Fatal("no error should be thrown:", err)
	}
	if hs256.Public() == nil {
		t.Fatal("public key should not be nil")
	}

	stringSignature := base64.RawURLEncoding.EncodeToString(signature)
	t.Logf("%s.%s", digest, stringSignature)

	if stringSignature != "fdOPQ05ZfRhkST2-rIWgUpbqUsVhkkNVNcuG7Ki0s-8" {
		t.Errorf("unexpected signature produced: %s", stringSignature)
	}
}

func TestES256_SignGeneratedSecret(t *testing.T) {
	body := map[string]any{
		"sub":  "1234567890",
		"name": "John Doe",
		"iat":  1516239022,
	}

	headerKeys := map[string]string{
		"alg": "HS256",
		"typ": "JWT",
	}

	bBody, err := json.Marshal(body)
	if err != nil {
		t.Fatal("no error should be thrown:", err)
	}
	bHeader, err := json.Marshal(headerKeys)
	if err != nil {
		t.Fatal("no error should be thrown:", err)
	}

	b64Header := base64.RawURLEncoding.EncodeToString(bHeader)
	b64Body := base64.RawURLEncoding.EncodeToString(bBody)

	digest := fmt.Sprintf("%s.%s", b64Header, b64Body)

	hs256, err := NewSigner(nil)
	if err != nil {
		t.Fatal("no error should be thrown:", err)
	}

	signature, err := hs256.Sign(rand.Reader, []byte(digest), nil)
	if err != nil {
		t.Fatal("no error should be thrown:", err)
	}
	if hs256.Public() == nil {
		t.Fatal("public key should not be nil")
	}

	stringSignature := base64.RawURLEncoding.EncodeToString(signature)
	t.Logf("%s.%s", digest, stringSignature)

	secretKey := hs256.Public().(common.SecretKey)

	hs2562, err := NewSigner((*[]byte)(&secretKey))
	if err != nil {
		t.Fatal("no error should be thrown:", err)
	}

	signature2, err := hs2562.Sign(rand.Reader, []byte(digest), nil)
	if err != nil {
		t.Fatal("no error should be thrown:", err)
	}
	if hs256.Public() == nil {
		t.Fatal("public key should not be nil")
	}

	stringSignature = base64.RawURLEncoding.EncodeToString(signature2)
	t.Logf("%s.%s", digest, stringSignature)

	if !bytes.Equal(signature, signature2) {
		t.Error("two signatures should match")
	}
}
