package hs512

import (
	"bytes"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"github.com/MichaelFraser99/go-jose/internal/algorithms/common"
	"sync"
	"testing"
)

func TestHS512_Sign(t *testing.T) {
	body := map[string]any{
		"sub":  "1234567890",
		"name": "John Doe",
		"iat":  1516239022,
	}

	headerKeys := map[string]string{
		"alg": "HS512",
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

	secretKey := []byte("your-512-bit-secret")
	hs512, err := NewSigner(&secretKey)
	if err != nil {
		t.Fatal("no error should be thrown:", err)
	}

	signature, err := hs512.Sign(rand.Reader, []byte(digest), nil)
	if err != nil {
		t.Fatal("no error should be thrown:", err)
	}
	if hs512.Public() == nil {
		t.Fatal("public key should not be nil")
	}

	stringSignature := base64.RawURLEncoding.EncodeToString(signature)

	if stringSignature != "xDtSUFJH9k4yIq80TMQ1-miAjnNN1skOJ1BzUMdw_8VRFn-AR8fFNjvPiXyleHSRw28BXnEupZxCxWUfWwIoqg" {
		t.Errorf("unexpected signature produced: %s", stringSignature)
	}
}

func TestHS512_SignGeneratedSecret(t *testing.T) {
	body := map[string]any{
		"sub":  "1234567890",
		"name": "John Doe",
		"iat":  1516239022,
	}

	headerKeys := map[string]string{
		"alg": "HS512",
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

	hs512, err := NewSigner(nil)
	if err != nil {
		t.Fatal("no error should be thrown:", err)
	}

	signature, err := hs512.Sign(rand.Reader, []byte(digest), nil)
	if err != nil {
		t.Fatal("no error should be thrown:", err)
	}
	if hs512.Public() == nil {
		t.Fatal("public key should not be nil")
	}

	stringSignature := base64.RawURLEncoding.EncodeToString(signature)
	t.Logf("%s.%s", digest, stringSignature)

	secretKey := hs512.Public().(common.SecretKey)

	hs5122, err := NewSigner((*[]byte)(&secretKey))
	if err != nil {
		t.Fatal("no error should be thrown:", err)
	}

	signature2, err := hs5122.Sign(rand.Reader, []byte(digest), nil)
	if err != nil {
		t.Fatal("no error should be thrown:", err)
	}
	if hs512.Public() == nil {
		t.Fatal("public key should not be nil")
	}

	stringSignature = base64.RawURLEncoding.EncodeToString(signature2)
	t.Logf("%s.%s", digest, stringSignature)

	if !bytes.Equal(signature, signature2) {
		t.Error("two signatures should match")
	}
}

func TestSigner_OneSignerServesConcurrentCallers(t *testing.T) {
	secret := []byte("a-secret-shared-across-goroutines")
	signer, err := NewSigner(&secret)
	if err != nil {
		t.Fatalf("failed to build the signer: %v", err)
	}

	input := []byte("the signing input")
	want, err := signer.Sign(nil, input, nil)
	if err != nil {
		t.Fatalf("failed to produce the sequential mac: %v", err)
	}

	const callers = 64
	results := make([][]byte, callers)
	errs := make([]error, callers)
	var wg sync.WaitGroup
	for i := range results {
		wg.Add(1)
		go func(at int) {
			defer wg.Done()
			results[at], errs[at] = signer.Sign(nil, input, nil)
		}(i)
	}
	wg.Wait()

	for i := range results {
		if errs[i] != nil {
			t.Fatalf("caller %d failed: %v", i, errs[i])
		}
		if !bytes.Equal(results[i], want) {
			t.Fatalf("[RFC 2104] a mac over one input under one key is one value, so a signer shared between callers must not depend on how the calls interleave: caller %d produced %x, want %x", i, results[i], want)
		}
	}
}

func TestValidator_OneValidatorServesConcurrentCallers(t *testing.T) {
	secret := []byte("a-secret-shared-across-goroutines")
	signer, err := NewSigner(&secret)
	if err != nil {
		t.Fatalf("failed to build the signer: %v", err)
	}
	input := []byte("the signing input")
	signature, err := signer.Sign(nil, input, nil)
	if err != nil {
		t.Fatalf("failed to sign: %v", err)
	}

	validator, err := NewValidator(signer.Public())
	if err != nil {
		t.Fatalf("failed to build the validator: %v", err)
	}

	const callers = 64
	valid := make([]bool, callers)
	errs := make([]error, callers)
	var wg sync.WaitGroup
	for i := range valid {
		wg.Add(1)
		go func(at int) {
			defer wg.Done()
			valid[at], errs[at] = validator.ValidateSignature(input, signature)
		}(i)
	}
	wg.Wait()

	for i := range valid {
		if errs[i] != nil {
			t.Fatalf("caller %d failed: %v", i, errs[i])
		}
		if !valid[i] {
			t.Fatalf("[RFC 2104] a validator shared between callers must accept a correct mac regardless of how the calls interleave, caller %d refused it", i)
		}
	}
}

func TestSigner_MatchesTheRFC4231Vector(t *testing.T) {
	key := []byte("Jefe")
	signer, err := NewSigner(&key)
	if err != nil {
		t.Fatalf("failed to build the signer: %v", err)
	}

	mac, err := signer.Sign(nil, []byte("what do ya want for nothing?"), nil)
	if err != nil {
		t.Fatalf("failed to sign: %v", err)
	}

	const want = "164b7a7bfcf819e2e395fbe73b56e0a387bd64222e831fd610270cd7ea2505549758bf75c05a994a6d034f65f8f0e6fdcaeab1a34d4a6b4b636e070a38bce737"
	if got := hex.EncodeToString(mac); got != want {
		t.Errorf("[RFC 4231 test case 2] HMAC-SHA-512 of %q under key %q is %s, got %s", "what do ya want for nothing?", "Jefe", want, got)
	}
}

func TestValidator_RefusesAMacThatIsNotTheRightOne(t *testing.T) {
	secret := []byte("Jefe")
	signer, err := NewSigner(&secret)
	if err != nil {
		t.Fatalf("failed to build the signer: %v", err)
	}
	input := []byte("what do ya want for nothing?")
	correct, err := signer.Sign(nil, input, nil)
	if err != nil {
		t.Fatalf("failed to sign: %v", err)
	}
	validator, err := NewValidator(signer.Public())
	if err != nil {
		t.Fatalf("failed to build the validator: %v", err)
	}

	tests := map[string]func() []byte{
		"the correct mac with its first byte flipped": func() []byte {
			bad := bytes.Clone(correct)
			bad[0] ^= 0x01
			return bad
		},
		"the correct mac with its last byte flipped": func() []byte {
			bad := bytes.Clone(correct)
			bad[len(bad)-1] ^= 0x01
			return bad
		},
		"the correct mac truncated by one byte": func() []byte { return correct[:len(correct)-1] },
		"the correct mac with a byte appended":  func() []byte { return append(bytes.Clone(correct), 0x00) },
		"an empty mac":                          func() []byte { return []byte{} },
		"a mac over different input": func() []byte {
			other, err := signer.Sign(nil, []byte("what do ya want for something?"), nil)
			if err != nil {
				t.Fatalf("failed to sign the other input: %v", err)
			}
			return other
		},
	}

	for name, build := range tests {
		t.Run(name, func(t *testing.T) {
			valid, err := validator.ValidateSignature(input, build())
			if err != nil {
				t.Fatalf("[RFC 2104] a mac that does not match is a refusal, not an error, got %v", err)
			}
			if valid {
				t.Errorf("[RFC 2104] only the mac computed over this input under this key may be accepted")
			}
		})
	}

	valid, err := validator.ValidateSignature(input, correct)
	if err != nil || !valid {
		t.Errorf("[RFC 2104] the correct mac must still be accepted, got valid=%v err=%v", valid, err)
	}
}
