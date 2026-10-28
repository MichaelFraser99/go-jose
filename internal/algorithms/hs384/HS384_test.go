package hs384

import (
	"bytes"
	"crypto"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha512"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/MichaelFraser99/go-jose/internal/algorithms/common"
	"github.com/MichaelFraser99/go-jose/joseerror"
	"sync"
	"testing"
)

func TestHS384_Sign(t *testing.T) {
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
		t.Fatal("no error should be thrown:", err)
	}
	bHeader, err := json.Marshal(headerKeys)
	if err != nil {
		t.Fatal("no error should be thrown:", err)
	}

	b64Header := base64.RawURLEncoding.EncodeToString(bHeader)
	b64Body := base64.RawURLEncoding.EncodeToString(bBody)

	digest := fmt.Sprintf("%s.%s", b64Header, b64Body)

	secretKey := bytes.Repeat([]byte("k"), MinimumSecretBytes)
	hs384, err := NewSigner(&secretKey)
	if err != nil {
		t.Fatal("no error should be thrown:", err)
	}

	signature, err := hs384.Sign(rand.Reader, []byte(digest), nil)
	if err != nil {
		t.Fatal("no error should be thrown:", err)
	}
	if hs384.Public() == nil {
		t.Fatal("public key should not be nil")
	}

	stringSignature := base64.RawURLEncoding.EncodeToString(signature)
	t.Logf("%s.%s", digest, stringSignature)

	expected := func() string {
		mac := hmac.New(sha512.New384, secretKey)
		mac.Write([]byte(digest))
		return base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
	}()
	if stringSignature != expected {
		t.Errorf("[RFC 7515 5.1] the signature is the HMAC of the signing input under the key, want %s, got %s", expected, stringSignature)
	}
}

func TestHS384_SignGeneratedSecret(t *testing.T) {
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
		t.Fatal("no error should be thrown:", err)
	}
	bHeader, err := json.Marshal(headerKeys)
	if err != nil {
		t.Fatal("no error should be thrown:", err)
	}

	b64Header := base64.RawURLEncoding.EncodeToString(bHeader)
	b64Body := base64.RawURLEncoding.EncodeToString(bBody)

	digest := fmt.Sprintf("%s.%s", b64Header, b64Body)

	hs384, err := NewSigner(nil)
	if err != nil {
		t.Fatal("no error should be thrown:", err)
	}

	signature, err := hs384.Sign(rand.Reader, []byte(digest), nil)
	if err != nil {
		t.Fatal("no error should be thrown:", err)
	}
	if hs384.Public() == nil {
		t.Fatal("public key should not be nil")
	}

	stringSignature := base64.RawURLEncoding.EncodeToString(signature)
	t.Logf("%s.%s", digest, stringSignature)

	secretKey := hs384.Public().(common.SecretKey)

	hs3842, err := NewSigner((*[]byte)(&secretKey))
	if err != nil {
		t.Fatal("no error should be thrown:", err)
	}

	signature2, err := hs3842.Sign(rand.Reader, []byte(digest), nil)
	if err != nil {
		t.Fatal("no error should be thrown:", err)
	}
	if hs384.Public() == nil {
		t.Fatal("public key should not be nil")
	}

	stringSignature = base64.RawURLEncoding.EncodeToString(signature2)
	t.Logf("%s.%s", digest, stringSignature)

	if !bytes.Equal(signature, signature2) {
		t.Error("two signatures should match")
	}
}

func TestSigner_OneSignerServesConcurrentCallers(t *testing.T) {
	secret := bytes.Repeat([]byte("k"), MinimumSecretBytes)
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
	secret := bytes.Repeat([]byte("k"), MinimumSecretBytes)
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

func TestSigner_MatchesTheRFC4231LongKeyVector(t *testing.T) {
	key := bytes.Repeat([]byte{0xaa}, 131)
	signer, err := NewSigner(&key)
	if err != nil {
		t.Fatalf("failed to build the signer: %v", err)
	}

	const data = "Test Using Larger Than Block-Size Key - Hash Key First"
	mac, err := signer.Sign(nil, []byte(data), nil)
	if err != nil {
		t.Fatalf("failed to sign: %v", err)
	}

	const want = "4ece084485813e9088d2c63a041bc5b44f9ef1012a2b588f3cd11f05033ac4c60c2ef6ab4030fe8296248df163f44952"
	if got := hex.EncodeToString(mac); got != want {
		t.Errorf("[RFC 4231 test case 6] HMAC-SHA-384 of %q under a 131 byte key of 0xaa is %s, got %s", data, want, got)
	}
}

func TestValidator_RefusesAMacThatIsNotTheRightOne(t *testing.T) {
	secret := bytes.Repeat([]byte("k"), MinimumSecretBytes)
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

func TestSigner_DoesNotTakeItsKeyFromTheCallersSlice(t *testing.T) {
	tests := map[string]func(signer *Signer, supplied []byte){
		"the slice the caller supplied": func(_ *Signer, supplied []byte) { supplied[0] = 'X' },
		"the value Public returns": func(signer *Signer, _ []byte) {
			returned, ok := signer.Public().(common.SecretKey)
			if !ok {
				panic("Public did not return a common.SecretKey")
			}
			returned[0] = 'X'
		},
	}

	for name, mutate := range tests {
		t.Run(name, func(t *testing.T) {
			secret := bytes.Repeat([]byte("k"), MinimumSecretBytes)
			signer, err := NewSigner(&secret)
			if err != nil {
				t.Fatalf("failed to build the signer: %v", err)
			}

			input := []byte("the signing input")
			before, err := signer.Sign(nil, input, nil)
			if err != nil {
				t.Fatalf("failed to sign: %v", err)
			}

			mutate(signer, secret)

			after, err := signer.Sign(nil, input, nil)
			if err != nil {
				t.Fatalf("failed to sign after the mutation: %v", err)
			}
			if !bytes.Equal(before, after) {
				t.Errorf("[RFC 2104] a signer's key is fixed when it is built, so writing to %s must not change the mac it produces", name)
			}
		})
	}
}

func TestValidator_DoesNotTakeItsKeyFromTheCallersSlice(t *testing.T) {
	secret := bytes.Repeat([]byte("k"), MinimumSecretBytes)
	signer, err := NewSigner(&secret)
	if err != nil {
		t.Fatalf("failed to build the signer: %v", err)
	}
	input := []byte("the signing input")
	signature, err := signer.Sign(nil, input, nil)
	if err != nil {
		t.Fatalf("failed to sign: %v", err)
	}

	supplied := common.SecretKey(bytes.Clone(secret))
	validator, err := NewValidator(supplied)
	if err != nil {
		t.Fatalf("failed to build the validator: %v", err)
	}
	supplied[0] = 'X'

	valid, err := validator.ValidateSignature(input, signature)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !valid {
		t.Errorf("[RFC 2104] a validator's key is fixed when it is built, so writing to the caller's slice afterwards must not change what it accepts")
	}
}

func TestNewSigner_RefusesASecretShorterThanTheHashOutput(t *testing.T) {
	tests := map[string]struct {
		reference string
		secret    []byte
		accept    bool
	}{
		"a secret of exactly the hash output":  {reference: "RFC 7518 3.2", secret: bytes.Repeat([]byte("k"), 48), accept: true},
		"a secret longer than the hash output": {reference: "RFC 7518 3.2", secret: bytes.Repeat([]byte("k"), 48+1), accept: true},
		"a secret one byte short":              {reference: "RFC 7518 3.2", secret: bytes.Repeat([]byte("k"), 48-1)},
		"a one byte secret":                    {reference: "RFC 7518 3.2", secret: []byte("k")},
		"an empty secret":                      {reference: "RFC 7518 3.2", secret: []byte{}},
		"a nil secret slice":                   {reference: "RFC 7518 3.2", secret: nil},
	}

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			secret := tc.secret
			signer, err := NewSigner(&secret)
			if tc.accept {
				if err != nil {
					t.Fatalf("[%s] a key of at least the SHA-384 output size must be accepted, got %v", tc.reference, err)
				}
				return
			}
			if err == nil {
				t.Fatalf("[%s] a key of the same size as the SHA-384 output or larger MUST be used, so a %d byte key must be refused, got a signer", tc.reference, len(tc.secret))
			}
			if signer != nil {
				t.Errorf("[%s] no signer may be returned alongside the refusal", tc.reference)
			}
			if !errors.Is(err, joseerror.ErrInvalidPrivateKey) {
				t.Errorf("[%s] the refusal must carry the key error class, got %v", tc.reference, err)
			}
		})
	}
}

func TestNewValidator_RefusesASecretShorterThanTheHashOutput(t *testing.T) {
	tests := map[string]struct {
		reference string
		key       crypto.PublicKey
		accept    bool
	}{
		"a secret of exactly the hash output":  {reference: "RFC 7518 3.2", key: common.SecretKey(bytes.Repeat([]byte("k"), 48)), accept: true},
		"a secret longer than the hash output": {reference: "RFC 7518 3.2", key: common.SecretKey(bytes.Repeat([]byte("k"), 48*2)), accept: true},
		"a secret one byte short":              {reference: "RFC 7518 3.2", key: common.SecretKey(bytes.Repeat([]byte("k"), 48-1))},
		"an empty secret":                      {reference: "RFC 7518 3.2", key: common.SecretKey([]byte{})},
		"a typed nil secret":                   {reference: "RFC 7518 3.2", key: common.SecretKey(nil)},
		"a nil public key":                     {reference: "RFC 7517 4", key: nil},
		"a key of the wrong type":              {reference: "RFC 7517 4", key: "not a secret key"},
		"a raw byte slice, not a SecretKey":    {reference: "RFC 7517 4", key: bytes.Repeat([]byte("k"), 48)},
	}

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			validator, err := NewValidator(tc.key)
			if tc.accept {
				if err != nil {
					t.Fatalf("[%s] a key of at least the SHA-384 output size must be accepted, got %v", tc.reference, err)
				}
				return
			}
			if err == nil {
				t.Fatalf("[%s] a validator keyed with %s accepts a mac anyone can forge, so it must be refused", tc.reference, name)
			}
			if validator != nil {
				t.Errorf("[%s] no validator may be returned alongside the refusal", tc.reference)
			}
			if !errors.Is(err, joseerror.ErrInvalidPublicKey) {
				t.Errorf("[%s] the refusal must carry the key error class, got %v", tc.reference, err)
			}
		})
	}
}

func TestNewSigner_AGeneratedSecretIsLongEnough(t *testing.T) {
	signer, err := NewSigner(nil)
	if err != nil {
		t.Fatalf("a generated secret must satisfy the library's own rule, got %v", err)
	}
	secret, ok := signer.Public().(common.SecretKey)
	if !ok {
		t.Fatalf("expected a common.SecretKey, got %T", signer.Public())
	}
	if len(secret) < 48 {
		t.Errorf("[RFC 7518 3.2] a generated secret must be at least the SHA-384 output size of 48 bytes, got %d", len(secret))
	}
}
