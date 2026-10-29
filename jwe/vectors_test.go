package jwe

import (
	"bytes"
	"context"
	"encoding/base64"
	"errors"
	"reflect"
	"slices"
	"testing"

	"github.com/MichaelFraser99/go-jose/internal/jose/jsonutils"
	"github.com/MichaelFraser99/go-jose/internal/testvectors"
	"github.com/MichaelFraser99/go-jose/joseerror"
	"github.com/MichaelFraser99/go-jose/jwa"
	"github.com/MichaelFraser99/go-jose/jwk"
	"github.com/MichaelFraser99/go-jose/model"
)

func examples(t *testing.T) map[string]testvectors.JWEExample {
	t.Helper()
	all, err := testvectors.JWEExamples()
	if err != nil {
		t.Fatal(err)
	}
	byID := map[string]testvectors.JWEExample{}
	for _, example := range all {
		byID[example.ID] = example
	}
	return byID
}

func recipientKey(t *testing.T, example testvectors.JWEExample) any {
	t.Helper()
	if example.RecipientJWK["kty"] == "oct" {
		k, err := base64.RawURLEncoding.DecodeString(example.RecipientJWK["k"].(string))
		if err != nil {
			t.Fatal(err)
		}
		return k
	}
	key, err := jwk.PrivateFromJwk(example.RecipientJWK)
	if err != nil {
		t.Fatalf("reading the %s recipient jwk: %s", example.ID, err)
	}
	return key
}

func exampleDecrypter(t *testing.T, example testvectors.JWEExample) model.Decrypter {
	t.Helper()
	decrypter, err := GetDecrypter(jwa.GetAlgorithm(example.Alg), recipientKey(t, example))
	if err != nil {
		t.Fatalf("building a %s decrypter for %s: %s", example.Alg, example.ID, err)
	}
	return decrypter
}

func TestDecrypt_RecoversThePlaintextOfEachRFCExample(t *testing.T) {
	byID := examples(t)
	for _, id := range []string{"RFC7516-A.1", "RFC7516-A.3", "RFC7520-5.2", "RFC7520-5.6", "RFC7520-5.8"} {
		t.Run(id, func(t *testing.T) {
			example := byID[id]
			head, plaintext, err := Decrypt(context.Background(), example.Compact, []model.Decrypter{exampleDecrypter(t, example)}, nil)
			if err != nil {
				t.Fatalf("[RFC 7516 5.2] %s must decrypt, got %s", id, err)
			}
			if !bytes.Equal(plaintext, example.Plaintext) {
				t.Errorf("[RFC 7516 5.2] %s decrypted to %q, want %q", id, plaintext, example.Plaintext)
			}
			want, err := jsonutils.DecodeBase64urlMap(example.ProtectedHeader)
			if err != nil {
				t.Fatal(err)
			}
			if !reflect.DeepEqual(head, want) {
				t.Errorf("[RFC 7516 5.2] %s header is %v, want %v", id, head, want)
			}
		})
	}
}

func TestDecrypter_RecoversTheCEKOfEachRFCExample(t *testing.T) {
	byID := examples(t)
	for _, id := range []string{"RFC7516-A.1", "RFC7516-A.3", "RFC7520-5.2", "RFC7520-5.6", "RFC7520-5.8"} {
		t.Run(id, func(t *testing.T) {
			example := byID[id]
			cek, err := exampleDecrypter(t, example).Decrypt(nil, example.EncryptedKey, model.DecrypterOpts{Enc: jwa.GetEncryption(example.Enc)})
			if err != nil {
				t.Fatalf("[RFC 7516 5.2 step 10] %s: %s", id, err)
			}
			if !bytes.Equal(cek, example.CEK) {
				t.Errorf("[RFC 7516 5.2 step 10] %s CEK is %x, want %x", id, cek, example.CEK)
			}
		})
	}
}

func TestEncrypt_ReproducesRFC7516AppendixA3(t *testing.T) {
	example := examples(t)["RFC7516-A.3"]
	encrypter, err := GetEncrypter(jwa.A128KW, recipientKey(t, example))
	if err != nil {
		t.Fatal(err)
	}
	random := bytes.NewReader(slices.Concat(example.CEK, example.IV))
	got, err := encrypt(random, encrypter, jwa.A128CBCHS256, example.Plaintext, nil)
	if err != nil {
		t.Fatal(err)
	}
	if got != example.Compact {
		t.Errorf("[RFC 7516 A.3.8] with the appendix's CEK and IV, want\n%s\ngot\n%s", example.Compact, got)
	}
}

func TestEncrypter_WrapsTheCEKAsEachRFCExampleDoes(t *testing.T) {
	byID := examples(t)
	for _, id := range []string{"RFC7516-A.3", "RFC7520-5.6", "RFC7520-5.8"} {
		t.Run(id, func(t *testing.T) {
			example := byID[id]
			encrypter, err := GetEncrypter(jwa.GetAlgorithm(example.Alg), recipientKey(t, example))
			if err != nil {
				t.Fatal(err)
			}
			cek, encryptedKey, err := encrypter.WrapKey(bytes.NewReader(example.CEK), jwa.GetEncryption(example.Enc), map[string]any{})
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(cek, example.CEK) || !bytes.Equal(encryptedKey, example.EncryptedKey) {
				t.Errorf("[RFC 7516 5.1 steps 2 to 4] %s: want CEK %x and encrypted key %x, got %x and %x", id, example.CEK, example.EncryptedKey, cek, encryptedKey)
			}
		})
	}
}

func TestDecrypt_RefusesEachRFCExampleThisLibraryDoesNotImplement(t *testing.T) {
	byID := examples(t)
	for _, id := range []string{"RFC7520-5.3", "RFC7520-5.4", "RFC7520-5.5", "RFC7520-5.7", "RFC7520-5.9"} {
		t.Run(id, func(t *testing.T) {
			example := byID[id]
			decrypter, err := GetDecrypter(jwa.A128KW, make([]byte, 16))
			if err != nil {
				t.Fatal(err)
			}
			_, plaintext, err := Decrypt(context.Background(), example.Compact, []model.Decrypter{decrypter}, nil)
			if !errors.Is(err, joseerror.ErrMalformedToken) || !errors.Is(err, joseerror.ErrUnsupportedAlgorithm) || plaintext != nil {
				t.Errorf("[RFC 7516 5.2 step 5] %s names an alg or zip this library does not implement, so want ErrUnsupportedAlgorithm, got %v", id, err)
			}
		})
	}
}
