package jwe

import (
	"bytes"
	"context"
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
	key, err := jwk.PrivateFromJwk(example.RecipientJWK)
	if err != nil {
		t.Fatalf("reading the %s recipient jwk: %s", example.ID, err)
	}
	return key
}

func exampleKey(t *testing.T, example testvectors.JWEExample) any {
	t.Helper()
	if example.Password != "" {
		return PasswordKey{Password: []byte(example.Password), Count: example.P2C}
	}
	key := recipientKey(t, example)
	if example.Alg == "dir" {
		return DirectKey{Key: key.([]byte), Enc: jwa.GetEncryption(example.Enc)}
	}
	return key
}

func exampleDecrypter(t *testing.T, example testvectors.JWEExample) model.Decrypter {
	t.Helper()
	decrypter, err := GetDecrypter(jwa.GetAlgorithm(example.Alg), exampleKey(t, example))
	if err != nil {
		t.Fatalf("building a %s decrypter for %s: %s", example.Alg, example.ID, err)
	}
	return decrypter
}

func TestDecrypt_RecoversThePlaintextOfEachRFCExample(t *testing.T) {
	byID := examples(t)
	for _, id := range []string{"RFC7516-A.1", "RFC7516-A.3", "RFC7520-5.2", "RFC7520-5.3", "RFC7520-5.4", "RFC7520-5.5", "RFC7520-5.6", "RFC7520-5.7", "RFC7520-5.8", "RFC7520-5.9"} {
		t.Run(id, func(t *testing.T) {
			example := byID[id]
			opts := &model.JWEOptions{MaxDecompressedSize: len(example.Plaintext)}
			head, plaintext, _, err := Decrypt(context.Background(), example.Compact, []model.Decrypter{exampleDecrypter(t, example)}, opts)
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
	for _, id := range []string{"RFC7516-A.1", "RFC7516-A.3", "RFC7520-5.2", "RFC7520-5.3", "RFC7520-5.4", "RFC7520-5.5", "RFC7520-5.6", "RFC7520-5.7", "RFC7520-5.8", "RFC7520-5.9"} {
		t.Run(id, func(t *testing.T) {
			example := byID[id]
			head, err := jsonutils.DecodeBase64urlMap(example.ProtectedHeader)
			if err != nil {
				t.Fatal(err)
			}
			cek, err := exampleDecrypter(t, example).Decrypt(nil, example.EncryptedKey, model.DecrypterOpts{Header: head, Enc: jwa.GetEncryption(example.Enc)})
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
	for _, id := range []string{"RFC7516-A.3", "RFC7520-5.3", "RFC7520-5.6", "RFC7520-5.7", "RFC7520-5.8"} {
		t.Run(id, func(t *testing.T) {
			example := byID[id]
			encrypter, err := GetEncrypter(jwa.GetAlgorithm(example.Alg), exampleKey(t, example))
			if err != nil {
				t.Fatal(err)
			}
			random := slices.Concat(example.P2S, example.CEK, example.KeyWrapIV)
			head := map[string]any{}
			cek, encryptedKey, err := encrypter.WrapKey(bytes.NewReader(random), jwa.GetEncryption(example.Enc), head)
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(cek, example.CEK) || !bytes.Equal(encryptedKey, example.EncryptedKey) {
				t.Errorf("[RFC 7516 5.1 steps 2 to 4] %s: want CEK %x and encrypted key %x, got %x and %x", id, example.CEK, example.EncryptedKey, cek, encryptedKey)
			}
			printed, err := jsonutils.DecodeBase64urlMap(example.ProtectedHeader)
			if err != nil {
				t.Fatal(err)
			}
			for _, name := range []string{"iv", "tag", "p2s", "p2c"} {
				want, inPrinted := printed[name]
				got, inEmitted := head[name]
				if number, isInt := got.(int); isInt {
					got = float64(number)
				}
				if inPrinted != inEmitted || got != want {
					t.Errorf("[RFC 7518 4.7.1, 4.8.1] %s: the '%s' header the encrypter wrote is %v, and the RFC prints %v", id, name, got, want)
				}
			}
		})
	}
}

func TestDecrypt_RefusesTheRFCsCompressedExampleUnlessDecompressionIsOnAndBigEnough(t *testing.T) {
	example := examples(t)["RFC7520-5.9"]
	decrypter := exampleDecrypter(t, example)
	for name, c := range map[string]struct {
		opts *model.JWEOptions
		want error
	}{
		"no options":                       {opts: nil, want: joseerror.ErrUnsupportedAlgorithm},
		"MaxDecompressedSize unset":        {opts: &model.JWEOptions{}, want: joseerror.ErrUnsupportedAlgorithm},
		"MaxDecompressedSize negative":     {opts: &model.JWEOptions{MaxDecompressedSize: -1}, want: joseerror.ErrUnsupportedAlgorithm},
		"MaxDecompressedSize one too few":  {opts: &model.JWEOptions{MaxDecompressedSize: len(example.Plaintext) - 1}, want: joseerror.ErrOutOfBounds},
		"MaxDecompressedSize of one octet": {opts: &model.JWEOptions{MaxDecompressedSize: 1}, want: joseerror.ErrOutOfBounds},
	} {
		t.Run(name, func(t *testing.T) {
			_, plaintext, d, err := Decrypt(context.Background(), example.Compact, []model.Decrypter{decrypter}, c.opts)
			if !errors.Is(err, c.want) || errors.Is(err, joseerror.ErrMalformedToken) || plaintext != nil || d != nil {
				t.Errorf("[RFC 8725bis 3.15] want %v and no plaintext, got %v", c.want, err)
			}
		})
	}
}

func TestDecrypt_RefusesTheRFCsRSA1_5ExamplesEvenWithTheRightKey(t *testing.T) {
	byID := examples(t)
	for _, id := range []string{"RFC7516-A.2", "RFC7520-5.1"} {
		t.Run(id, func(t *testing.T) {
			example := byID[id]
			key := recipientKey(t, example)
			decrypters := []model.Decrypter{}
			for _, alg := range []jwa.Algorithm{jwa.RSAOAEP, jwa.RSAOAEP256} {
				decrypter, err := GetDecrypter(alg, key)
				if err != nil {
					t.Fatal(err)
				}
				decrypters = append(decrypters, decrypter)
			}
			_, plaintext, used, err := Decrypt(context.Background(), example.Compact, decrypters, nil)
			if !errors.Is(err, joseerror.ErrUnsupportedAlgorithm) || plaintext != nil || used != nil {
				t.Errorf("[RFC 8725 3.2] RSA1_5 is not implemented, so want ErrUnsupportedAlgorithm before any key is used, got %v", err)
			}
			if decrypter, err := GetDecrypter(jwa.GetAlgorithm(example.Alg), key); !errors.Is(err, joseerror.ErrUnsupportedAlgorithm) || decrypter != nil {
				t.Errorf("[RFC 8725 3.2] want no RSA1_5 decrypter, got %v", err)
			}
		})
	}
}
