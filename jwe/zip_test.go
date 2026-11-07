package jwe

import (
	"bytes"
	"compress/flate"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"encoding/base64"
	"encoding/json"
	"errors"
	"runtime"
	"strings"
	"testing"

	"github.com/MichaelFraser99/go-jose/joseerror"
	"github.com/MichaelFraser99/go-jose/jwa"
	"github.com/MichaelFraser99/go-jose/model"
)

func deflate(t *testing.T, plaintext []byte) []byte {
	t.Helper()
	var compressed bytes.Buffer
	writer, err := flate.NewWriter(&compressed, flate.BestCompression)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := writer.Write(plaintext); err != nil {
		t.Fatal(err)
	}
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}
	return compressed.Bytes()
}

func zipToken(t *testing.T, key []byte, zip any, content []byte) string {
	t.Helper()
	head, err := json.Marshal(map[string]any{"alg": "dir", "enc": "A128GCM", "zip": zip})
	if err != nil {
		t.Fatal(err)
	}
	encodedHead := base64.RawURLEncoding.EncodeToString(head)
	block, err := aes.NewCipher(key)
	if err != nil {
		t.Fatal(err)
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		t.Fatal(err)
	}
	iv := randomBytes(t, 12)
	sealed := aead.Seal(nil, iv, content, []byte(encodedHead))
	encode := base64.RawURLEncoding.EncodeToString
	return strings.Join([]string{encodedHead, "", encode(iv), encode(sealed[:len(content)]), encode(sealed[len(content):])}, ".")
}

func zipDecrypter(t *testing.T, key []byte) model.Decrypter {
	t.Helper()
	decrypter, err := GetDecrypter(jwa.Dir, DirectKey{Key: key, Enc: jwa.A128GCM})
	if err != nil {
		t.Fatal(err)
	}
	return decrypter
}

func TestDecrypt_InflatesADEFPlaintextUpToMaxDecompressedSize(t *testing.T) {
	key := randomBytes(t, 16)
	decrypter := zipDecrypter(t, key)
	message := []byte(strings.Repeat("You can trust us to stick with you through thick and thin. ", 20))
	token := zipToken(t, key, "DEF", deflate(t, message))
	for name, limit := range map[string]int{"exactly the plaintext's length": len(message), "far more than it": 1 << 30} {
		t.Run(name, func(t *testing.T) {
			head, plaintext, used, err := Decrypt(context.Background(), token, []model.Decrypter{decrypter}, &model.JoseOptions{MaxDecompressedSize: limit})
			if err != nil || !bytes.Equal(plaintext, message) || used != decrypter || head["zip"] != "DEF" {
				t.Errorf("[RFC 7516 5.2 step 16] want the inflated plaintext and the header naming zip, got %d octets, %v and %v", len(plaintext), head, err)
			}
		})
	}
	empty := zipToken(t, key, "DEF", deflate(t, nil))
	if _, plaintext, _, err := Decrypt(context.Background(), empty, []model.Decrypter{decrypter}, &model.JoseOptions{MaxDecompressedSize: 1}); err != nil || plaintext == nil || len(plaintext) != 0 {
		t.Errorf("[RFC 7516 5.2 step 16] an empty DEF plaintext must inflate to an empty, non-nil slice, got %v and %v", plaintext, err)
	}
}

func TestDecrypt_RefusesAZipItCannotOrMayNotInflate(t *testing.T) {
	key := randomBytes(t, 16)
	decrypter := zipDecrypter(t, key)
	message := []byte(strings.Repeat("a", 1000))
	compressed := deflate(t, message)
	on := &model.JoseOptions{MaxDecompressedSize: 1 << 20}
	for _, c := range []struct {
		name      string
		token     string
		opts      *model.JoseOptions
		want      error
		malformed bool
		clause    string
	}{
		{name: "decompression off", token: zipToken(t, key, "DEF", compressed), want: joseerror.ErrUnsupportedAlgorithm, clause: "RFC 7516 4.1.3"},
		{name: "one octet more than MaxDecompressedSize", token: zipToken(t, key, "DEF", compressed), opts: &model.JoseOptions{MaxDecompressedSize: 999}, want: joseerror.ErrOutOfBounds, clause: "RFC 8725bis 3.15"},
		{name: "a zip in the wrong case", token: zipToken(t, key, "def", compressed), opts: on, want: joseerror.ErrUnsupportedAlgorithm, clause: "RFC 7516 4.1.3"},
		{name: "an empty zip", token: zipToken(t, key, "", compressed), opts: on, want: joseerror.ErrUnsupportedAlgorithm, clause: "RFC 7516 4.1.3"},
		{name: "a zip naming GZIP", token: zipToken(t, key, "GZIP", compressed), opts: on, want: joseerror.ErrUnsupportedAlgorithm, clause: "RFC 7516 4.1.3"},
		{name: "a zip that is not a string", token: zipToken(t, key, []any{"DEF"}, compressed), opts: on, want: joseerror.ErrMalformedClaim, malformed: true, clause: "RFC 7516 4.1.3"},
		{name: "a zip of null", token: zipToken(t, key, nil, compressed), opts: on, want: joseerror.ErrMalformedClaim, malformed: true, clause: "RFC 7516 4.1.3"},
		{name: "a plaintext that is not DEFLATE", token: zipToken(t, key, "DEF", []byte{0xff, 0xff, 0xff, 0xff}), opts: on, want: joseerror.ErrMalformedToken, malformed: true, clause: "RFC 1951"},
		{name: "an empty plaintext", token: zipToken(t, key, "DEF", nil), opts: on, want: joseerror.ErrMalformedToken, malformed: true, clause: "RFC 1951"},
		{name: "a truncated DEFLATE stream", token: zipToken(t, key, "DEF", compressed[:len(compressed)/2]), opts: on, want: joseerror.ErrMalformedToken, malformed: true, clause: "RFC 1951"},
		{name: "a stream that fails the tag", token: zipToken(t, randomBytes(t, 16), "DEF", []byte{0xff}), opts: on, want: joseerror.ErrDecryptionFailed, clause: "RFC 7516 11.5"},
	} {
		t.Run(c.name, func(t *testing.T) {
			_, plaintext, used, err := Decrypt(context.Background(), c.token, []model.Decrypter{decrypter}, c.opts)
			if !errors.Is(err, c.want) || plaintext != nil || used != nil {
				t.Errorf("[%s] want %v and no plaintext, got %v", c.clause, c.want, err)
			}
			if errors.Is(err, joseerror.ErrMalformedToken) != c.malformed {
				t.Errorf("[%s] want ErrMalformedToken %v, got %v", c.clause, c.malformed, err)
			}
		})
	}
}

func TestDecrypt_ADecompressionBombStopsAtMaxDecompressedSize(t *testing.T) {
	key := randomBytes(t, 16)
	bomb := deflate(t, make([]byte, 64<<20))
	token := zipToken(t, key, "DEF", bomb)
	var before, after runtime.MemStats
	runtime.GC()
	runtime.ReadMemStats(&before)
	_, plaintext, _, err := Decrypt(context.Background(), token, []model.Decrypter{zipDecrypter(t, key)}, &model.JoseOptions{MaxDecompressedSize: 1 << 20})
	runtime.ReadMemStats(&after)
	if !errors.Is(err, joseerror.ErrOutOfBounds) || plaintext != nil {
		t.Fatalf("[RFC 8725bis 3.15] %d octets that inflate to 64 MiB must be refused with ErrOutOfBounds, got %v", len(bomb), err)
	}
	if allocated := after.TotalAlloc - before.TotalAlloc; allocated > 16<<20 {
		t.Errorf("[RFC 8725bis 3.15] refusing a 64 MiB bomb at a 1 MiB bound allocated %d MiB, so inflation did not stop at the bound", allocated>>20)
	}
}

func TestParseHeader_RefusesZipUnlessDecompressionIsOn(t *testing.T) {
	key := randomBytes(t, 16)
	token := zipToken(t, key, "DEF", deflate(t, []byte("p")))
	if _, err := ParseHeader(token, nil); !errors.Is(err, joseerror.ErrUnsupportedAlgorithm) {
		t.Errorf("[RFC 7516 4.1.3] want ErrUnsupportedAlgorithm without MaxDecompressedSize, got %v", err)
	}
	if head, err := ParseHeader(token, &model.JoseOptions{MaxDecompressedSize: 1}); err != nil || head["zip"] != "DEF" {
		t.Errorf("[RFC 7516 4.1.3] with MaxDecompressedSize set, ParseHeader must return the header, got %v and %v", head, err)
	}
}
