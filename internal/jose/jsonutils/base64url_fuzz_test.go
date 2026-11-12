package jsonutils

import (
	"bytes"
	"encoding/base64"
	"strings"
	"testing"
)

func decodeByTheAlphabet(encoded string) ([]byte, bool) {
	const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"
	for i := 0; i < len(encoded); i++ {
		if strings.IndexByte(alphabet, encoded[i]) < 0 {
			return nil, false
		}
	}
	decoded, err := base64.RawURLEncoding.Strict().DecodeString(encoded)
	return decoded, err == nil
}

func FuzzDecodeBase64url_AcceptsExactlyTheRFC7515Section2Alphabet(f *testing.F) {
	for _, seed := range []string{"", "A", "AQ", "AQI", "AQID", "_x", "AQ\nID", "AQ\r\nID", "AQID\n", "AQ==", "+w", "AQ\x00ID", "eyJhbGciOiJFUzI1NiJ9"} {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, encoded string) {
		want, valid := decodeByTheAlphabet(encoded)
		got, err := DecodeBase64url(encoded)
		if valid != (err == nil) || valid && !bytes.Equal(got, want) {
			t.Errorf("[RFC 7515 2] %q: want %x and valid %v, got %x and %v", encoded, want, valid, got, err)
		}
	})
}

func BenchmarkDecodeBase64url(b *testing.B) {
	encoded := base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{0xa5, 0x5a, 0x0f}, 1<<18))
	b.SetBytes(int64(len(encoded)))
	for b.Loop() {
		if _, err := DecodeBase64url(encoded); err != nil {
			b.Fatal(err)
		}
	}
}
