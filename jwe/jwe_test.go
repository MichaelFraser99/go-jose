package jwe

import (
	"bytes"
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"math"
	"strings"
	"sync"
	"testing"

	"github.com/MichaelFraser99/go-jose/joseerror"
	"github.com/MichaelFraser99/go-jose/jwa"
	"github.com/MichaelFraser99/go-jose/model"
)

var allEncryptions = []jwa.Encryption{jwa.A128CBCHS256, jwa.A192CBCHS384, jwa.A256CBCHS512, jwa.A128GCM, jwa.A192GCM, jwa.A256GCM}

var cekSizes = map[jwa.Encryption]int{
	jwa.A128CBCHS256: 32, jwa.A192CBCHS384: 48, jwa.A256CBCHS512: 64,
	jwa.A128GCM: 16, jwa.A192GCM: 24, jwa.A256GCM: 32,
}

var rsaTestKey = sync.OnceValues(func() (*rsa.PrivateKey, error) {
	return rsa.GenerateKey(rand.Reader, 2048)
})

func testRSAKey(t *testing.T) *rsa.PrivateKey {
	t.Helper()
	key, err := rsaTestKey()
	if err != nil {
		t.Fatal(err)
	}
	return key
}

func randomBytes(t *testing.T, n int) []byte {
	t.Helper()
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		t.Fatal(err)
	}
	return b
}

type keyPair struct {
	encrypter model.Encrypter
	decrypter model.Decrypter
}

func pairFor(t *testing.T, alg jwa.Algorithm, enc jwa.Encryption) keyPair {
	t.Helper()
	sharedKeySizes := map[jwa.Algorithm]int{jwa.A128KW: 16, jwa.A192KW: 24, jwa.A256KW: 32, jwa.Dir: cekSizes[enc]}
	var public, private any
	if size, shared := sharedKeySizes[alg]; shared {
		public = randomBytes(t, size)
	} else {
		public, private = &testRSAKey(t).PublicKey, testRSAKey(t)
	}
	if private == nil {
		private = public
	}
	encrypter, err := GetEncrypter(alg, public)
	if err != nil {
		t.Fatalf("GetEncrypter(%s): %s", alg, err)
	}
	decrypter, err := GetDecrypter(alg, private)
	if err != nil {
		t.Fatalf("GetDecrypter(%s): %s", alg, err)
	}
	return keyPair{encrypter: encrypter, decrypter: decrypter}
}

var allKeyManagement = []jwa.Algorithm{jwa.RSAOAEP, jwa.RSAOAEP256, jwa.RSAOAEP384, jwa.RSAOAEP512, jwa.A128KW, jwa.A192KW, jwa.A256KW, jwa.Dir}

func TestEncrypt_RoundTripsEveryAlgAndEnc(t *testing.T) {
	for _, alg := range allKeyManagement {
		for _, enc := range allEncryptions {
			t.Run(alg.String()+"/"+enc.String(), func(t *testing.T) {
				pair := pairFor(t, alg, enc)
				for _, plaintext := range [][]byte{{}, []byte("x"), bytes.Repeat([]byte{0xff}, 16), randomBytes(t, 4097)} {
					token, err := Encrypt(pair.encrypter, enc, plaintext, map[string]any{"kid": "k1"})
					if err != nil {
						t.Fatal(err)
					}
					head, got, err := Decrypt(context.Background(), token, []model.Decrypter{pair.decrypter}, nil)
					if err != nil {
						t.Fatalf("[RFC 7516 5.2] decrypting what Encrypt produced: %s", err)
					}
					if !bytes.Equal(got, plaintext) {
						t.Errorf("[RFC 7516 5.2] want %d octets back, got %d", len(plaintext), len(got))
					}
					if head["alg"] != alg.String() || head["enc"] != enc.String() || head["kid"] != "k1" {
						t.Errorf("[RFC 7516 5.1 step 13] header is %v", head)
					}
				}
			})
		}
	}
}

func TestEncrypt_EmitsTheLengthsEncDefines(t *testing.T) {
	ivSizes := map[jwa.Encryption]int{jwa.A128CBCHS256: 16, jwa.A192CBCHS384: 16, jwa.A256CBCHS512: 16, jwa.A128GCM: 12, jwa.A192GCM: 12, jwa.A256GCM: 12}
	tagSizes := map[jwa.Encryption]int{jwa.A128CBCHS256: 16, jwa.A192CBCHS384: 24, jwa.A256CBCHS512: 32, jwa.A128GCM: 16, jwa.A192GCM: 16, jwa.A256GCM: 16}
	for _, enc := range allEncryptions {
		t.Run(enc.String(), func(t *testing.T) {
			token, err := Encrypt(pairFor(t, jwa.A128KW, enc).encrypter, enc, []byte("plaintext"), nil)
			if err != nil {
				t.Fatal(err)
			}
			parts := decodedParts(t, token)
			if len(parts[1]) != cekSizes[enc]+8 || len(parts[2]) != ivSizes[enc] || len(parts[4]) != tagSizes[enc] {
				t.Errorf("[RFC 7518 5.2.3 to 5.3] want a wrapped key of %d, an IV of %d and a tag of %d octets, got %d, %d and %d", cekSizes[enc]+8, ivSizes[enc], tagSizes[enc], len(parts[1]), len(parts[2]), len(parts[4]))
			}
		})
	}
}

func TestEncrypt_ADirTokenHasAnEmptyEncryptedKey(t *testing.T) {
	token, err := Encrypt(pairFor(t, jwa.Dir, jwa.A128GCM).encrypter, jwa.A128GCM, []byte("p"), nil)
	if err != nil {
		t.Fatal(err)
	}
	if segment := strings.Split(token, ".")[1]; segment != "" {
		t.Errorf("[RFC 7516 5.1 step 5] want an empty JWE Encrypted Key, got %q", segment)
	}
}

func decodedParts(t *testing.T, token string) [5][]byte {
	t.Helper()
	var parts [5][]byte
	for i, segment := range strings.Split(token, ".") {
		decoded, err := base64.RawURLEncoding.DecodeString(segment)
		if err != nil {
			t.Fatal(err)
		}
		parts[i] = decoded
	}
	return parts
}

func encodeParts(parts [5][]byte) string {
	segments := make([]string, 5)
	for i, part := range parts {
		segments[i] = base64.RawURLEncoding.EncodeToString(part)
	}
	return strings.Join(segments, ".")
}

func TestDecrypt_RefusesATokenWithAnyOctetChanged(t *testing.T) {
	for _, alg := range []jwa.Algorithm{jwa.RSAOAEP256, jwa.A256KW, jwa.Dir} {
		for _, enc := range []jwa.Encryption{jwa.A128CBCHS256, jwa.A256GCM} {
			pair := pairFor(t, alg, enc)
			token, err := Encrypt(pair.encrypter, enc, []byte("a plaintext of more than one block"), nil)
			if err != nil {
				t.Fatal(err)
			}
			original := decodedParts(t, token)
			for part, name := range []string{"protected header", "encrypted key", "initialization vector", "ciphertext", "authentication tag"} {
				for _, offset := range []int{0, len(original[part]) - 1} {
					if len(original[part]) == 0 {
						continue
					}
					t.Run(alg.String()+"/"+enc.String()+"/"+name, func(t *testing.T) {
						tampered := original
						tampered[part] = bytes.Clone(original[part])
						tampered[part][offset] ^= 0x01
						_, plaintext, err := Decrypt(context.Background(), encodeParts(tampered), []model.Decrypter{pair.decrypter}, nil)
						if err == nil || plaintext != nil {
							t.Fatalf("[RFC 7516 5.2 step 16] a %s changed at octet %d must not decrypt", name, offset)
						}
						if part > 0 && !errors.Is(err, joseerror.ErrDecryptionFailed) {
							t.Errorf("[RFC 7516 11.5] a changed %s must fail as ErrDecryptionFailed, got %v", name, err)
						}
					})
				}
			}
		}
	}
}

func TestDecrypt_EveryFailureToDecryptIsTheSameError(t *testing.T) {
	for _, alg := range []jwa.Algorithm{jwa.RSAOAEP, jwa.A128KW, jwa.Dir} {
		t.Run(alg.String(), func(t *testing.T) {
			pair := pairFor(t, alg, jwa.A128GCM)
			token, err := Encrypt(pair.encrypter, jwa.A128GCM, []byte("p"), nil)
			if err != nil {
				t.Fatal(err)
			}
			wrongKey := pairFor(t, alg, jwa.A128GCM).decrypter
			if alg == jwa.RSAOAEP {
				other, err := rsa.GenerateKey(rand.Reader, 2048)
				if err != nil {
					t.Fatal(err)
				}
				wrongKey, err = GetDecrypter(alg, other)
				if err != nil {
					t.Fatal(err)
				}
			}
			parts := decodedParts(t, token)
			parts[4][0] ^= 1
			_, _, wrongKeyErr := Decrypt(context.Background(), token, []model.Decrypter{wrongKey}, nil)
			_, _, wrongTagErr := Decrypt(context.Background(), encodeParts(parts), []model.Decrypter{pair.decrypter}, nil)
			if !errors.Is(wrongKeyErr, joseerror.ErrDecryptionFailed) || wrongKeyErr == nil || wrongTagErr == nil || wrongKeyErr.Error() != wrongTagErr.Error() {
				t.Errorf("[RFC 7516 11.5] a wrong key and a wrong tag must be indistinguishable, got %q and %q", wrongKeyErr, wrongTagErr)
			}
		})
	}
}

type scriptedDecrypter struct {
	alg   jwa.Algorithm
	cek   []byte
	err   error
	calls *int
	seen  *model.DecrypterOpts
}

func (s scriptedDecrypter) Alg() jwa.Algorithm       { return s.alg }
func (s scriptedDecrypter) Public() crypto.PublicKey { return nil }
func (s scriptedDecrypter) Decrypt(_ io.Reader, _ []byte, opts crypto.DecrypterOpts) ([]byte, error) {
	if s.calls != nil {
		*s.calls++
	}
	if s.seen != nil {
		*s.seen = opts.(model.DecrypterOpts)
	}
	return s.cek, s.err
}

func dirToken(t *testing.T, enc jwa.Encryption, cek []byte) string {
	t.Helper()
	encrypter, err := GetEncrypter(jwa.Dir, cek)
	if err != nil {
		t.Fatal(err)
	}
	token, err := Encrypt(encrypter, enc, []byte("secret"), nil)
	if err != nil {
		t.Fatal(err)
	}
	return token
}

func TestDecrypt_ADecrypterThatFailsOrReturnsTheWrongLengthIsGivenARandomCEK(t *testing.T) {
	cek := randomBytes(t, 32)
	token := dirToken(t, jwa.A128CBCHS256, cek)
	parts := decodedParts(t, token)
	parts[4][0] ^= 1
	_, _, wrongTag := Decrypt(context.Background(), encodeParts(parts), []model.Decrypter{scriptedDecrypter{alg: jwa.Dir, cek: cek}}, nil)
	for name, decrypter := range map[string]scriptedDecrypter{
		"an error":                     {alg: jwa.Dir, err: errors.New("hardware module unavailable")},
		"a CEK one octet short":        {alg: jwa.Dir, cek: cek[:31]},
		"a CEK one octet long":         {alg: jwa.Dir, cek: append(bytes.Clone(cek), 0)},
		"no CEK":                       {alg: jwa.Dir},
		"the right CEK and an error":   {alg: jwa.Dir, cek: cek, err: errors.New("but also failed")},
		"a CEK half of which is right": {alg: jwa.Dir, cek: append(bytes.Clone(cek[:16]), make([]byte, 16)...)},
	} {
		t.Run(name, func(t *testing.T) {
			_, plaintext, err := Decrypt(context.Background(), token, []model.Decrypter{decrypter}, nil)
			if !errors.Is(err, joseerror.ErrDecryptionFailed) || plaintext != nil || err.Error() != wrongTag.Error() {
				t.Errorf("[RFC 7516 11.5] want the error a changed tag gives, %q, with no plaintext, got %v", wrongTag, err)
			}
			_, plaintext, err = Decrypt(context.Background(), token, []model.Decrypter{decrypter, scriptedDecrypter{alg: jwa.Dir, cek: cek}}, nil)
			if err != nil || string(plaintext) != "secret" {
				t.Errorf("[RFC 7516 11.5] a failing decrypter must not stop the next being tried, got %q and %v", plaintext, err)
			}
		})
	}
}

func TestDecrypt_TriesEachDecrypterOfTheTokensAlgInTurn(t *testing.T) {
	cek := randomBytes(t, 16)
	token := dirToken(t, jwa.A128GCM, cek)
	var wrongCalls, rightCalls, otherAlgCalls int
	decrypters := []model.Decrypter{
		scriptedDecrypter{alg: jwa.A128KW, cek: cek, calls: &otherAlgCalls},
		scriptedDecrypter{alg: jwa.Dir, cek: make([]byte, 16), calls: &wrongCalls},
		scriptedDecrypter{alg: jwa.Dir, err: errors.New("no"), calls: &wrongCalls},
		scriptedDecrypter{alg: jwa.Dir, cek: cek, calls: &rightCalls},
	}
	_, plaintext, err := Decrypt(context.Background(), token, decrypters, nil)
	if err != nil || string(plaintext) != "secret" {
		t.Fatalf("[RFC 7516 5.2 step 16] want the plaintext from the third dir decrypter, got %q and %v", plaintext, err)
	}
	if wrongCalls != 2 || rightCalls != 1 || otherAlgCalls != 0 {
		t.Errorf("[RFC 7516 5.2 step 6] want 2 failed dir calls, 1 good one and none of another alg, got %d, %d and %d", wrongCalls, rightCalls, otherAlgCalls)
	}
}

func TestDecrypt_PassesTheDecrypterTheHeaderAndEnc(t *testing.T) {
	cek := randomBytes(t, 16)
	encrypter, err := GetEncrypter(jwa.Dir, cek)
	if err != nil {
		t.Fatal(err)
	}
	token, err := Encrypt(encrypter, jwa.A128GCM, []byte("p"), map[string]any{"kid": "k"})
	if err != nil {
		t.Fatal(err)
	}
	var seen model.DecrypterOpts
	head, _, err := Decrypt(context.Background(), token, []model.Decrypter{scriptedDecrypter{alg: jwa.Dir, cek: cek, seen: &seen}}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if seen.Enc != jwa.A128GCM || seen.Header["kid"] != "k" || seen.Header["alg"] != "dir" {
		t.Errorf("[RFC 7516 5.2 step 10] want the header and enc, got %+v", seen)
	}
	seen.Header["kid"] = "changed"
	if head["kid"] != "k" {
		t.Errorf("a decrypter must not be able to change the header Decrypt returns")
	}
}

func TestDecrypt_RefusesAMalformedToken(t *testing.T) {
	cek := randomBytes(t, 16)
	pair := pairFor(t, jwa.A128KW, jwa.A128GCM)
	kwToken, err := Encrypt(pair.encrypter, jwa.A128GCM, []byte("p"), nil)
	if err != nil {
		t.Fatal(err)
	}
	kwParts := decodedParts(t, kwToken)
	segments := strings.Split(kwToken, ".")
	dirParts := decodedParts(t, dirToken(t, jwa.A128GCM, cek))
	withPart := func(parts [5][]byte, i int, value []byte) string {
		parts[i] = value
		return encodeParts(parts)
	}
	withSegment := func(i int, value string) string {
		changed := append([]string{}, segments...)
		changed[i] = value
		return strings.Join(changed, ".")
	}
	tests := map[string]string{
		"three parts, a JWS":                    strings.Join(segments[:3], "."),
		"four parts":                            strings.Join(segments[:4], "."),
		"six parts":                             kwToken + ".",
		"an empty string":                       "",
		"a padded header":                       withSegment(0, segments[0]+"="),
		"a header that is not JSON":             withSegment(0, base64.RawURLEncoding.EncodeToString([]byte("{"))),
		"a header that is a JSON array":         withSegment(0, base64.RawURLEncoding.EncodeToString([]byte("[]"))),
		"an encrypted key with a padding octet": withSegment(1, segments[1]+"="),
		"an IV that is not base64url":           withSegment(2, "!!!!"),
		"a ciphertext with a space":             withSegment(3, segments[3][:2]+" "+segments[3][2:]),
		"a tag with non-zero pad bits":          withSegment(4, segments[4][:len(segments[4])-1]+"B"),
		"an IV one octet short":                 withPart(kwParts, 2, kwParts[2][:11]),
		"an IV one octet long":                  withPart(kwParts, 2, append(bytes.Clone(kwParts[2]), 0)),
		"an empty IV":                           withPart(kwParts, 2, nil),
		"a tag one octet short":                 withPart(kwParts, 4, kwParts[4][:15]),
		"an empty tag":                          withPart(kwParts, 4, nil),
		"a dir token with an encrypted key":     withPart(dirParts, 1, []byte{0}),
	}
	decrypters := []model.Decrypter{pair.decrypter, scriptedDecrypter{alg: jwa.Dir, cek: cek}}
	for name, token := range tests {
		t.Run(name, func(t *testing.T) {
			_, plaintext, err := Decrypt(context.Background(), token, decrypters, nil)
			if !errors.Is(err, joseerror.ErrMalformedToken) || plaintext != nil {
				t.Errorf("[RFC 7516 5.2 steps 1 to 10] want ErrMalformedToken, got %v", err)
			}
		})
	}
}

func headerToken(t *testing.T, head map[string]any) string {
	t.Helper()
	encoded, err := json.Marshal(head)
	if err != nil {
		t.Fatal(err)
	}
	return base64.RawURLEncoding.EncodeToString(encoded) + "..AAAAAAAAAAAAAAAA.AA.AAAAAAAAAAAAAAAAAAAAAA"
}

func TestDecrypt_ChecksTheHeader(t *testing.T) {
	decrypter := scriptedDecrypter{alg: jwa.Dir, cek: make([]byte, 16)}
	tests := []struct {
		name string
		head map[string]any
		opts *model.JoseOptions
		want []error
	}{
		{name: "no alg", head: map[string]any{"enc": "A128GCM"}, want: []error{joseerror.ErrMissingClaim}},
		{name: "an alg that is not a string", head: map[string]any{"alg": 1, "enc": "A128GCM"}, want: []error{joseerror.ErrMalformedClaim}},
		{name: "a JWS alg", head: map[string]any{"alg": "RS256", "enc": "A128GCM"}, want: []error{joseerror.ErrUnsupportedAlgorithm}},
		{name: "none", head: map[string]any{"alg": "none", "enc": "A128GCM"}, want: []error{joseerror.ErrUnsupportedAlgorithm}},
		{name: "RSA1_5", head: map[string]any{"alg": "RSA1_5", "enc": "A128GCM"}, want: []error{joseerror.ErrUnsupportedAlgorithm}},
		{name: "an alg in the wrong case", head: map[string]any{"alg": "DIR", "enc": "A128GCM"}, want: []error{joseerror.ErrUnsupportedAlgorithm}},
		{name: "an enc as the alg", head: map[string]any{"alg": "A128GCM", "enc": "A128GCM"}, want: []error{joseerror.ErrUnsupportedAlgorithm}},
		{name: "no enc", head: map[string]any{"alg": "dir"}, want: []error{joseerror.ErrMissingClaim}},
		{name: "an enc that is not a string", head: map[string]any{"alg": "dir", "enc": []any{"A128GCM"}}, want: []error{joseerror.ErrMalformedClaim}},
		{name: "an unknown enc", head: map[string]any{"alg": "dir", "enc": "A128CCM"}, want: []error{joseerror.ErrUnsupportedAlgorithm}},
		{name: "an enc in the wrong case", head: map[string]any{"alg": "dir", "enc": "a128gcm"}, want: []error{joseerror.ErrUnsupportedAlgorithm}},
		{name: "an alg as the enc", head: map[string]any{"alg": "dir", "enc": "A128KW"}, want: []error{joseerror.ErrUnsupportedAlgorithm}},
		{name: "zip DEF", head: map[string]any{"alg": "dir", "enc": "A128GCM", "zip": "DEF"}, want: []error{joseerror.ErrUnsupportedAlgorithm}},
		{name: "zip of another type", head: map[string]any{"alg": "dir", "enc": "A128GCM", "zip": 1}, want: []error{joseerror.ErrUnsupportedAlgorithm}},
		{name: "an alg outside the allow-list", head: map[string]any{"alg": "dir", "enc": "A128GCM"}, opts: &model.JoseOptions{AllowedKeyManagementAlgorithms: []jwa.Algorithm{jwa.A128KW}}, want: []error{joseerror.ErrUnsupportedAlgorithm}},
		{name: "an enc outside the allow-list", head: map[string]any{"alg": "dir", "enc": "A128GCM"}, opts: &model.JoseOptions{AllowedContentEncryptionAlgorithms: []jwa.Encryption{jwa.A256GCM}}, want: []error{joseerror.ErrUnsupportedAlgorithm}},
		{name: "a JWS allow-list does not admit the alg", head: map[string]any{"alg": "dir", "enc": "A128GCM"}, opts: &model.JoseOptions{AllowedKeyManagementAlgorithms: []jwa.Algorithm{jwa.RS256}}, want: []error{joseerror.ErrUnsupportedAlgorithm}},
		{name: "crit naming an extension not understood", head: map[string]any{"alg": "dir", "enc": "A128GCM", "crit": []any{"exp"}, "exp": 1}, want: []error{joseerror.ErrMissingCriticalClaim}},
		{name: "crit naming a parameter that is absent", head: map[string]any{"alg": "dir", "enc": "A128GCM", "crit": []any{"exp"}}, opts: &model.JoseOptions{UnderstoodCriticalHeaders: []string{"exp"}}, want: []error{joseerror.ErrMissingCriticalClaim}},
		{name: "an empty crit", head: map[string]any{"alg": "dir", "enc": "A128GCM", "crit": []any{}}, want: []error{joseerror.ErrMalformedClaim}},
		{name: "a typ outside AcceptedTypes", head: map[string]any{"alg": "dir", "enc": "A128GCM", "typ": "JWT"}, opts: &model.JoseOptions{AcceptedTypes: []string{"secevent+jwt"}}, want: []error{joseerror.ErrMalformedClaim}},
		{name: "no kid when one is required", head: map[string]any{"alg": "dir", "enc": "A128GCM"}, opts: &model.JoseOptions{RequireKeyIdentifier: true}, want: []error{joseerror.ErrMissingClaim}},
		{name: "a jku that is not https", head: map[string]any{"alg": "dir", "enc": "A128GCM", "jku": "http://example.com"}, want: []error{joseerror.ErrMalformedClaim}},
		{name: "crit naming enc, which is present", head: map[string]any{"alg": "dir", "enc": "A128GCM", "crit": []any{"enc"}}, opts: &model.JoseOptions{UnderstoodCriticalHeaders: []string{"enc"}}, want: []error{joseerror.ErrMalformedClaim}},
		{name: "crit naming p2c, which is present", head: map[string]any{"alg": "dir", "enc": "A128GCM", "p2c": 1000, "crit": []any{"p2c"}}, opts: &model.JoseOptions{UnderstoodCriticalHeaders: []string{"p2c"}}, want: []error{joseerror.ErrMalformedClaim}},
		{name: "a kid that is not a string", head: map[string]any{"alg": "dir", "enc": "A128GCM", "kid": 7}, want: []error{joseerror.ErrMalformedClaim}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, plaintext, err := Decrypt(context.Background(), headerToken(t, tt.head), []model.Decrypter{decrypter}, tt.opts)
			if !errors.Is(err, joseerror.ErrMalformedToken) || plaintext != nil {
				t.Fatalf("[RFC 7516 5.2 step 5] want ErrMalformedToken, got %v", err)
			}
			for _, want := range tt.want {
				if errors.Is(err, want) {
					return
				}
			}
			t.Errorf("[RFC 7516 4.1] want one of %v, got %v", tt.want, err)
		})
	}
}

func TestDecrypt_AcceptsWhatTheHeaderRulesAllow(t *testing.T) {
	cek := randomBytes(t, 16)
	encrypter, err := GetEncrypter(jwa.Dir, cek)
	if err != nil {
		t.Fatal(err)
	}
	decrypter, err := GetDecrypter(jwa.Dir, cek)
	if err != nil {
		t.Fatal(err)
	}
	tests := []struct {
		name string
		head map[string]any
		opts *model.JoseOptions
	}{
		{name: "an alg and enc inside the allow-lists", opts: &model.JoseOptions{AllowedKeyManagementAlgorithms: []jwa.Algorithm{jwa.A128KW, jwa.Dir}, AllowedContentEncryptionAlgorithms: []jwa.Encryption{jwa.A128GCM}}},
		{name: "a crit naming an understood extension", head: map[string]any{"crit": []any{"exp"}, "exp": 1}, opts: &model.JoseOptions{UnderstoodCriticalHeaders: []string{"exp"}}},
		{name: "a b64 of false, which is a JWS parameter", head: map[string]any{"b64": false}},
		{name: "a b64 that is not a boolean", head: map[string]any{"b64": "no"}},
		{name: "an accepted typ", head: map[string]any{"typ": "JOSE"}, opts: &model.JoseOptions{AcceptedTypes: []string{"JOSE"}}},
		{name: "an unknown parameter", head: map[string]any{"unknown": map[string]any{}}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			token, err := Encrypt(encrypter, jwa.A128GCM, []byte("p"), tt.head)
			if err != nil {
				t.Fatal(err)
			}
			if _, _, err := Decrypt(context.Background(), token, []model.Decrypter{decrypter}, tt.opts); err != nil {
				t.Errorf("[RFC 7516 4.1] want the token accepted, got %v", err)
			}
		})
	}
}

func TestDecrypt_RefusesBadOptions(t *testing.T) {
	cek := randomBytes(t, 16)
	token := dirToken(t, jwa.A128GCM, cek)
	good, err := GetDecrypter(jwa.Dir, cek)
	if err != nil {
		t.Fatal(err)
	}
	var typedNil *rsaTypedNil
	cancelled, cancel := context.WithCancel(context.Background())
	cancel()
	tests := []struct {
		name       string
		ctx        context.Context
		decrypters []model.Decrypter
		opts       *model.JoseOptions
		want       error
		mentions   string
	}{
		{name: "a nil context", ctx: nil, decrypters: []model.Decrypter{good}, want: joseerror.ErrInvalidOptions},
		{name: "a nil decrypter", ctx: context.Background(), decrypters: []model.Decrypter{good, nil}, want: joseerror.ErrInvalidOptions},
		{name: "a typed nil decrypter", ctx: context.Background(), decrypters: []model.Decrypter{typedNil, good}, want: joseerror.ErrInvalidOptions},
		{name: "no decrypters", ctx: context.Background(), want: joseerror.ErrDecryptionFailed},
		{name: "no decrypter of the token's alg", ctx: context.Background(), decrypters: []model.Decrypter{pairFor(t, jwa.A128KW, jwa.A128GCM).decrypter}, want: joseerror.ErrDecryptionFailed},
		{name: "no decrypter of the token's alg, named", ctx: context.Background(), decrypters: []model.Decrypter{pairFor(t, jwa.A128KW, jwa.A128GCM).decrypter}, want: joseerror.ErrDecryptionFailed, mentions: "dir"},
		{name: "more decrypters than MaxKeysTried", ctx: context.Background(), decrypters: []model.Decrypter{good, good, good}, opts: &model.JoseOptions{MaxKeysTried: 2}, want: joseerror.ErrTooManyKeys},
		{name: "a cancelled context", ctx: cancelled, decrypters: []model.Decrypter{good}, want: context.Canceled},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, plaintext, err := Decrypt(tt.ctx, token, tt.decrypters, tt.opts)
			if !errors.Is(err, tt.want) || plaintext != nil || !strings.Contains(err.Error(), tt.mentions) {
				t.Errorf("want %v naming %q, got %v", tt.want, tt.mentions, err)
			}
		})
	}
}

func TestDecrypt_MaxKeysTriedDefaultsTo100(t *testing.T) {
	cek := randomBytes(t, 16)
	token := dirToken(t, jwa.A128GCM, cek)
	right := scriptedDecrypter{alg: jwa.Dir, cek: cek}
	wrong := scriptedDecrypter{alg: jwa.Dir, cek: make([]byte, 16)}
	hundred := append(make([]model.Decrypter, 0, 101), right)
	for len(hundred) < 100 {
		hundred = append(hundred, wrong)
	}
	if _, _, err := Decrypt(context.Background(), token, hundred, &model.JoseOptions{}); err != nil {
		t.Errorf("100 decrypters are within the default, got %v", err)
	}
	if _, _, err := Decrypt(context.Background(), token, append(hundred, wrong), nil); !errors.Is(err, joseerror.ErrTooManyKeys) {
		t.Errorf("101 decrypters exceed the default, want ErrTooManyKeys, got %v", err)
	}
	if _, _, err := Decrypt(context.Background(), token, append(hundred, wrong), &model.JoseOptions{MaxKeysTried: -1}); !errors.Is(err, joseerror.ErrTooManyKeys) {
		t.Errorf("a negative MaxKeysTried means the default, want ErrTooManyKeys, got %v", err)
	}
}

type rsaTypedNil struct{ model.Decrypter }

type headerRewriter struct {
	model.Encrypter
	rewrite func(map[string]any)
	cek     []byte
	key     []byte
}

func (h headerRewriter) WrapKey(random io.Reader, enc jwa.Encryption, header map[string]any) ([]byte, []byte, error) {
	cek, key, err := h.Encrypter.WrapKey(random, enc, header)
	if h.rewrite != nil {
		h.rewrite(header)
	}
	if h.cek != nil {
		cek, err = h.cek, nil
	}
	if h.key != nil {
		key = h.key
	}
	return cek, key, err
}

func TestEncrypt_RefusesWhatItCannotEmit(t *testing.T) {
	kw := pairFor(t, jwa.A128KW, jwa.A128GCM).encrypter
	dir := pairFor(t, jwa.Dir, jwa.A128GCM).encrypter
	var typedNil *headerRewriter
	tests := []struct {
		name      string
		encrypter model.Encrypter
		enc       jwa.Encryption
		head      map[string]any
		want      error
	}{
		{name: "no encrypter", enc: jwa.A128GCM, want: joseerror.ErrInvalidPublicKey},
		{name: "a typed nil encrypter", encrypter: typedNil, enc: jwa.A128GCM, want: joseerror.ErrInvalidPublicKey},
		{name: "an unknown enc", encrypter: kw, enc: jwa.UnknownEncryption, want: joseerror.ErrUnsupportedAlgorithm},
		{name: "an unknown enc with an encrypter that ignores enc", encrypter: headerRewriter{Encrypter: dir, cek: make([]byte, 16)}, enc: jwa.UnknownEncryption, want: joseerror.ErrUnsupportedAlgorithm},
		{name: "an enc outside the enumeration", encrypter: kw, enc: jwa.Encryption(99), want: joseerror.ErrUnsupportedAlgorithm},
		{name: "a head naming another alg", encrypter: kw, enc: jwa.A128GCM, head: map[string]any{"alg": "A256KW"}, want: joseerror.ErrUnsupportedAlgorithm},
		{name: "a head naming another enc", encrypter: kw, enc: jwa.A128GCM, head: map[string]any{"enc": "A256GCM"}, want: joseerror.ErrUnsupportedAlgorithm},
		{name: "a head with an alg that is not a string", encrypter: kw, enc: jwa.A128GCM, head: map[string]any{"alg": 1}, want: joseerror.ErrUnsupportedAlgorithm},
		{name: "a head with zip", encrypter: kw, enc: jwa.A128GCM, head: map[string]any{"zip": "DEF"}, want: joseerror.ErrUnsupportedAlgorithm},
		{name: "a head whose crit names an absent parameter", encrypter: kw, enc: jwa.A128GCM, head: map[string]any{"crit": []any{"exp"}}, want: joseerror.ErrMissingCriticalClaim},
		{name: "a head whose crit names enc", encrypter: kw, enc: jwa.A128GCM, head: map[string]any{"crit": []any{"enc"}}, want: joseerror.ErrMalformedClaim},
		{name: "a head with a jku that is not https", encrypter: kw, enc: jwa.A128GCM, head: map[string]any{"jku": "http://example.com"}, want: joseerror.ErrMalformedClaim},
		{name: "a head holding a value JSON cannot encode", encrypter: kw, enc: jwa.A128GCM, head: map[string]any{"x": make(chan int)}, want: joseerror.ErrMalformedClaim},
		{name: "a head holding NaN", encrypter: kw, enc: jwa.A128GCM, head: map[string]any{"x": math.NaN()}, want: joseerror.ErrMalformedClaim},
		{name: "a dir key of the wrong length for enc", encrypter: dir, enc: jwa.A256GCM, want: joseerror.ErrInvalidPublicKey},
		{name: "an encrypter that rewrites alg", encrypter: headerRewriter{Encrypter: kw, rewrite: func(h map[string]any) { h["alg"] = "none" }}, enc: jwa.A128GCM, want: joseerror.ErrEncryptionError},
		{name: "an encrypter that rewrites enc", encrypter: headerRewriter{Encrypter: kw, rewrite: func(h map[string]any) { h["enc"] = "A256GCM" }}, enc: jwa.A128GCM, want: joseerror.ErrEncryptionError},
		{name: "an encrypter that deletes alg", encrypter: headerRewriter{Encrypter: kw, rewrite: func(h map[string]any) { delete(h, "alg") }}, enc: jwa.A128GCM, want: joseerror.ErrEncryptionError},
		{name: "an encrypter returning a short CEK", encrypter: headerRewriter{Encrypter: kw, cek: make([]byte, 15)}, enc: jwa.A128GCM, want: joseerror.ErrEncryptionError},
		{name: "a dir encrypter returning an encrypted key", encrypter: headerRewriter{Encrypter: dir, key: []byte{1}}, enc: jwa.A128GCM, want: joseerror.ErrEncryptionError},
		{name: "an encrypter adding a malformed parameter", encrypter: headerRewriter{Encrypter: kw, rewrite: func(h map[string]any) { h["x5t"] = "not base64url!" }}, enc: jwa.A128GCM, want: joseerror.ErrMalformedClaim},
		{name: "an encrypter of a JWS alg", encrypter: algOverride{Encrypter: kw, alg: jwa.RS256}, enc: jwa.A128GCM, want: joseerror.ErrUnsupportedAlgorithm},
		{name: "an encrypter of an alg outside the enumeration", encrypter: algOverride{Encrypter: kw, alg: jwa.Algorithm(999)}, enc: jwa.A128GCM, want: joseerror.ErrUnsupportedAlgorithm},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			token, err := Encrypt(tt.encrypter, tt.enc, []byte("p"), tt.head)
			if !errors.Is(err, tt.want) || token != "" {
				t.Errorf("want %v and no token, got %v and %q", tt.want, err, token)
			}
		})
	}
}

type algOverride struct {
	model.Encrypter
	alg jwa.Algorithm
}

func (a algOverride) Alg() jwa.Algorithm { return a.alg }

func TestEncrypt_DoesNotWriteIntoTheCallersHead(t *testing.T) {
	head := map[string]any{"kid": "k"}
	if _, err := Encrypt(pairFor(t, jwa.A128KW, jwa.A128GCM).encrypter, jwa.A128GCM, []byte("p"), head); err != nil {
		t.Fatal(err)
	}
	if len(head) != 1 || head["kid"] != "k" {
		t.Errorf("Encrypt must not modify head, got %v", head)
	}
}

func TestEncrypt_AcceptsAHeadThatNamesTheAlgAndEncInUse(t *testing.T) {
	pair := pairFor(t, jwa.A128KW, jwa.A128GCM)
	token, err := Encrypt(pair.encrypter, jwa.A128GCM, []byte("p"), map[string]any{"alg": "A128KW", "enc": "A128GCM"})
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := Decrypt(context.Background(), token, []model.Decrypter{pair.decrypter}, nil); err != nil {
		t.Error(err)
	}
}

func TestEncrypt_UsesAFreshCEKAndIVEachTime(t *testing.T) {
	encrypter := pairFor(t, jwa.A128KW, jwa.A128GCM).encrypter
	first, err := Encrypt(encrypter, jwa.A128GCM, []byte("p"), nil)
	if err != nil {
		t.Fatal(err)
	}
	second, err := Encrypt(encrypter, jwa.A128GCM, []byte("p"), nil)
	if err != nil {
		t.Fatal(err)
	}
	a, b := decodedParts(t, first), decodedParts(t, second)
	if bytes.Equal(a[1], b[1]) || bytes.Equal(a[2], b[2]) {
		t.Errorf("[RFC 7516 5.1 steps 2 and 9] two encryptions share a wrapped CEK or an IV")
	}
}

func TestEncrypt_RefusesAFailingRandomSource(t *testing.T) {
	tests := []struct {
		name   string
		alg    jwa.Algorithm
		supply int
	}{
		{name: "RSA-OAEP with no CEK", alg: jwa.RSAOAEP, supply: 15},
		{name: "RSA-OAEP with a CEK and no OAEP seed", alg: jwa.RSAOAEP, supply: 16},
		{name: "A128KW with no CEK", alg: jwa.A128KW, supply: 15},
		{name: "A128KW with a CEK and no IV", alg: jwa.A128KW, supply: 16 + 11},
		{name: "dir with no IV", alg: jwa.Dir, supply: 11},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			token, err := encrypt(bytes.NewReader(make([]byte, tt.supply)), pairFor(t, tt.alg, jwa.A128GCM).encrypter, jwa.A128GCM, []byte("p"), nil)
			if !errors.Is(err, joseerror.ErrEncryptionError) || token != "" {
				t.Errorf("want ErrEncryptionError once the random source runs dry, got %v", err)
			}
		})
	}
}
