package jwe

import (
	"bytes"
	"context"
	"crypto"
	"crypto/pbkdf2"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"math"
	"slices"
	"testing"

	"github.com/MichaelFraser99/go-jose/internal/algorithms/aeskw"
	"github.com/MichaelFraser99/go-jose/joseerror"
	"github.com/MichaelFraser99/go-jose/jwa"
	"github.com/MichaelFraser99/go-jose/model"
)

func keyedHeaderToken(t *testing.T, head map[string]any, encryptedKeySize int) string {
	t.Helper()
	encoded, err := json.Marshal(head)
	if err != nil {
		t.Fatal(err)
	}
	return base64.RawURLEncoding.EncodeToString(encoded) + "." + base64.RawURLEncoding.EncodeToString(make([]byte, encryptedKeySize)) + ".AAAAAAAAAAAAAAAA.AA.AAAAAAAAAAAAAAAAAAAAAA"
}

type headerCase struct {
	name      string
	head      map[string]any
	opts      *model.JoseOptions
	want      error
	malformed bool
	clause    string
}

func checkHeaderCases(t *testing.T, alg jwa.Algorithm, encryptedKeySize int, decrypter model.Decrypter, cases []headerCase) {
	t.Helper()
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			head := map[string]any{"alg": alg.String(), "enc": "A128GCM"}
			for name, value := range c.head {
				if value == nil {
					delete(head, name)
					continue
				}
				head[name] = value
			}
			_, plaintext, used, err := Decrypt(context.Background(), keyedHeaderToken(t, head, encryptedKeySize), []model.Decrypter{decrypter}, c.opts)
			if !errors.Is(err, c.want) || plaintext != nil || used != nil {
				t.Errorf("[%s] want %v and no plaintext, got %v", c.clause, c.want, err)
			}
			if errors.Is(err, joseerror.ErrMalformedToken) != c.malformed {
				t.Errorf("[%s] ErrMalformedToken marks a header that breaks the RFCs and nothing else; want it %v, got %v", c.clause, c.malformed, err)
			}
		})
	}
}

func TestDecrypt_ChecksTheAESGCMKeyWrapParameters(t *testing.T) {
	decrypter := pairFor(t, jwa.A128GCMKW, jwa.A128GCM).decrypter
	iv, tag := "AAAAAAAAAAAAAAAA", "AAAAAAAAAAAAAAAAAAAAAA"
	checkHeaderCases(t, jwa.A128GCMKW, 16, decrypter, []headerCase{
		{name: "a well-formed iv and tag reach the key", head: map[string]any{"iv": iv, "tag": tag}, want: joseerror.ErrDecryptionFailed, clause: "RFC 7518 4.7.1"},
		{name: "no iv", head: map[string]any{"tag": tag}, want: joseerror.ErrMissingClaim, malformed: true, clause: "RFC 7518 4.7.1.1"},
		{name: "no tag", head: map[string]any{"iv": iv}, want: joseerror.ErrMissingClaim, malformed: true, clause: "RFC 7518 4.7.1.2"},
		{name: "an iv that is not a string", head: map[string]any{"iv": 12, "tag": tag}, want: joseerror.ErrMalformedClaim, malformed: true, clause: "RFC 7518 4.7.1.1"},
		{name: "an iv that is not base64url", head: map[string]any{"iv": "AAAAAAAAAAAAAAA=", "tag": tag}, want: joseerror.ErrMalformedClaim, malformed: true, clause: "RFC 7518 4.7.1.1"},
		{name: "an 11-octet iv", head: map[string]any{"iv": "AAAAAAAAAAAAAAA", "tag": tag}, want: joseerror.ErrMalformedClaim, malformed: true, clause: "RFC 7518 4.7"},
		{name: "a 13-octet iv", head: map[string]any{"iv": "AAAAAAAAAAAAAAAAAA", "tag": tag}, want: joseerror.ErrMalformedClaim, malformed: true, clause: "RFC 7518 4.7"},
		{name: "an empty iv", head: map[string]any{"iv": "", "tag": tag}, want: joseerror.ErrMalformedClaim, malformed: true, clause: "RFC 7518 4.7"},
		{name: "a 15-octet tag", head: map[string]any{"iv": iv, "tag": "AAAAAAAAAAAAAAAAAAAA"}, want: joseerror.ErrMalformedClaim, malformed: true, clause: "RFC 7518 4.7"},
		{name: "a 17-octet tag", head: map[string]any{"iv": iv, "tag": "AAAAAAAAAAAAAAAAAAAAAAA"}, want: joseerror.ErrMalformedClaim, malformed: true, clause: "RFC 7518 4.7"},
		{name: "a tag that is not a string", head: map[string]any{"iv": iv, "tag": []any{"x"}}, want: joseerror.ErrMalformedClaim, malformed: true, clause: "RFC 7518 4.7.1.2"},
		{name: "a short iv on an alg outside the allow-list", head: map[string]any{"iv": "AA", "tag": tag}, opts: &model.JoseOptions{AllowedKeyManagementAlgorithms: []jwa.Algorithm{jwa.A128KW}}, want: joseerror.ErrMalformedClaim, malformed: true, clause: "RFC 7516 5.2 step 5"},
	})
}

func TestDecrypt_AnAESGCMKeyWrapEncryptedKeyMustBeTheCEKsLength(t *testing.T) {
	pair := pairFor(t, jwa.A128GCMKW, jwa.A128GCM)
	token, err := Encrypt(pair.encrypter, jwa.A128GCM, []byte("p"), nil)
	if err != nil {
		t.Fatal(err)
	}
	parts := decodedParts(t, token)
	for name, key := range map[string][]byte{"one octet short": parts[1][:15], "one octet long": append(bytes.Clone(parts[1]), 0), "empty": {}} {
		t.Run(name, func(t *testing.T) {
			_, _, _, err := Decrypt(context.Background(), encodeParts(withPartsOf(parts, 1, key)), []model.Decrypter{pair.decrypter}, nil)
			if !errors.Is(err, joseerror.ErrMalformedToken) {
				t.Errorf("[RFC 7518 4.7] the encrypted key is the GCM ciphertext of the CEK, so it must be 16 octets for A128GCM, got %v", err)
			}
		})
	}
}

func TestAESGCMKeyWrap_TheHeaderTagAuthenticatesTheEncryptedKey(t *testing.T) {
	pair := pairFor(t, jwa.A256GCMKW, jwa.A256GCM)
	head := map[string]any{}
	cek, encryptedKey, err := pair.encrypter.WrapKey(randReader(t), jwa.A256GCM, head)
	if err != nil {
		t.Fatal(err)
	}
	if got, err := pair.decrypter.Decrypt(nil, encryptedKey, model.DecrypterOpts{Header: head, Enc: jwa.A256GCM}); err != nil || !bytes.Equal(got, cek) {
		t.Fatalf("[RFC 7518 4.7] the decrypter must recover the CEK under the header's iv and tag, got %x and %v", got, err)
	}
	for _, name := range []string{"iv", "tag"} {
		t.Run(name, func(t *testing.T) {
			changed := map[string]any{"iv": head["iv"], "tag": head["tag"]}
			octets, err := base64.RawURLEncoding.DecodeString(head[name].(string))
			if err != nil {
				t.Fatal(err)
			}
			octets[0] ^= 1
			changed[name] = base64.RawURLEncoding.EncodeToString(octets)
			if got, err := pair.decrypter.Decrypt(nil, encryptedKey, model.DecrypterOpts{Header: changed, Enc: jwa.A256GCM}); err == nil || got != nil {
				t.Errorf("[RFC 7518 4.7] with one bit of the '%s' header changed, GCM must refuse the encrypted key, got %x", name, got)
			}
		})
	}
}

func randReader(t *testing.T) io.Reader {
	t.Helper()
	return bytes.NewReader(randomBytes(t, 4096))
}

func TestEncrypt_EachAESGCMKeyWrapAndPBES2TokenHasAFreshIVOrSalt(t *testing.T) {
	for alg, name := range map[jwa.Algorithm]string{jwa.A128GCMKW: "iv", jwa.PBES2HS256A128KW: "p2s"} {
		t.Run(alg.String(), func(t *testing.T) {
			encrypter := pairFor(t, alg, jwa.A128GCM).encrypter
			seen := map[any]bool{}
			for range 8 {
				token, err := Encrypt(encrypter, jwa.A128GCM, []byte("p"), nil)
				if err != nil {
					t.Fatal(err)
				}
				head, err := ParseHeader(token, nil)
				if err != nil {
					t.Fatal(err)
				}
				if seen[head[name]] {
					t.Fatalf("[RFC 7518 8.4, 4.8.1.1] the '%s' header %v repeated", name, head[name])
				}
				seen[head[name]] = true
			}
		})
	}
}

func TestDecrypt_ChecksThePBES2Parameters(t *testing.T) {
	decrypter := &scriptedDecrypter{alg: jwa.PBES2HS256A128KW}
	salt := "AAAAAAAAAAA"
	checkHeaderCases(t, jwa.PBES2HS256A128KW, 24, decrypter, []headerCase{
		{name: "an 8-octet p2s and a p2c of 1000 reach the key", head: map[string]any{"p2s": salt, "p2c": 1000}, want: joseerror.ErrDecryptionFailed, clause: "RFC 7518 4.8.1"},
		{name: "a p2c of 1e3, which is an integer", head: map[string]any{"p2s": salt, "p2c": 1e3}, want: joseerror.ErrDecryptionFailed, clause: "RFC 7518 4.8.1.2"},
		{name: "a p2c of 1, which is only below the recommendation", head: map[string]any{"p2s": salt, "p2c": 1}, want: joseerror.ErrDecryptionFailed, clause: "RFC 7518 4.8.1.2"},
		{name: "no p2s", head: map[string]any{"p2c": 1000}, want: joseerror.ErrMissingClaim, malformed: true, clause: "RFC 7518 4.8.1.1"},
		{name: "a 7-octet p2s", head: map[string]any{"p2s": "AAAAAAAAAA", "p2c": 1000}, want: joseerror.ErrMalformedClaim, malformed: true, clause: "RFC 7518 4.8.1.1"},
		{name: "an empty p2s", head: map[string]any{"p2s": "", "p2c": 1000}, want: joseerror.ErrMalformedClaim, malformed: true, clause: "RFC 7518 4.8.1.1"},
		{name: "a p2s that is not base64url", head: map[string]any{"p2s": "AAAAAAAAAAA=", "p2c": 1000}, want: joseerror.ErrMalformedClaim, malformed: true, clause: "RFC 7518 4.8.1.1"},
		{name: "a p2s that is not a string", head: map[string]any{"p2s": 12345678, "p2c": 1000}, want: joseerror.ErrMalformedClaim, malformed: true, clause: "RFC 7518 4.8.1.1"},
		{name: "no p2c", head: map[string]any{"p2s": salt}, want: joseerror.ErrMissingClaim, malformed: true, clause: "RFC 7518 4.8.1.2"},
		{name: "a p2c of 0", head: map[string]any{"p2s": salt, "p2c": 0}, want: joseerror.ErrMalformedClaim, malformed: true, clause: "RFC 7518 4.8.1.2"},
		{name: "a negative p2c", head: map[string]any{"p2s": salt, "p2c": -1000}, want: joseerror.ErrMalformedClaim, malformed: true, clause: "RFC 7518 4.8.1.2"},
		{name: "a fractional p2c", head: map[string]any{"p2s": salt, "p2c": 1000.5}, want: joseerror.ErrMalformedClaim, malformed: true, clause: "RFC 7518 4.8.1.2"},
		{name: "a p2c that is a string", head: map[string]any{"p2s": salt, "p2c": "1000"}, want: joseerror.ErrMalformedClaim, malformed: true, clause: "RFC 7518 4.8.1.2"},
		{name: "a p2c that is a boolean", head: map[string]any{"p2s": salt, "p2c": true}, want: joseerror.ErrMalformedClaim, malformed: true, clause: "RFC 7518 4.8.1.2"},
		{name: "a p2c of null", head: map[string]any{"p2s": salt, "p2c": json.RawMessage("null")}, want: joseerror.ErrMalformedClaim, malformed: true, clause: "RFC 7518 4.8.1.2"},
		{name: "a short p2s on an alg outside the allow-list", head: map[string]any{"p2s": "AA", "p2c": 1000}, opts: &model.JoseOptions{AllowedKeyManagementAlgorithms: []jwa.Algorithm{jwa.A128KW}}, want: joseerror.ErrMalformedClaim, malformed: true, clause: "RFC 7516 5.2 step 5"},
	})
}

func TestDecrypt_BoundsTheP2CAPeerChooses(t *testing.T) {
	decrypter := &scriptedDecrypter{alg: jwa.PBES2HS256A128KW}
	salt := "AAAAAAAAAAA"
	checkHeaderCases(t, jwa.PBES2HS256A128KW, 24, decrypter, []headerCase{
		{name: "twice OWASP's figure, the default bound", head: map[string]any{"p2s": salt, "p2c": 1_200_000}, want: joseerror.ErrDecryptionFailed, clause: "RFC 8725bis 3.13"},
		{name: "one more than the default bound", head: map[string]any{"p2s": salt, "p2c": 1_200_001}, want: joseerror.ErrOutOfBounds, clause: "RFC 8725bis 3.13"},
		{name: "one more than the default bound with a negative MaxPBES2Count", head: map[string]any{"p2s": salt, "p2c": 1_200_001}, opts: &model.JoseOptions{MaxPBES2Count: -1}, want: joseerror.ErrOutOfBounds, clause: "RFC 8725bis 3.13"},
		{name: "a p2c too large for an int", head: map[string]any{"p2s": salt, "p2c": 1e300}, want: joseerror.ErrOutOfBounds, clause: "RFC 8725bis 3.13"},
		{name: "a p2c at a lowered bound", head: map[string]any{"p2s": salt, "p2c": 5000}, opts: &model.JoseOptions{MaxPBES2Count: 5000}, want: joseerror.ErrDecryptionFailed, clause: "RFC 8725bis 3.13"},
		{name: "a p2c above a lowered bound", head: map[string]any{"p2s": salt, "p2c": 5001}, opts: &model.JoseOptions{MaxPBES2Count: 5000}, want: joseerror.ErrOutOfBounds, clause: "RFC 8725bis 3.13"},
		{name: "a p2c above the default bound that a raised bound allows", head: map[string]any{"p2s": salt, "p2c": 1_200_001}, opts: &model.JoseOptions{MaxPBES2Count: 1_200_001, AllowedKeyManagementAlgorithms: []jwa.Algorithm{jwa.PBES2HS256A128KW}}, want: joseerror.ErrDecryptionFailed, clause: "RFC 8725bis 3.13"},
		{name: "a p2c below the recommendation when it is required", head: map[string]any{"p2s": salt, "p2c": 999}, opts: &model.JoseOptions{RequireRecommendedPBES2Count: true}, want: joseerror.ErrOutOfBounds, clause: "RFC 7518 4.8.1.2"},
		{name: "a p2c at the recommendation when it is required", head: map[string]any{"p2s": salt, "p2c": 1000}, opts: &model.JoseOptions{RequireRecommendedPBES2Count: true}, want: joseerror.ErrDecryptionFailed, clause: "RFC 7518 4.8.1.2"},
		{name: "a p2c above the bound on an alg outside the allow-list", head: map[string]any{"p2s": salt, "p2c": 1_200_001}, opts: &model.JoseOptions{AllowedKeyManagementAlgorithms: []jwa.Algorithm{jwa.A128KW}}, want: joseerror.ErrUnsupportedAlgorithm, clause: "RFC 7516 5.2 step 5"},
	})
}

func TestDecrypt_RefusesAnOversizeP2CBeforeAnyPBKDF2Runs(t *testing.T) {
	decrypter := pairFor(t, jwa.PBES2HS512A256KW, jwa.A256GCM).decrypter
	called := 0
	opts := &model.JoseOptions{MaxPBES2Count: 1000, OnDecrypterError: func(model.Decrypter, error) { called++ }}
	token := keyedHeaderToken(t, map[string]any{"alg": "PBES2-HS512+A256KW", "enc": "A128GCM", "p2s": "AAAAAAAAAAA", "p2c": 100_000}, 24)
	_, _, _, err := Decrypt(context.Background(), token, []model.Decrypter{decrypter, decrypter, decrypter}, opts)
	if !errors.Is(err, joseerror.ErrOutOfBounds) || called != 0 {
		t.Errorf("[RFC 8725bis 3.13] a p2c above MaxPBES2Count must be refused with ErrOutOfBounds before any decrypter runs, got %v after %d decrypter failures", err, called)
	}
}

type lowCountEncrypter struct {
	password []byte
	count    int
}

func (l lowCountEncrypter) Alg() jwa.Algorithm       { return jwa.PBES2HS256A128KW }
func (l lowCountEncrypter) Public() crypto.PublicKey { return nil }

func (l lowCountEncrypter) WrapKey(random io.Reader, enc jwa.Encryption, header map[string]any) ([]byte, []byte, error) {
	saltInput, cek := make([]byte, 8), make([]byte, cekSizes[enc])
	if _, err := io.ReadFull(random, saltInput); err != nil {
		return nil, nil, err
	}
	if _, err := io.ReadFull(random, cek); err != nil {
		return nil, nil, err
	}
	salt := append([]byte("PBES2-HS256+A128KW\x00"), saltInput...)
	kek, err := pbkdf2.Key(sha256.New, string(l.password), salt, l.count, 16)
	if err != nil {
		return nil, nil, err
	}
	wrapped, err := aeskw.Wrap(kek, cek)
	if err != nil {
		return nil, nil, err
	}
	header["p2s"] = base64.RawURLEncoding.EncodeToString(saltInput)
	header["p2c"] = l.count
	return cek, wrapped, nil
}

func TestDecrypt_AcceptsALowP2CUnlessTheRecommendationIsRequired(t *testing.T) {
	password := []byte("correct horse battery staple")
	decrypter, err := GetDecrypter(jwa.PBES2HS256A128KW, PasswordKey{Password: password})
	if err != nil {
		t.Fatal(err)
	}
	for _, count := range []int{1, 999} {
		token, err := Encrypt(lowCountEncrypter{password: password, count: count}, jwa.A128GCM, []byte("low"), nil)
		if err != nil {
			t.Fatal(err)
		}
		if _, plaintext, _, err := Decrypt(context.Background(), token, []model.Decrypter{decrypter}, nil); err != nil || string(plaintext) != "low" {
			t.Errorf("[RFC 7518 4.8.1.2] a p2c of %d is below the recommended minimum, which is not required, so by default it must decrypt, got %v", count, err)
		}
		if _, plaintext, _, err := Decrypt(context.Background(), token, []model.Decrypter{decrypter}, &model.JoseOptions{RequireRecommendedPBES2Count: true}); !errors.Is(err, joseerror.ErrOutOfBounds) || plaintext != nil {
			t.Errorf("[RFC 7518 4.8.1.2] with RequireRecommendedPBES2Count, a p2c of %d must be refused with ErrOutOfBounds, got %v", count, err)
		}
	}
}

func TestGetEncrypter_APasswordKeyCountIsTheP2C(t *testing.T) {
	password := []byte("password")
	for _, c := range []struct {
		count, want int
	}{{0, 600_000}, {1, 1}, {999, 999}, {1000, 1000}, {4096, 4096}, {2_000_000, 2_000_000}} {
		encrypter, err := GetEncrypter(jwa.PBES2HS256A128KW, PasswordKey{Password: password, Count: c.count})
		if err != nil {
			t.Fatal(err)
		}
		head := map[string]any{}
		if _, _, err := encrypter.WrapKey(randReader(t), jwa.A128GCM, head); err != nil {
			t.Fatal(err)
		}
		if head["p2c"] != c.want {
			t.Errorf("[RFC 7518 4.8.1.2] a Count of %d must write a p2c of %d, got %v", c.count, c.want, head["p2c"])
		}
	}
	for _, count := range []int{-1, math.MinInt} {
		if encrypter, err := GetEncrypter(jwa.PBES2HS256A128KW, PasswordKey{Password: password, Count: count}); !errors.Is(err, joseerror.ErrInvalidPublicKey) || encrypter != nil {
			t.Errorf("[RFC 7518 4.8.1.2] p2c must be a positive integer, so a Count of %d must be refused, got %v", count, err)
		}
		if decrypter, err := GetDecrypter(jwa.PBES2HS256A128KW, PasswordKey{Password: password, Count: count}); err != nil || decrypter == nil {
			t.Errorf("a decrypter reads p2c from each token, so a Count of %d must be ignored, got %v", count, err)
		}
	}
}

func TestPasswordKey_PublicIsACopyOfThePassword(t *testing.T) {
	password := []byte("password")
	pair := pairFor(t, jwa.PBES2HS256A128KW, jwa.A128GCM)
	encrypter, err := GetEncrypter(jwa.PBES2HS256A128KW, PasswordKey{Password: password, Count: 1000})
	if err != nil {
		t.Fatal(err)
	}
	decrypter, err := GetDecrypter(jwa.PBES2HS256A128KW, PasswordKey{Password: password})
	if err != nil {
		t.Fatal(err)
	}
	password[0] ^= 1
	public := encrypter.Public().(PasswordKey)
	if string(public.Password) != "password" || public.Count != 1000 {
		t.Errorf("Public must return the PasswordKey given, copied before the caller changed it, got %+v", public)
	}
	public.Password[0] ^= 1
	if again := encrypter.Public().(PasswordKey); string(again.Password) != "password" {
		t.Errorf("each Public must return a new copy, so changing one must not change the next, got %q", again.Password)
	}
	decrypterPublic := decrypter.Public().(PasswordKey)
	decrypterPublic.Password[0] ^= 1
	token, err := Encrypt(encrypter, jwa.A128GCM, []byte("p"), nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, _, err := Decrypt(context.Background(), token, []model.Decrypter{decrypter, pair.decrypter}, nil); err != nil {
		t.Errorf("changing the password given, or the one Public returns, must not change the keys, got %v", err)
	}
	if public := decrypter.Public().(PasswordKey); string(public.Password) != "password" {
		t.Errorf("a decrypter's Public must return its password, got %+v", public)
	}
}

func TestGetEncrypterFromJwk_RefusesPBES2AndBuildsAESGCMKeyWrap(t *testing.T) {
	for _, alg := range passwordAlgorithms {
		jwk := octJwkFixture([]byte("password"))
		if e, err := GetEncrypterFromJwk(alg, jwk, nil); !errors.Is(err, joseerror.ErrUnsupportedAlgorithm) || e != nil {
			t.Errorf("[RFC 7518 4.8] a jwk holds no password, so GetEncrypterFromJwk(%s) must refuse with ErrUnsupportedAlgorithm, got %v", alg, err)
		}
		if d, err := GetDecrypterFromJwk(alg, jwk, nil); !errors.Is(err, joseerror.ErrUnsupportedAlgorithm) || d != nil {
			t.Errorf("[RFC 7518 4.8] a jwk holds no password, so GetDecrypterFromJwk(%s) must refuse with ErrUnsupportedAlgorithm, got %v", alg, err)
		}
	}
	for alg, size := range map[jwa.Algorithm]int{jwa.A128GCMKW: 16, jwa.A192GCMKW: 24, jwa.A256GCMKW: 32} {
		secret := randomBytes(t, size)
		encrypter, err := GetEncrypterFromJwk(alg, octJwkFixture(secret), nil)
		if err != nil {
			t.Fatalf("[RFC 7518 6.4] %s from an oct jwk: %v", alg, err)
		}
		decrypter, err := GetDecrypterFromJwk(alg, with(octJwkFixture(secret), map[string]any{"key_ops": []any{"unwrapKey"}}), nil)
		if err != nil {
			t.Fatalf("[RFC 7518 6.4] %s from an oct jwk: %v", alg, err)
		}
		token, err := Encrypt(encrypter, jwa.A128GCM, []byte("p"), nil)
		if err != nil {
			t.Fatal(err)
		}
		if _, _, _, err := Decrypt(context.Background(), token, []model.Decrypter{decrypter}, nil); err != nil {
			t.Errorf("[RFC 7516 5.2] %s round trip: %v", alg, err)
		}
		if e, err := GetEncrypterFromJwk(alg, with(octJwkFixture(secret), map[string]any{"key_ops": []any{"encrypt"}}), nil); !errors.Is(err, joseerror.ErrInvalidPublicKey) || e != nil {
			t.Errorf("[RFC 7517 4.3] a %s jwk whose key_ops lacks wrapKey must be refused, got %v", alg, err)
		}
	}
}

func TestDecrypt_MaxPBES2CountBoundsTheIterationsOfTheWholeCall(t *testing.T) {
	password := func() model.Decrypter { return &scriptedDecrypter{alg: jwa.PBES2HS256A128KW} }
	other := &scriptedDecrypter{alg: jwa.A128KW}
	salt := "AAAAAAAAAAA"
	for _, c := range []struct {
		name       string
		p2c        int
		decrypters []model.Decrypter
		opts       *model.JoseOptions
		want       error
	}{
		{name: "two decrypters at half the default bound", p2c: 600_000, decrypters: []model.Decrypter{password(), password()}, want: joseerror.ErrDecryptionFailed},
		{name: "two decrypters at one more than half the default bound", p2c: 600_001, decrypters: []model.Decrypter{password(), password()}, want: joseerror.ErrOutOfBounds},
		{name: "three decrypters at a third of a lowered bound", p2c: 1000, decrypters: []model.Decrypter{password(), password(), password()}, opts: &model.JoseOptions{MaxPBES2Count: 3000}, want: joseerror.ErrDecryptionFailed},
		{name: "three decrypters at one more than a third of a lowered bound", p2c: 1001, decrypters: []model.Decrypter{password(), password(), password()}, opts: &model.JoseOptions{MaxPBES2Count: 3000}, want: joseerror.ErrOutOfBounds},
		{name: "three decrypters whose product is one less than a lowered bound", p2c: 1000, decrypters: []model.Decrypter{password(), password(), password()}, opts: &model.JoseOptions{MaxPBES2Count: 3001}, want: joseerror.ErrDecryptionFailed},
		{name: "decrypters of another alg do not count", p2c: 1_200_000, decrypters: []model.Decrypter{other, password(), other, other}, want: joseerror.ErrDecryptionFailed},
		{name: "a hundred decrypters at a p2c of 12,001", p2c: 12_001, decrypters: slices.Repeat([]model.Decrypter{password()}, 100), want: joseerror.ErrOutOfBounds},
	} {
		t.Run(c.name, func(t *testing.T) {
			called := 0
			opts := &model.JoseOptions{OnDecrypterError: func(model.Decrypter, error) { called++ }}
			if c.opts != nil {
				opts.MaxPBES2Count = c.opts.MaxPBES2Count
			}
			token := keyedHeaderToken(t, map[string]any{"alg": "PBES2-HS256+A128KW", "enc": "A128GCM", "p2s": salt, "p2c": c.p2c}, 24)
			_, plaintext, _, err := Decrypt(context.Background(), token, c.decrypters, opts)
			if !errors.Is(err, c.want) || plaintext != nil {
				t.Errorf("[RFC 8725bis 3.13] want %v, got %v", c.want, err)
			}
			if errors.Is(err, joseerror.ErrOutOfBounds) && called != 0 {
				t.Errorf("[RFC 8725bis 3.13] a token over the bound must be refused before any decrypter runs, but %d ran", called)
			}
		})
	}
}
