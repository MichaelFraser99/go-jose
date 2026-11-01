package jwe

import (
	"bytes"
	"context"
	"encoding/base64"
	"errors"
	"maps"
	"math/big"
	"strings"
	"testing"

	"github.com/MichaelFraser99/go-jose/joseerror"
	"github.com/MichaelFraser99/go-jose/jwa"
	"github.com/MichaelFraser99/go-jose/model"
)

var rsaOAEPAlgorithms = []jwa.Algorithm{jwa.RSAOAEP, jwa.RSAOAEP256, jwa.RSAOAEP384, jwa.RSAOAEP512}

var keyWrapSizes = map[jwa.Algorithm]int{jwa.A128KW: 16, jwa.A192KW: 24, jwa.A256KW: 32}

func b64(b []byte) string {
	return base64.RawURLEncoding.EncodeToString(b)
}

func rsaPublicJwkFixture(t *testing.T) map[string]any {
	t.Helper()
	key := testRSAKey(t)
	return map[string]any{"kty": "RSA", "n": b64(key.N.Bytes()), "e": b64(big.NewInt(int64(key.E)).Bytes())}
}

func rsaPrivateJwkFixture(t *testing.T) map[string]any {
	t.Helper()
	key := testRSAKey(t)
	key.Precompute()
	jwk := rsaPublicJwkFixture(t)
	jwk["d"] = b64(key.D.Bytes())
	jwk["p"] = b64(key.Primes[0].Bytes())
	jwk["q"] = b64(key.Primes[1].Bytes())
	jwk["dp"] = b64(key.Precomputed.Dp.Bytes())
	jwk["dq"] = b64(key.Precomputed.Dq.Bytes())
	jwk["qi"] = b64(key.Precomputed.Qinv.Bytes())
	return jwk
}

func octJwkFixture(secret []byte) map[string]any {
	return map[string]any{"kty": "oct", "k": b64(secret)}
}

func with(jwk map[string]any, members map[string]any) map[string]any {
	out := maps.Clone(jwk)
	for name, value := range members {
		if value == nil {
			delete(out, name)
			continue
		}
		out[name] = value
	}
	return out
}

func TestGetEncrypterFromJwk_RoundTripsEachAlgorithm(t *testing.T) {
	type fixture struct {
		public, private map[string]any
		rawDecrypter    func(t *testing.T) model.Decrypter
	}
	fixtures := map[jwa.Algorithm]fixture{}
	for _, alg := range rsaOAEPAlgorithms {
		fixtures[alg] = fixture{
			public:  rsaPublicJwkFixture(t),
			private: rsaPrivateJwkFixture(t),
			rawDecrypter: func(t *testing.T) model.Decrypter {
				d, err := GetDecrypter(alg, testRSAKey(t))
				if err != nil {
					t.Fatal(err)
				}
				return d
			},
		}
	}
	for alg, size := range keyWrapSizes {
		secret := randomBytes(t, size)
		fixtures[alg] = fixture{
			public:  octJwkFixture(secret),
			private: octJwkFixture(secret),
			rawDecrypter: func(t *testing.T) model.Decrypter {
				d, err := GetDecrypter(alg, secret)
				if err != nil {
					t.Fatal(err)
				}
				return d
			},
		}
	}

	for alg, f := range fixtures {
		t.Run(alg.String(), func(t *testing.T) {
			declared := map[string]any{"alg": alg.String(), "use": "enc"}
			encrypter, err := GetEncrypterFromJwk(alg, with(f.public, declared))
			if err != nil {
				t.Fatalf("[RFC 7517 4.2] a %s jwk declared for enc must build an Encrypter, got %v", alg, err)
			}
			decrypter, err := GetDecrypterFromJwk(alg, with(f.private, map[string]any{"alg": alg.String(), "key_ops": []any{"unwrapKey"}}))
			if err != nil {
				t.Fatalf("[RFC 7517 4.3] a %s jwk whose key_ops include unwrapKey must build a Decrypter, got %v", alg, err)
			}
			if encrypter.Alg() != alg || decrypter.Alg() != alg {
				t.Errorf("[RFC 7518 4.1] want %s from both, got %s and %s", alg, encrypter.Alg(), decrypter.Alg())
			}

			plaintext := []byte("Live long and prosper.")
			token, err := Encrypt(encrypter, jwa.A128GCM, plaintext, nil)
			if err != nil {
				t.Fatal(err)
			}
			for name, d := range map[string]model.Decrypter{"the jwk": decrypter, "the raw key": f.rawDecrypter(t)} {
				_, got, _, err := Decrypt(context.Background(), token, []model.Decrypter{d}, nil)
				if err != nil {
					t.Fatalf("[RFC 7516 5.2] a token encrypted to the jwk must decrypt with %s, got %v", name, err)
				}
				if !bytes.Equal(got, plaintext) {
					t.Errorf("[RFC 7516 5.2] decrypting with %s gave %q, want %q", name, got, plaintext)
				}
			}
		})
	}
}

func TestGetDecrypterFromJwk_DecryptsTheRFC7520Examples(t *testing.T) {
	byID := examples(t)
	for id, clause := range map[string]string{"RFC7520-5.2": "RFC 7520 5.2", "RFC7520-5.8": "RFC 7520 5.8"} {
		t.Run(id, func(t *testing.T) {
			example := byID[id]
			decrypter, err := GetDecrypterFromJwk(jwa.GetAlgorithm(example.Alg), example.RecipientJWK)
			if err != nil {
				t.Fatalf("[%s] the published recipient jwk must build a %s Decrypter, got %v", clause, example.Alg, err)
			}
			_, plaintext, _, err := Decrypt(context.Background(), example.Compact, []model.Decrypter{decrypter}, nil)
			if err != nil {
				t.Fatalf("[%s] the published JWE must decrypt, got %v", clause, err)
			}
			if !bytes.Equal(plaintext, example.Plaintext) {
				t.Errorf("[%s] decrypted to %q, want %q", clause, plaintext, example.Plaintext)
			}
		})
	}
}

type jwkCase struct {
	alg    jwa.Algorithm
	jwk    map[string]any
	clause string
}

func checkRefusedBoth(t *testing.T, name string, encrypterJwk, decrypterJwk jwkCase) {
	t.Helper()
	t.Run(name+"/encrypter", func(t *testing.T) {
		encrypter, err := GetEncrypterFromJwk(encrypterJwk.alg, encrypterJwk.jwk)
		if !errors.Is(err, joseerror.ErrInvalidPublicKey) || errors.Is(err, joseerror.ErrUnsupportedAlgorithm) || encrypter != nil {
			t.Errorf("[%s] want ErrInvalidPublicKey alone and a nil Encrypter, got %v and %v", encrypterJwk.clause, err, encrypter)
		}
	})
	t.Run(name+"/decrypter", func(t *testing.T) {
		decrypter, err := GetDecrypterFromJwk(decrypterJwk.alg, decrypterJwk.jwk)
		if !errors.Is(err, joseerror.ErrInvalidPrivateKey) || errors.Is(err, joseerror.ErrUnsupportedAlgorithm) || decrypter != nil {
			t.Errorf("[%s] want ErrInvalidPrivateKey alone and a nil Decrypter, got %v and %v", decrypterJwk.clause, err, decrypter)
		}
	})
}

func TestGetEncrypterFromJwk_TheFixturesAreAcceptedWithoutTheirFault(t *testing.T) {
	secret := randomBytes(t, 16)
	for name, c := range map[string]struct {
		alg             jwa.Algorithm
		public, private map[string]any
	}{
		"RSA-OAEP": {alg: jwa.RSAOAEP, public: rsaPublicJwkFixture(t), private: rsaPrivateJwkFixture(t)},
		"A128KW":   {alg: jwa.A128KW, public: octJwkFixture(secret), private: octJwkFixture(secret)},
	} {
		for variant, members := range map[string][2]map[string]any{
			"bare":                      {{}, {}},
			"alg and use":               {{"alg": c.alg.String(), "use": "enc"}, {"alg": c.alg.String(), "use": "enc"}},
			"use and key_ops":           {{"use": "enc", "key_ops": []any{"wrapKey", "unwrapKey"}}, {"use": "enc", "key_ops": []any{"wrapKey", "unwrapKey"}}},
			"key_ops alone":             {{"key_ops": []any{"wrapKey"}}, {"key_ops": []any{"unwrapKey"}}},
			"unrelated ops without use": {{"key_ops": []any{"wrapKey", "sign"}}, {"key_ops": []any{"unwrapKey", "sign"}}},
			"an unknown op":             {{"use": "enc", "key_ops": []any{"wrapKey", "x-custom"}}, {"use": "enc", "key_ops": []any{"unwrapKey", "x-custom"}}},
		} {
			t.Run(name+"/"+variant, func(t *testing.T) {
				if e, err := GetEncrypterFromJwk(c.alg, with(c.public, members[0])); err != nil || e == nil {
					t.Errorf("[RFC 7517 4.3] the control jwk must build an Encrypter, got %v", err)
				}
				if d, err := GetDecrypterFromJwk(c.alg, with(c.private, members[1])); err != nil || d == nil {
					t.Errorf("[RFC 7517 4.3] the control jwk must build a Decrypter, got %v", err)
				}
			})
		}
	}
}

func TestGetEncrypterFromJwk_RefusesAJwkThatDeclaresAnotherUse(t *testing.T) {
	secret := randomBytes(t, 16)
	rsaPublic, rsaPrivate := rsaPublicJwkFixture(t), rsaPrivateJwkFixture(t)
	oct := octJwkFixture(secret)

	type fault struct {
		encrypter, decrypter map[string]any
		clause               string
	}
	faults := map[string]fault{
		"an alg naming another key wrap": {
			encrypter: map[string]any{"alg": "A192KW", "use": "enc"},
			decrypter: map[string]any{"alg": "A192KW", "use": "enc"},
			clause:    "RFC 8725 3.1",
		},
		"an alg differing only in case": {
			encrypter: map[string]any{"alg": "a128kw"},
			decrypter: map[string]any{"alg": "a128kw"},
			clause:    "RFC 7517 4.4",
		},
		"an empty alg": {
			encrypter: map[string]any{"alg": ""},
			decrypter: map[string]any{"alg": ""},
			clause:    "RFC 7517 4.4",
		},
		"an alg that is not a string": {
			encrypter: map[string]any{"alg": []any{"A128KW"}},
			decrypter: map[string]any{"alg": []any{"A128KW"}},
			clause:    "RFC 7517 4.4",
		},
		"use sig": {
			encrypter: map[string]any{"alg": "A128KW", "use": "sig"},
			decrypter: map[string]any{"alg": "A128KW", "use": "sig"},
			clause:    "RFC 7517 4.2",
		},
		"use that differs in case": {
			encrypter: map[string]any{"alg": "A128KW", "use": "ENC"},
			decrypter: map[string]any{"alg": "A128KW", "use": "ENC"},
			clause:    "RFC 7517 4.2",
		},
		"use that is not a string": {
			encrypter: map[string]any{"alg": "A128KW", "use": []any{"enc"}},
			decrypter: map[string]any{"alg": "A128KW", "use": []any{"enc"}},
			clause:    "RFC 7517 4.2",
		},
		"key_ops naming only the opposite direction": {
			encrypter: map[string]any{"alg": "A128KW", "key_ops": []any{"unwrapKey", "encrypt", "decrypt"}},
			decrypter: map[string]any{"alg": "A128KW", "key_ops": []any{"wrapKey", "encrypt", "decrypt"}},
			clause:    "RFC 7517 4.3",
		},
		"key_ops listing the operation twice": {
			encrypter: map[string]any{"alg": "A128KW", "key_ops": []any{"wrapKey", "wrapKey"}},
			decrypter: map[string]any{"alg": "A128KW", "key_ops": []any{"unwrapKey", "unwrapKey"}},
			clause:    "RFC 7517 4.3",
		},
		"key_ops listing another value twice": {
			encrypter: map[string]any{"alg": "A128KW", "key_ops": []any{"encrypt", "wrapKey", "encrypt"}},
			decrypter: map[string]any{"alg": "A128KW", "key_ops": []any{"decrypt", "unwrapKey", "decrypt"}},
			clause:    "RFC 7517 4.3",
		},
		"empty key_ops": {
			encrypter: map[string]any{"alg": "A128KW", "key_ops": []any{}},
			decrypter: map[string]any{"alg": "A128KW", "key_ops": []any{}},
			clause:    "RFC 7517 4.3",
		},
		"key_ops that is a string": {
			encrypter: map[string]any{"alg": "A128KW", "key_ops": "wrapKey"},
			decrypter: map[string]any{"alg": "A128KW", "key_ops": "unwrapKey"},
			clause:    "RFC 7517 4.3",
		},
		"key_ops holding a number beside the operation": {
			encrypter: map[string]any{"alg": "A128KW", "key_ops": []any{"wrapKey", 7}},
			decrypter: map[string]any{"alg": "A128KW", "key_ops": []any{"unwrapKey", 7}},
			clause:    "RFC 7517 4.3",
		},
		"use enc with key_ops that also sign": {
			encrypter: map[string]any{"alg": "A128KW", "use": "enc", "key_ops": []any{"wrapKey", "unwrapKey", "sign"}},
			decrypter: map[string]any{"alg": "A128KW", "use": "enc", "key_ops": []any{"wrapKey", "unwrapKey", "sign"}},
			clause:    "RFC 7517 4.3",
		},
		"use enc with key_ops that also verify": {
			encrypter: map[string]any{"alg": "A128KW", "use": "enc", "key_ops": []any{"verify", "wrapKey", "unwrapKey"}},
			decrypter: map[string]any{"alg": "A128KW", "use": "enc", "key_ops": []any{"verify", "wrapKey", "unwrapKey"}},
			clause:    "RFC 7517 4.3",
		},
	}
	for name, f := range faults {
		checkRefusedBoth(t, "A128KW "+name,
			jwkCase{alg: jwa.A128KW, jwk: with(oct, f.encrypter), clause: f.clause},
			jwkCase{alg: jwa.A128KW, jwk: with(oct, f.decrypter), clause: f.clause})
	}

	rsaFaults := map[string]fault{
		"an alg naming another RSA-OAEP": {
			encrypter: map[string]any{"alg": "RSA-OAEP-256", "use": "enc"},
			decrypter: map[string]any{"alg": "RSA-OAEP-256", "use": "enc"},
			clause:    "RFC 8725 3.1",
		},
		"an alg naming a signature algorithm": {
			encrypter: map[string]any{"alg": "RS256"},
			decrypter: map[string]any{"alg": "RS256"},
			clause:    "RFC 8725 3.1",
		},
		"use sig": {
			encrypter: map[string]any{"alg": "RSA-OAEP", "use": "sig"},
			decrypter: map[string]any{"alg": "RSA-OAEP", "use": "sig"},
			clause:    "RFC 7517 4.2",
		},
		"key_ops for signing": {
			encrypter: map[string]any{"alg": "RSA-OAEP", "key_ops": []any{"verify", "unwrapKey"}},
			decrypter: map[string]any{"alg": "RSA-OAEP", "key_ops": []any{"sign", "wrapKey"}},
			clause:    "RFC 7517 4.3",
		},
		"use enc with key_ops that also sign": {
			encrypter: map[string]any{"alg": "RSA-OAEP", "use": "enc", "key_ops": []any{"wrapKey", "unwrapKey", "sign"}},
			decrypter: map[string]any{"alg": "RSA-OAEP", "use": "enc", "key_ops": []any{"wrapKey", "unwrapKey", "sign"}},
			clause:    "RFC 7517 4.3",
		},
	}
	for name, f := range rsaFaults {
		checkRefusedBoth(t, "RSA-OAEP "+name,
			jwkCase{alg: jwa.RSAOAEP, jwk: with(rsaPublic, f.encrypter), clause: f.clause},
			jwkCase{alg: jwa.RSAOAEP, jwk: with(rsaPrivate, f.decrypter), clause: f.clause})
	}
}

func TestGetEncrypterFromJwk_RefusesAKeyThatDoesNotSuitTheAlgorithm(t *testing.T) {
	rsaPublic, rsaPrivate := rsaPublicJwkFixture(t), rsaPrivateJwkFixture(t)
	for name, c := range map[string]struct {
		alg                  jwa.Algorithm
		encrypter, decrypter map[string]any
		clause               string
	}{
		"an oct jwk for RSA-OAEP":                     {alg: jwa.RSAOAEP, encrypter: octJwkFixture(randomBytes(t, 32)), decrypter: octJwkFixture(randomBytes(t, 32)), clause: "RFC 7518 4.3"},
		"an RSA jwk for A128KW":                       {alg: jwa.A128KW, encrypter: rsaPrivate, decrypter: rsaPrivate, clause: "RFC 7518 4.4"},
		"an RSA public jwk for an RSA-OAEP decrypter": {alg: jwa.RSAOAEP, encrypter: with(rsaPublic, map[string]any{"n": "AQAB"}), decrypter: rsaPublic, clause: "RFC 7518 6.3.2"},
		"a 24-octet oct jwk for A128KW":               {alg: jwa.A128KW, encrypter: octJwkFixture(randomBytes(t, 24)), decrypter: octJwkFixture(randomBytes(t, 24)), clause: "RFC 7518 4.4"},
		"a 16-octet oct jwk for A256KW":               {alg: jwa.A256KW, encrypter: octJwkFixture(randomBytes(t, 16)), decrypter: octJwkFixture(randomBytes(t, 16)), clause: "RFC 7518 4.4"},
		"a 33-octet oct jwk for A256KW":               {alg: jwa.A256KW, encrypter: octJwkFixture(randomBytes(t, 33)), decrypter: octJwkFixture(randomBytes(t, 33)), clause: "RFC 7518 4.4"},
		"an oct jwk with no k":                        {alg: jwa.A128KW, encrypter: map[string]any{"kty": "oct"}, decrypter: map[string]any{"kty": "oct"}, clause: "RFC 7518 6.4.1"},
		"an oct jwk whose k is a number":              {alg: jwa.A128KW, encrypter: map[string]any{"kty": "oct", "k": 16}, decrypter: map[string]any{"kty": "oct", "k": 16}, clause: "RFC 7518 6.4.1"},
		"an oct jwk whose k is empty":                 {alg: jwa.A128KW, encrypter: map[string]any{"kty": "oct", "k": ""}, decrypter: map[string]any{"kty": "oct", "k": ""}, clause: "RFC 7518 6.4.1"},
		"an oct jwk whose k is padded":                {alg: jwa.A128KW, encrypter: map[string]any{"kty": "oct", "k": "AAAAAAAAAAAAAAAAAAAAAA=="}, decrypter: map[string]any{"kty": "oct", "k": "AAAAAAAAAAAAAAAAAAAAAA=="}, clause: "RFC 7515 2"},
		"an oct jwk whose k is standard base64":       {alg: jwa.A128KW, encrypter: map[string]any{"kty": "oct", "k": "+AAAAAAAAAAAAAAAAAAA/w"}, decrypter: map[string]any{"kty": "oct", "k": "+AAAAAAAAAAAAAAAAAAA/w"}, clause: "RFC 7515 2"},
		"a jwk with no kty":                           {alg: jwa.A128KW, encrypter: map[string]any{"k": b64(randomBytes(t, 16))}, decrypter: map[string]any{"k": b64(randomBytes(t, 16))}, clause: "RFC 7517 4.1"},
	} {
		checkRefusedBoth(t, name,
			jwkCase{alg: c.alg, jwk: c.encrypter, clause: c.clause},
			jwkCase{alg: c.alg, jwk: c.decrypter, clause: c.clause})
	}
}

func TestGetEncrypterFromJwk_RefusesDirAndAlgorithmsThatAreNotForKeyManagement(t *testing.T) {
	secret := randomBytes(t, 16)
	algorithms := []jwa.Algorithm{jwa.ES256, jwa.RS256, jwa.PS256, jwa.HS256, jwa.EdDSA, jwa.Ed25519, jwa.MLDSA44, jwa.Unknown, jwa.Algorithm(999), jwa.Algorithm(-1), jwa.Dir}
	for _, alg := range algorithms {
		for name, key := range map[string]map[string]any{
			"oct": with(octJwkFixture(secret), map[string]any{"alg": alg.String(), "use": "enc"}),
			"RSA": rsaPrivateJwkFixture(t),
		} {
			t.Run(alg.String()+"/"+name, func(t *testing.T) {
				encrypter, err := GetEncrypterFromJwk(alg, key)
				if !errors.Is(err, joseerror.ErrUnsupportedAlgorithm) || encrypter != nil {
					t.Errorf("[RFC 7518 4.1] want ErrUnsupportedAlgorithm and a nil Encrypter, got %v and %v", err, encrypter)
				}
				decrypter, err := GetDecrypterFromJwk(alg, key)
				if !errors.Is(err, joseerror.ErrUnsupportedAlgorithm) || decrypter != nil {
					t.Errorf("[RFC 7518 4.1] want ErrUnsupportedAlgorithm and a nil Decrypter, got %v and %v", err, decrypter)
				}
			})
		}
	}
}

func TestGetEncrypterFromJwk_RefusesDirWithAPointerToDirectKey(t *testing.T) {
	jwk := map[string]any{"kty": "oct", "k": b64(randomBytes(t, 16)), "alg": "dir", "use": "enc"}
	_, encErr := GetEncrypterFromJwk(jwa.Dir, jwk)
	_, decErr := GetDecrypterFromJwk(jwa.Dir, jwk)
	for name, err := range map[string]error{"GetEncrypterFromJwk": encErr, "GetDecrypterFromJwk": decErr} {
		if err == nil || !strings.Contains(err.Error(), "jwe.DirectKey") {
			t.Errorf("[RFC 8725 3.1] %s: a jwk names no enc for a dir key, so the refusal must point to jwe.DirectKey, got %v", name, err)
		}
	}
}

func TestGetEncrypterFromJwk_AJwkOfTheWrongShapeIsRefusedNotPanicked(t *testing.T) {
	oct := octJwkFixture(randomBytes(t, 16))
	shapes := map[string]any{
		"a number":  7.0,
		"a boolean": true,
		"null":      nil,
		"an object": map[string]any{"enc": true},
		"an array":  []any{map[string]any{}},
	}
	for _, member := range []string{"kty", "k", "alg", "use", "key_ops"} {
		for shapeName, value := range shapes {
			jwk := maps.Clone(oct)
			jwk[member] = value
			t.Run(member+" as "+shapeName, func(t *testing.T) {
				defer func() {
					if r := recover(); r != nil {
						t.Fatalf("[RFC 7517 4] a %s holding %s comes from a peer and must be refused, not panic: %v", member, shapeName, r)
					}
				}()
				if e, err := GetEncrypterFromJwk(jwa.A128KW, jwk); err == nil || e != nil {
					t.Errorf("[RFC 7517 4] a %s holding %s must be refused with a nil Encrypter, got %v", member, shapeName, err)
				}
				if d, err := GetDecrypterFromJwk(jwa.A128KW, jwk); err == nil || d != nil {
					t.Errorf("[RFC 7517 4] a %s holding %s must be refused with a nil Decrypter, got %v", member, shapeName, err)
				}
			})
		}
	}
	for _, jwk := range []map[string]any{nil, {}} {
		if e, err := GetEncrypterFromJwk(jwa.RSAOAEP, jwk); err == nil || e != nil {
			t.Errorf("[RFC 7517 4.1] an empty jwk must be refused with a nil Encrypter, got %v", err)
		}
		if d, err := GetDecrypterFromJwk(jwa.RSAOAEP, jwk); err == nil || d != nil {
			t.Errorf("[RFC 7517 4.1] an empty jwk must be refused with a nil Decrypter, got %v", err)
		}
	}
}
