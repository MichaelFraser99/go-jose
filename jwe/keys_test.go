package jwe

import (
	"bytes"
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"errors"
	"io"
	"math/big"
	"reflect"
	"testing"

	"github.com/MichaelFraser99/go-jose/joseerror"
	"github.com/MichaelFraser99/go-jose/jwa"
	"github.com/MichaelFraser99/go-jose/model"
)

var signatureAlgorithms = []jwa.Algorithm{jwa.ES256, jwa.ES384, jwa.ES512, jwa.RS256, jwa.RS384, jwa.RS512, jwa.PS256, jwa.PS384, jwa.PS512, jwa.HS256, jwa.HS384, jwa.HS512, jwa.EdDSA, jwa.Ed25519, jwa.MLDSA44, jwa.MLDSA65, jwa.MLDSA87, jwa.Unknown, jwa.Algorithm(999), jwa.Algorithm(-1)}

func TestGetEncrypterAndGetDecrypter_RefuseAnAlgorithmThatIsNotForKeyManagement(t *testing.T) {
	for _, alg := range signatureAlgorithms {
		t.Run(alg.String(), func(t *testing.T) {
			for _, key := range []any{&testRSAKey(t).PublicKey, testRSAKey(t), make([]byte, 32)} {
				encrypter, err := GetEncrypter(alg, key)
				if !errors.Is(err, joseerror.ErrUnsupportedAlgorithm) || encrypter != nil {
					t.Errorf("[RFC 7518 4.1] GetEncrypter: want ErrUnsupportedAlgorithm and a nil Encrypter, got %v and %v", err, encrypter)
				}
				decrypter, err := GetDecrypter(alg, key)
				if !errors.Is(err, joseerror.ErrUnsupportedAlgorithm) || decrypter != nil {
					t.Errorf("[RFC 7518 4.1] GetDecrypter: want ErrUnsupportedAlgorithm and a nil Decrypter, got %v and %v", err, decrypter)
				}
			}
		})
	}
}

func TestGetEncrypterAndGetDecrypter_RefuseAKeyTheAlgorithmCannotUse(t *testing.T) {
	small, err := rsa.GenerateKey(rand.Reader, 1024)
	if err != nil {
		t.Fatal(err)
	}
	ecKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	var nilRSAPublic *rsa.PublicKey
	var nilRSAPrivate *rsa.PrivateKey
	tests := []struct {
		name    string
		alg     jwa.Algorithm
		public  any
		private any
		clause  string
	}{
		{name: "a 1024-bit RSA key", alg: jwa.RSAOAEP, public: &small.PublicKey, private: small, clause: "RFC 7518 4.3"},
		{name: "an RSA key over a crypto.Decrypter of 1024 bits", alg: jwa.RSAOAEP256, public: &small.PublicKey, private: opaqueDecrypter{small}, clause: "RFC 7518 4.3"},
		{name: "an EC key for RSA-OAEP", alg: jwa.RSAOAEP, public: &ecKey.PublicKey, private: ecKey, clause: "RFC 7518 4.3"},
		{name: "a nil RSA key", alg: jwa.RSAOAEP512, public: nilRSAPublic, private: nilRSAPrivate, clause: "RFC 7518 4.3"},
		{name: "a private key to encrypt with and a public key to decrypt with", alg: jwa.RSAOAEP384, public: testRSAKey(t), private: &testRSAKey(t).PublicKey, clause: "RFC 7518 4.3"},
		{name: "bytes for RSA-OAEP", alg: jwa.RSAOAEP, public: make([]byte, 256), private: make([]byte, 256), clause: "RFC 7518 4.3"},
		{name: "a 15-octet A128KW key", alg: jwa.A128KW, public: make([]byte, 15), private: make([]byte, 15), clause: "RFC 7518 4.4"},
		{name: "a 17-octet A128KW key", alg: jwa.A128KW, public: make([]byte, 17), private: make([]byte, 17), clause: "RFC 7518 4.4"},
		{name: "a 32-octet A128KW key", alg: jwa.A128KW, public: make([]byte, 32), private: make([]byte, 32), clause: "RFC 7518 4.4"},
		{name: "a 16-octet A192KW key", alg: jwa.A192KW, public: make([]byte, 16), private: make([]byte, 16), clause: "RFC 7518 4.4"},
		{name: "a 24-octet A256KW key", alg: jwa.A256KW, public: make([]byte, 24), private: make([]byte, 24), clause: "RFC 7518 4.4"},
		{name: "an empty A256KW key", alg: jwa.A256KW, public: []byte{}, private: []byte{}, clause: "RFC 7518 4.4"},
		{name: "a string for A128KW", alg: jwa.A128KW, public: "0123456789abcdef", private: "0123456789abcdef", clause: "RFC 7518 4.4"},
		{name: "an RSA key for A128KW", alg: jwa.A128KW, public: &testRSAKey(t).PublicKey, private: testRSAKey(t), clause: "RFC 7518 4.4"},
		{name: "an empty dir key", alg: jwa.Dir, public: []byte{}, private: []byte{}, clause: "RFC 7518 4.5"},
		{name: "a nil dir key", alg: jwa.Dir, public: []byte(nil), private: []byte(nil), clause: "RFC 7518 4.5"},
		{name: "a 15-octet dir key", alg: jwa.Dir, public: make([]byte, 15), private: make([]byte, 15), clause: "RFC 7518 4.5"},
		{name: "a 33-octet dir key", alg: jwa.Dir, public: make([]byte, 33), private: make([]byte, 33), clause: "RFC 7518 4.5"},
		{name: "a 65-octet dir key", alg: jwa.Dir, public: make([]byte, 65), private: make([]byte, 65), clause: "RFC 7518 4.5"},
		{name: "nothing for dir", alg: jwa.Dir, clause: "RFC 7518 4.5"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			encrypter, err := GetEncrypter(tt.alg, tt.public)
			if !errors.Is(err, joseerror.ErrInvalidPublicKey) || encrypter != nil {
				t.Errorf("[%s] GetEncrypter: want ErrInvalidPublicKey and a nil Encrypter, got %v and %v", tt.clause, err, encrypter)
			}
			decrypter, err := GetDecrypter(tt.alg, tt.private)
			if !errors.Is(err, joseerror.ErrInvalidPrivateKey) || decrypter != nil {
				t.Errorf("[%s] GetDecrypter: want ErrInvalidPrivateKey and a nil Decrypter, got %v and %v", tt.clause, err, decrypter)
			}
		})
	}
}

func TestGetEncrypter_ADirKeyOfEachCEKLengthIsAccepted(t *testing.T) {
	for _, size := range []int{16, 24, 32, 48, 64} {
		if _, err := GetEncrypter(jwa.Dir, make([]byte, size)); err != nil {
			t.Errorf("[RFC 7518 4.5] a %d-octet key is the CEK of some enc, got %v", size, err)
		}
		if _, err := GetDecrypter(jwa.Dir, make([]byte, size)); err != nil {
			t.Errorf("[RFC 7518 4.5] a %d-octet key is the CEK of some enc, got %v", size, err)
		}
	}
}

type opaqueDecrypter struct {
	key *rsa.PrivateKey
}

func (o opaqueDecrypter) Public() crypto.PublicKey { return o.key.Public() }

func (o opaqueDecrypter) Decrypt(random io.Reader, msg []byte, opts crypto.DecrypterOpts) ([]byte, error) {
	return o.key.Decrypt(random, msg, opts)
}

func TestGetDecrypter_DecryptsThroughACryptoDecrypter(t *testing.T) {
	for _, alg := range []jwa.Algorithm{jwa.RSAOAEP, jwa.RSAOAEP256, jwa.RSAOAEP384, jwa.RSAOAEP512} {
		t.Run(alg.String(), func(t *testing.T) {
			encrypter, err := GetEncrypter(alg, &testRSAKey(t).PublicKey)
			if err != nil {
				t.Fatal(err)
			}
			decrypter, err := GetDecrypter(alg, opaqueDecrypter{testRSAKey(t)})
			if err != nil {
				t.Fatal(err)
			}
			token, err := Encrypt(encrypter, jwa.A256GCM, []byte("held in a module"), nil)
			if err != nil {
				t.Fatal(err)
			}
			if _, plaintext, err := Decrypt(context.Background(), token, []model.Decrypter{decrypter}, nil); err != nil || string(plaintext) != "held in a module" {
				t.Errorf("want the plaintext, got %q and %v", plaintext, err)
			}
		})
	}
}

func TestRSAOAEP_EachAlgorithmUsesItsOwnHash(t *testing.T) {
	algs := []jwa.Algorithm{jwa.RSAOAEP, jwa.RSAOAEP256, jwa.RSAOAEP384, jwa.RSAOAEP512}
	hashes := []crypto.Hash{crypto.SHA1, crypto.SHA256, crypto.SHA384, crypto.SHA512}
	for i, alg := range algs {
		t.Run(alg.String(), func(t *testing.T) {
			encrypter, err := GetEncrypter(alg, &testRSAKey(t).PublicKey)
			if err != nil {
				t.Fatal(err)
			}
			cek, encryptedKey, err := encrypter.WrapKey(rand.Reader, jwa.A128GCM, map[string]any{})
			if err != nil {
				t.Fatal(err)
			}
			for j, hash := range hashes {
				recovered, err := rsa.DecryptOAEP(hash.New(), nil, testRSAKey(t), encryptedKey, nil)
				if i == j && (err != nil || !bytes.Equal(recovered, cek)) {
					t.Errorf("[RFC 7518 4.3] %s must be RSAES-OAEP with %s and MGF1 with %s, got %v", alg, hash, hash, err)
				}
				if i != j && err == nil {
					t.Errorf("[RFC 7518 4.3] %s decrypted under %s", alg, hash)
				}
			}
		})
	}
}

func TestGetDecrypter_ASharedKeyFromPublicDecrypts(t *testing.T) {
	for _, alg := range []jwa.Algorithm{jwa.A128KW, jwa.A192KW, jwa.A256KW, jwa.Dir} {
		t.Run(alg.String(), func(t *testing.T) {
			encrypter := pairFor(t, alg, jwa.A128CBCHS256).encrypter
			decrypter, err := GetDecrypter(alg, encrypter.Public())
			if err != nil {
				t.Fatal(err)
			}
			token, err := Encrypt(encrypter, jwa.A128CBCHS256, []byte("p"), nil)
			if err != nil {
				t.Fatal(err)
			}
			if _, _, err := Decrypt(context.Background(), token, []model.Decrypter{decrypter}, nil); err != nil {
				t.Error(err)
			}
		})
	}
}

func TestGetEncrypterAndGetDecrypter_KeepTheirOwnCopyOfASharedKey(t *testing.T) {
	sizes := map[jwa.Algorithm]int{jwa.A128KW: 16, jwa.A192KW: 24, jwa.A256KW: 32, jwa.Dir: 16}
	changes := map[string]func(encrypterInput, decrypterInput []byte, encrypter model.Encrypter, decrypter model.Decrypter){
		"the encrypter's input": func(e, _ []byte, _ model.Encrypter, _ model.Decrypter) { e[0] ^= 0xff },
		"the decrypter's input": func(_, d []byte, _ model.Encrypter, _ model.Decrypter) { d[0] ^= 0xff },
		"what the encrypter's Public returned": func(_, _ []byte, e model.Encrypter, _ model.Decrypter) {
			reflect.ValueOf(e.Public()).Bytes()[0] ^= 0xff
		},
		"what the decrypter's Public returned": func(_, _ []byte, _ model.Encrypter, d model.Decrypter) {
			reflect.ValueOf(d.Public()).Bytes()[0] ^= 0xff
		},
		"a CEK the encrypter returned": func(_, _ []byte, e model.Encrypter, _ model.Decrypter) {
			if cek, _, err := e.WrapKey(rand.Reader, jwa.A128GCM, map[string]any{}); err == nil {
				cek[0] ^= 0xff
			}
		},
		"a CEK the decrypter returned": func(_, _ []byte, _ model.Encrypter, d model.Decrypter) {
			if cek, err := d.Decrypt(nil, nil, nil); err == nil {
				cek[0] ^= 0xff
			}
		},
	}
	for _, alg := range []jwa.Algorithm{jwa.A128KW, jwa.A192KW, jwa.A256KW, jwa.Dir} {
		for name, change := range changes {
			t.Run(alg.String()+"/"+name, func(t *testing.T) {
				original := randomBytes(t, sizes[alg])
				encrypterInput, decrypterInput := bytes.Clone(original), bytes.Clone(original)
				encrypter, err := GetEncrypter(alg, encrypterInput)
				if err != nil {
					t.Fatal(err)
				}
				decrypter, err := GetDecrypter(alg, decrypterInput)
				if err != nil {
					t.Fatal(err)
				}
				change(encrypterInput, decrypterInput, encrypter, decrypter)
				if !bytes.Equal(reflect.ValueOf(encrypter.Public()).Bytes(), original) || !bytes.Equal(reflect.ValueOf(decrypter.Public()).Bytes(), original) {
					t.Errorf("changing %s must not change the key either side holds", name)
				}
			})
		}
	}
}

func TestGetEncrypter_KeepsItsOwnCopyOfAnRSAKey(t *testing.T) {
	other, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	given := testRSAKey(t).PublicKey
	given.N = new(big.Int).Set(given.N)
	encrypter, err := GetEncrypter(jwa.RSAOAEP256, &given)
	if err != nil {
		t.Fatal(err)
	}
	given.N.Set(other.N)
	decrypter, err := GetDecrypter(jwa.RSAOAEP256, testRSAKey(t))
	if err != nil {
		t.Fatal(err)
	}
	token, err := Encrypt(encrypter, jwa.A128GCM, []byte("p"), nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := Decrypt(context.Background(), token, []model.Decrypter{decrypter}, nil); err != nil {
		t.Errorf("changing the caller's public key after construction must not change the encrypter's, got %v", err)
	}
}
