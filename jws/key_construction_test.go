package jws

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha512"
	"encoding/base64"
	"errors"
	"fmt"
	"math/big"
	"testing"

	"github.com/MichaelFraser99/go-jose/joseerror"
	"github.com/MichaelFraser99/go-jose/jwa"
	"github.com/MichaelFraser99/go-jose/model"
)

var rsaAlgorithms = []jwa.Algorithm{jwa.RS256, jwa.RS384, jwa.RS512, jwa.PS256, jwa.PS384, jwa.PS512}

var ecdsaAlgorithms = map[jwa.Algorithm]elliptic.Curve{
	jwa.ES256: elliptic.P256(),
	jwa.ES384: elliptic.P384(),
	jwa.ES512: elliptic.P521(),
}

func rsaKeySizeClause(alg jwa.Algorithm) string {
	if alg == jwa.PS256 || alg == jwa.PS384 || alg == jwa.PS512 {
		return "RFC 7518 3.5"
	}
	return "RFC 7518 3.3"
}

func rsaPublicKeyOfBits(bits int) *rsa.PublicKey {
	n := new(big.Int).Lsh(big.NewInt(1), uint(bits-1))
	n.Add(n, big.NewInt(1))
	return &rsa.PublicKey{N: n, E: 65537}
}

func rsaPrivateKeyOfBits(bits int) *rsa.PrivateKey {
	return &rsa.PrivateKey{PublicKey: *rsaPublicKeyOfBits(bits), D: big.NewInt(3)}
}

func rsaJwkOf(key *rsa.PublicKey) map[string]any {
	return map[string]any{
		"kty": "RSA",
		"n":   base64.RawURLEncoding.EncodeToString(key.N.Bytes()),
		"e":   base64.RawURLEncoding.EncodeToString(big.NewInt(int64(key.E)).Bytes()),
	}
}

func constructionPanic(construct func() error) (panicked any, err error) {
	defer func() { panicked = recover() }()
	return nil, construct()
}

func TestRSAConstructors_RefuseAModulusOutsideTheSupportedRange(t *testing.T) {
	tests := []struct {
		bits   int
		accept bool
		clause string
	}{
		{bits: 1024},
		{bits: 2047},
		{bits: 2048, accept: true},
		{bits: 8192, accept: true},
		{bits: 8193, clause: "#83"},
		{bits: 1 << 20, clause: "#83"},
	}

	for _, alg := range rsaAlgorithms {
		for _, test := range tests {
			clause := test.clause
			if clause == "" {
				clause = rsaKeySizeClause(alg)
			}
			t.Run(fmt.Sprintf("%s with a %d-bit modulus", alg, test.bits), func(t *testing.T) {
				constructions := map[string]func() (any, error){
					"GetValidator": func() (any, error) {
						v, err := GetValidator(alg, rsaPublicKeyOfBits(test.bits))
						return v, err
					},
					"GetValidatorFromJwk": func() (any, error) {
						v, err := GetValidatorFromJwk(alg, rsaJwkOf(rsaPublicKeyOfBits(test.bits)))
						return v, err
					},
					"GetSignerFromPrivateKey": func() (any, error) {
						s, err := GetSignerFromPrivateKey(alg, rsaPrivateKeyOfBits(test.bits))
						return s, err
					},
				}
				for name, construct := range constructions {
					built, err := construct()
					if test.accept {
						if err != nil {
							t.Errorf("[%s] %s must accept a %d-bit modulus, got %v", clause, name, test.bits, err)
						}
						continue
					}
					if err == nil {
						t.Errorf("[%s] %s must refuse a %d-bit modulus", clause, name, test.bits)
						continue
					}
					if !errors.Is(err, joseerror.ErrInvalidPublicKey) && !errors.Is(err, joseerror.ErrInvalidPrivateKey) {
						t.Errorf("[%s] %s must refuse a %d-bit modulus as an invalid key, got %v", clause, name, test.bits, err)
					}
					if built != nil {
						t.Errorf("[%s] a refused construction must return a nil interface, got %#v", clause, built)
					}
				}
			})
		}
	}
}

func TestGetSigner_RefusesToGenerateAnRSAKeyAboveTheCeiling(t *testing.T) {
	for _, alg := range rsaAlgorithms {
		t.Run(alg.String(), func(t *testing.T) {
			signer, err := GetSigner(alg, &model.Opts{BitSize: 8193})
			if !errors.Is(err, joseerror.ErrInvalidPrivateKey) {
				t.Errorf("[#83] a validator refuses a modulus over 8192 bits, so a signer must not generate one, got err=%v", err)
			}
			if signer != nil {
				t.Errorf("[#83] a refused construction must return a nil Signer, got %#v", signer)
			}
		})
	}
}

func TestESConstructors_RefuseAKeyOnAnotherCurve(t *testing.T) {
	keys := map[string]*ecdsa.PrivateKey{}
	for _, curve := range []elliptic.Curve{elliptic.P256(), elliptic.P384(), elliptic.P521()} {
		key, err := ecdsa.GenerateKey(curve, rand.Reader)
		if err != nil {
			t.Fatalf("failed to generate a %s key: %v", curve.Params().Name, err)
		}
		keys[curve.Params().Name] = key
	}

	for alg, curve := range ecdsaAlgorithms {
		for name, key := range keys {
			t.Run(fmt.Sprintf("%s with a %s key", alg, name), func(t *testing.T) {
				accept := name == curve.Params().Name
				validator, err := GetValidator(alg, &key.PublicKey)
				signer, signerErr := GetSignerFromPrivateKey(alg, key)
				if accept {
					if err != nil || signerErr != nil {
						t.Errorf("[RFC 7518 3.1] %s is defined over %s, so a %s key must be accepted, got validator err=%v signer err=%v", alg, curve.Params().Name, name, err, signerErr)
					}
					return
				}
				if !errors.Is(err, joseerror.ErrInvalidPublicKey) || validator != nil {
					t.Errorf("[RFC 7518 3.1] %s is defined over %s, so a validator must refuse a %s key with ErrInvalidPublicKey, got validator=%v err=%v", alg, curve.Params().Name, name, validator, err)
				}
				if !errors.Is(signerErr, joseerror.ErrInvalidPrivateKey) || signer != nil {
					t.Errorf("[RFC 7518 3.1] %s is defined over %s, so a signer must refuse a %s key with ErrInvalidPrivateKey, got signer=%v err=%v", alg, curve.Params().Name, name, signer, signerErr)
				}
			})
		}
	}
}

func TestES384_RefusesAP256KeySigningASHA384DigestPaddedToES384Length(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate a P-256 key: %v", err)
	}
	input := []byte("eyJhbGciOiJFUzM4NCJ9.eyJzdWIiOiJ2aWN0aW0ifQ")
	digest := sha512.Sum384(input)
	r, s, err := ecdsa.Sign(rand.Reader, key, digest[:])
	if err != nil {
		t.Fatalf("failed to sign: %v", err)
	}
	signature := make([]byte, 96)
	r.FillBytes(signature[:48])
	s.FillBytes(signature[48:])

	validator, err := GetValidator(jwa.ES384, &key.PublicKey)
	if err == nil {
		valid, _ := validator.ValidateSignature(input, signature)
		t.Fatalf("[RFC 8725 3.1] a token labelled ES384 must not be checked with P-256, but a validator was built and reported valid=%t", valid)
	}
	if !errors.Is(err, joseerror.ErrInvalidPublicKey) {
		t.Errorf("[RFC 7518 3.1] the refusal must carry the invalid public key class, got %v", err)
	}
}

func TestConstructors_RefuseAKeyWithMissingFieldsWithoutPanicking(t *testing.T) {
	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("failed to generate an RSA key: %v", err)
	}
	ecKeys := map[jwa.Algorithm]*ecdsa.PrivateKey{}
	for alg, curve := range ecdsaAlgorithms {
		key, err := ecdsa.GenerateKey(curve, rand.Reader)
		if err != nil {
			t.Fatalf("failed to generate a %s key: %v", curve.Params().Name, err)
		}
		ecKeys[alg] = key
	}

	type keys struct {
		public  map[string]crypto.PublicKey
		private map[string]crypto.PrivateKey
	}
	rsaKeys := keys{
		public: map[string]crypto.PublicKey{
			"a nil *rsa.PublicKey": (*rsa.PublicKey)(nil),
			"a zero rsa.PublicKey": &rsa.PublicKey{},
			"a nil modulus":        &rsa.PublicKey{E: rsaKey.E},
			"a zero modulus":       &rsa.PublicKey{N: big.NewInt(0), E: rsaKey.E},
			"a negative modulus":   &rsa.PublicKey{N: new(big.Int).Neg(rsaKey.N), E: rsaKey.E},
			"a zero exponent":      &rsa.PublicKey{N: rsaKey.N},
			"a negative exponent":  &rsa.PublicKey{N: rsaKey.N, E: -rsaKey.E},
		},
		private: map[string]crypto.PrivateKey{
			"a nil *rsa.PrivateKey":   (*rsa.PrivateKey)(nil),
			"a zero rsa.PrivateKey":   &rsa.PrivateKey{},
			"a nil modulus":           &rsa.PrivateKey{PublicKey: rsa.PublicKey{E: rsaKey.E}, D: rsaKey.D, Primes: rsaKey.Primes},
			"a nil private exponent":  &rsa.PrivateKey{PublicKey: rsaKey.PublicKey, Primes: rsaKey.Primes},
			"a zero private exponent": &rsa.PrivateKey{PublicKey: rsaKey.PublicKey, D: big.NewInt(0), Primes: rsaKey.Primes},
			"a private exponent of n": &rsa.PrivateKey{PublicKey: rsaKey.PublicKey, D: new(big.Int).Set(rsaKey.N), Primes: rsaKey.Primes},
		},
	}

	for _, alg := range rsaAlgorithms {
		for name, key := range rsaKeys.public {
			t.Run(alg.String()+" validator with "+name, func(t *testing.T) {
				var validator model.Validator
				panicked, err := constructionPanic(func() error {
					var err error
					validator, err = GetValidator(alg, key)
					return err
				})
				if panicked != nil {
					t.Fatalf("[#119] GetValidator must refuse %s rather than panic, got panic %v", name, panicked)
				}
				if !errors.Is(err, joseerror.ErrInvalidPublicKey) || validator != nil {
					t.Errorf("[#119] GetValidator must refuse %s with ErrInvalidPublicKey and a nil Validator, got validator=%#v err=%v", name, validator, err)
				}
			})
		}
		for name, key := range rsaKeys.private {
			t.Run(alg.String()+" signer with "+name, func(t *testing.T) {
				var signer model.Signer
				panicked, err := constructionPanic(func() error {
					var err error
					signer, err = GetSignerFromPrivateKey(alg, key)
					return err
				})
				if panicked != nil {
					t.Fatalf("[#119] GetSignerFromPrivateKey must refuse %s rather than panic, got panic %v", name, panicked)
				}
				if !errors.Is(err, joseerror.ErrInvalidPrivateKey) || signer != nil {
					t.Errorf("[#119] GetSignerFromPrivateKey must refuse %s with ErrInvalidPrivateKey and a nil Signer, got signer=%#v err=%v", name, signer, err)
				}
			})
		}
	}

	for alg, ecKey := range ecKeys {
		curve := ecKey.Curve
		n := curve.Params().N
		public := map[string]crypto.PublicKey{
			"a nil *ecdsa.PublicKey":   (*ecdsa.PublicKey)(nil),
			"a zero ecdsa.PublicKey":   &ecdsa.PublicKey{},
			"a nil curve":              &ecdsa.PublicKey{X: ecKey.X, Y: ecKey.Y},
			"a nil x":                  &ecdsa.PublicKey{Curve: curve, Y: ecKey.Y},
			"a nil y":                  &ecdsa.PublicKey{Curve: curve, X: ecKey.X},
			"a point not on the curve": &ecdsa.PublicKey{Curve: curve, X: ecKey.X, Y: new(big.Int).Add(ecKey.Y, big.NewInt(1))},
		}
		private := map[string]crypto.PrivateKey{
			"a nil *ecdsa.PrivateKey": (*ecdsa.PrivateKey)(nil),
			"a zero ecdsa.PrivateKey": &ecdsa.PrivateKey{},
			"a nil curve":             &ecdsa.PrivateKey{PublicKey: ecdsa.PublicKey{X: ecKey.X, Y: ecKey.Y}, D: ecKey.D},
			"a nil x":                 &ecdsa.PrivateKey{PublicKey: ecdsa.PublicKey{Curve: curve, Y: ecKey.Y}, D: ecKey.D},
			"a nil y":                 &ecdsa.PrivateKey{PublicKey: ecdsa.PublicKey{Curve: curve, X: ecKey.X}, D: ecKey.D},
			"a nil scalar":            &ecdsa.PrivateKey{PublicKey: ecKey.PublicKey},
			"a zero scalar":           &ecdsa.PrivateKey{PublicKey: ecKey.PublicKey, D: big.NewInt(0)},
			"a negative scalar":       &ecdsa.PrivateKey{PublicKey: ecKey.PublicKey, D: new(big.Int).Neg(ecKey.D)},
			"a scalar equal to n":     &ecdsa.PrivateKey{PublicKey: ecKey.PublicKey, D: new(big.Int).Set(n)},
		}
		for name, key := range public {
			t.Run(alg.String()+" validator with "+name, func(t *testing.T) {
				var validator model.Validator
				panicked, err := constructionPanic(func() error {
					var err error
					validator, err = GetValidator(alg, key)
					return err
				})
				if panicked != nil {
					t.Fatalf("[#119] GetValidator must refuse %s rather than panic, got panic %v", name, panicked)
				}
				if !errors.Is(err, joseerror.ErrInvalidPublicKey) || validator != nil {
					t.Errorf("[#119] GetValidator must refuse %s with ErrInvalidPublicKey and a nil Validator, got validator=%#v err=%v", name, validator, err)
				}
			})
		}
		for name, key := range private {
			t.Run(alg.String()+" signer with "+name, func(t *testing.T) {
				var signer model.Signer
				panicked, err := constructionPanic(func() error {
					var err error
					signer, err = GetSignerFromPrivateKey(alg, key)
					return err
				})
				if panicked != nil {
					t.Fatalf("[#119] GetSignerFromPrivateKey must refuse %s rather than panic, got panic %v", name, panicked)
				}
				if !errors.Is(err, joseerror.ErrInvalidPrivateKey) || signer != nil {
					t.Errorf("[#119] GetSignerFromPrivateKey must refuse %s with ErrInvalidPrivateKey and a nil Signer, got signer=%#v err=%v", name, signer, err)
				}
			})
		}
	}
}

func TestRSASigners_AcceptAPrivateKeyCarryingOnlyD(t *testing.T) {
	full, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("failed to generate an RSA key: %v", err)
	}
	dOnly := &rsa.PrivateKey{PublicKey: full.PublicKey, D: full.D}
	input := []byte("the jws signing input")

	for _, alg := range rsaAlgorithms {
		t.Run(alg.String(), func(t *testing.T) {
			signer, err := GetSignerFromPrivateKey(alg, dOnly)
			if err != nil {
				t.Fatalf("[RFC 7518 6.3.2] \"d\" is the only private member an RSA key must carry, so a key without primes must be accepted, got %v", err)
			}
			signature, err := signer.Sign(rand.Reader, input, nil)
			if err != nil {
				t.Fatalf("[RFC 7518 6.3.2] a key without primes must sign, got %v", err)
			}
			validator, err := GetValidator(alg, &full.PublicKey)
			if err != nil {
				t.Fatalf("expected no error creating a validator, got %v", err)
			}
			if valid, err := validator.ValidateSignature(input, signature); !valid || err != nil {
				t.Errorf("[RFC 7518 6.3.2] a signature made with only d must verify, got valid=%t err=%v", valid, err)
			}
		})
	}
}
