package jws_test

import (
	"bytes"
	"crypto"
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/hmac"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/base64"
	"errors"
	"hash"
	"maps"
	"math/big"
	"strconv"
	"strings"
	"sync"
	"testing"

	"github.com/MichaelFraser99/go-jose/joseerror"
	"github.com/MichaelFraser99/go-jose/jwa"
	"github.com/MichaelFraser99/go-jose/jwk"
	"github.com/MichaelFraser99/go-jose/jws"
	"github.com/MichaelFraser99/go-jose/model"
)

const signerFromJwkInput = "eyJhbGciOiJFUzI1NiJ9.eyJpc3MiOiJqb2UifQ"

type privateJwkFixture struct {
	private map[string]any
	public  map[string]any
}

var (
	signerFromJwkRSAOnce sync.Once
	signerFromJwkRSAKey  *rsa.PrivateKey
)

func signerFromJwkRSA(t *testing.T) *rsa.PrivateKey {
	t.Helper()
	signerFromJwkRSAOnce.Do(func() {
		key, err := rsa.GenerateKey(rand.Reader, 2048)
		if err != nil {
			t.Fatal(err)
		}
		signerFromJwkRSAKey = key
	})
	return signerFromJwkRSAKey
}

func jwkPair(t *testing.T, private crypto.PrivateKey, public crypto.PublicKey) privateJwkFixture {
	t.Helper()
	privateJwk, err := jwk.PrivateJwk(private)
	if err != nil {
		t.Fatal(err)
	}
	publicJwk, err := jwk.PublicJwk(public)
	if err != nil {
		t.Fatal(err)
	}
	return privateJwkFixture{private: *privateJwk, public: *publicJwk}
}

func ecJwkPair(t *testing.T, curve elliptic.Curve) privateJwkFixture {
	t.Helper()
	key, err := ecdsa.GenerateKey(curve, rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return jwkPair(t, key, &key.PublicKey)
}

func ed25519JwkPair(t *testing.T) privateJwkFixture {
	t.Helper()
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return jwkPair(t, private, public)
}

func octJwk(secret []byte) map[string]any {
	return map[string]any{"kty": "oct", "k": base64.RawURLEncoding.EncodeToString(secret)}
}

func with(base map[string]any, members map[string]any) map[string]any {
	candidate := maps.Clone(base)
	for k, v := range members {
		if v == nil {
			delete(candidate, k)
			continue
		}
		candidate[k] = v
	}
	return candidate
}

func TestGetSignerFromJwk_SignsWhatTheValidatorOfItsPublicHalfVerifies(t *testing.T) {
	rsaKey := signerFromJwkRSA(t)
	rsaPair := jwkPair(t, rsaKey, &rsaKey.PublicKey)
	tests := map[jwa.Algorithm]struct {
		pair   privateJwkFixture
		clause string
	}{
		jwa.ES256:   {ecJwkPair(t, elliptic.P256()), "RFC 7518 3.4"},
		jwa.ES384:   {ecJwkPair(t, elliptic.P384()), "RFC 7518 3.4"},
		jwa.ES512:   {ecJwkPair(t, elliptic.P521()), "RFC 7518 3.4"},
		jwa.RS256:   {rsaPair, "RFC 7518 3.3"},
		jwa.RS384:   {rsaPair, "RFC 7518 3.3"},
		jwa.RS512:   {rsaPair, "RFC 7518 3.3"},
		jwa.PS256:   {rsaPair, "RFC 7518 3.5"},
		jwa.PS384:   {rsaPair, "RFC 7518 3.5"},
		jwa.PS512:   {rsaPair, "RFC 7518 3.5"},
		jwa.Ed25519: {ed25519JwkPair(t), "RFC 9864 2.2"},
	}
	for alg, test := range tests {
		t.Run(alg.String(), func(t *testing.T) {
			signer, err := jws.GetSignerFromJwk(alg, test.pair.private, nil)
			if err != nil {
				t.Fatalf("[%s] a private jwk of the key type %s names must build a signer, got %v", test.clause, alg, err)
			}
			if signer.Alg() != alg {
				t.Errorf("[RFC 7515 4.1.1] the signer must sign with %s, got %s", alg, signer.Alg())
			}
			signature, err := signer.Sign(rand.Reader, []byte(signerFromJwkInput), nil)
			if err != nil {
				t.Fatal(err)
			}
			validator, err := jws.GetValidatorFromJwk(alg, test.pair.public, nil)
			if err != nil {
				t.Fatal(err)
			}
			valid, err := validator.ValidateSignature([]byte(signerFromJwkInput), signature)
			if err != nil || !valid {
				t.Errorf("[%s] the public half of the jwk must verify what its private half signs, got %v and %v", test.clause, valid, err)
			}
		})
	}
}

func TestGetSignerFromJwk_SignsWithTheKeyInTheJwk(t *testing.T) {
	ecKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	ecJwk := jwkPair(t, ecKey, &ecKey.PublicKey).private
	signer, err := jws.GetSignerFromJwk(jwa.ES256, ecJwk, nil)
	if err != nil {
		t.Fatal(err)
	}
	signature, err := signer.Sign(rand.Reader, []byte(signerFromJwkInput), nil)
	if err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256([]byte(signerFromJwkInput))
	r, s := new(big.Int).SetBytes(signature[:32]), new(big.Int).SetBytes(signature[32:])
	if len(signature) != 64 || !ecdsa.Verify(&ecKey.PublicKey, digest[:], r, s) {
		t.Errorf("[RFC 7518 3.4] the signature must be R || S under the jwk's own key, checked with crypto/ecdsa")
	}

	rsaKey := signerFromJwkRSA(t)
	rsaSigner, err := jws.GetSignerFromJwk(jwa.RS256, jwkPair(t, rsaKey, &rsaKey.PublicKey).private, nil)
	if err != nil {
		t.Fatal(err)
	}
	rsaSignature, err := rsaSigner.Sign(rand.Reader, []byte(signerFromJwkInput), nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := rsa.VerifyPKCS1v15(&rsaKey.PublicKey, crypto.SHA256, digest[:], rsaSignature); err != nil {
		t.Errorf("[RFC 7518 3.3] the signature must be RSASSA-PKCS1-v1_5 SHA-256 under the jwk's own key, checked with crypto/rsa: %v", err)
	}

	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	edSigner, err := jws.GetSignerFromJwk(jwa.Ed25519, jwkPair(t, private, public).private, nil)
	if err != nil {
		t.Fatal(err)
	}
	edSignature, err := edSigner.Sign(rand.Reader, []byte(signerFromJwkInput), nil)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(edSignature, ed25519.Sign(private, []byte(signerFromJwkInput))) {
		t.Errorf("[RFC 8032 5.1.6] Ed25519 is deterministic, so the signature must be the one crypto/ed25519 computes with the jwk's key")
	}
}

func TestGetSignerFromJwk_MacsWithTheSecretOfAnOctJwk(t *testing.T) {
	tests := map[jwa.Algorithm]struct {
		hash    func() hash.Hash
		minimum int
	}{
		jwa.HS256: {sha256.New, 32},
		jwa.HS384: {sha512.New384, 48},
		jwa.HS512: {sha512.New, 64},
	}
	for alg, test := range tests {
		t.Run(alg.String(), func(t *testing.T) {
			secret := bytes.Repeat([]byte{0xa5}, test.minimum)
			signer, err := jws.GetSignerFromJwk(alg, octJwk(secret), nil)
			if err != nil {
				t.Fatalf("[RFC 7518 6.4] an oct jwk whose k is the size of the hash output is a key for %s, got %v", alg, err)
			}
			mac, err := signer.Sign(rand.Reader, []byte(signerFromJwkInput), nil)
			if err != nil {
				t.Fatal(err)
			}
			want := hmac.New(test.hash, secret)
			want.Write([]byte(signerFromJwkInput))
			if !hmac.Equal(mac, want.Sum(nil)) {
				t.Errorf("[RFC 7518 3.2] the MAC must be the HMAC of the signing input under k, checked with crypto/hmac")
			}
			validator, err := jws.GetValidator(alg, signer.Public())
			if err != nil {
				t.Fatal(err)
			}
			if valid, err := validator.ValidateSignature([]byte(signerFromJwkInput), mac); err != nil || !valid {
				t.Errorf("[RFC 7518 3.2] a validator built from the signer must verify its MAC, got %v and %v", valid, err)
			}

			short, err := jws.GetSignerFromJwk(alg, octJwk(secret[:test.minimum-1]), nil)
			if !errors.Is(err, joseerror.ErrInvalidPrivateKey) || short != nil {
				t.Errorf("[RFC 7518 3.2] a k one octet shorter than the hash output MUST NOT be used with %s, got %v and %v", alg, short, err)
			}
		})
	}
}

func TestGetSignerFromJwk_RefusesAKeyOfTheWrongTypeForTheAlgorithm(t *testing.T) {
	rsaKey := signerFromJwkRSA(t)
	secret := octJwk(bytes.Repeat([]byte{1}, 64))
	x25519Key, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tests := map[string]struct {
		alg    jwa.Algorithm
		jwk    map[string]any
		clause string
	}{
		"an oct jwk for ES256":      {jwa.ES256, secret, "RFC 7518 3.4"},
		"an oct jwk for RS256":      {jwa.RS256, secret, "RFC 7518 3.3"},
		"an oct jwk for Ed25519":    {jwa.Ed25519, secret, "RFC 9864 2.2"},
		"an oct jwk for ML-DSA-44":  {jwa.MLDSA44, secret, "RFC 9964 2"},
		"an EC jwk for HS256":       {jwa.HS256, ecJwkPair(t, elliptic.P256()).private, "RFC 7518 3.2"},
		"an RSA jwk for HS512":      {jwa.HS512, jwkPair(t, rsaKey, &rsaKey.PublicKey).private, "RFC 7518 3.2"},
		"an OKP jwk for HS384":      {jwa.HS384, ed25519JwkPair(t).private, "RFC 7518 3.2"},
		"a P-384 jwk for ES256":     {jwa.ES256, ecJwkPair(t, elliptic.P384()).private, "RFC 7518 3.4"},
		"an RSA jwk for ES256":      {jwa.ES256, jwkPair(t, rsaKey, &rsaKey.PublicKey).private, "RFC 7518 3.4"},
		"an X25519 jwk for Ed25519": {jwa.Ed25519, jwkPair(t, x25519Key, x25519Key.PublicKey()).private, "RFC 8037 3.2"},
		"an Ed25519 jwk for PS256":  {jwa.PS256, ed25519JwkPair(t).private, "RFC 7518 3.5"},
		"a P-256 jwk for ML-DSA-65": {jwa.MLDSA65, ecJwkPair(t, elliptic.P256()).private, "RFC 9964 2"},
	}
	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			signer, err := jws.GetSignerFromJwk(test.alg, test.jwk, nil)
			if !errors.Is(err, joseerror.ErrInvalidPrivateKey) {
				t.Errorf("[%s] %s is not a key for that algorithm, so it must be refused with ErrInvalidPrivateKey, got %v", test.clause, name, err)
			}
			if signer != nil {
				t.Errorf("[%s] no signer may be returned alongside the refusal, got %#v", test.clause, signer)
			}
		})
	}
}

func TestGetSignerFromJwk_RefusesAnRSAKeyBelow2048Bits(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 1024)
	if err != nil {
		t.Fatal(err)
	}
	privateJwk, err := jwk.PrivateJwk(key)
	if err != nil {
		t.Fatal(err)
	}
	for alg, clause := range map[jwa.Algorithm]string{jwa.RS256: "RFC 7518 3.3", jwa.RS512: "RFC 7518 3.3", jwa.PS256: "RFC 7518 3.5", jwa.PS384: "RFC 7518 3.5"} {
		t.Run(alg.String(), func(t *testing.T) {
			signer, err := jws.GetSignerFromJwk(alg, *privateJwk, nil)
			if !errors.Is(err, joseerror.ErrInvalidPrivateKey) || signer != nil {
				t.Errorf("[%s] a key of size 2048 bits or larger MUST be used, so a 1024-bit jwk must be refused with ErrInvalidPrivateKey, got %v and %v", clause, signer, err)
			}
		})
	}
}

func TestGetSignerFromJwk_RefusesAJwkWithNoPrivatePart(t *testing.T) {
	rsaKey := signerFromJwkRSA(t)
	examples := rfc9964Examples(t)
	tests := map[string]struct {
		alg    jwa.Algorithm
		jwk    map[string]any
		clause string
	}{
		"an EC jwk without d":        {jwa.ES256, ecJwkPair(t, elliptic.P256()).public, "RFC 7518 6.2.2.1"},
		"an RSA jwk without d":       {jwa.RS256, jwkPair(t, rsaKey, &rsaKey.PublicKey).public, "RFC 7518 6.3.2.1"},
		"an OKP jwk without d":       {jwa.Ed25519, ed25519JwkPair(t).public, "RFC 8037 2"},
		"an AKP jwk without priv":    {examples[0].alg, examples[0].publicJwk, "RFC 9964 4"},
		"an oct jwk without k":       {jwa.HS256, map[string]any{"kty": "oct"}, "RFC 7518 6.4.1"},
		"an oct jwk with an empty k": {jwa.HS256, map[string]any{"kty": "oct", "k": ""}, "RFC 7518 6.4.1"},
	}
	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			signer, err := jws.GetSignerFromJwk(test.alg, test.jwk, nil)
			if !errors.Is(err, joseerror.ErrInvalidPrivateKey) {
				t.Errorf("[%s] %s holds no private key to sign with, so it must be refused with ErrInvalidPrivateKey, got %v", test.clause, name, err)
			}
			if signer != nil {
				t.Errorf("[%s] no signer may be returned alongside the refusal, got %#v", test.clause, signer)
			}
		})
	}
}

func TestGetSignerFromJwk_SignsWithEachRFC9964ExampleJwk(t *testing.T) {
	for _, ex := range rfc9964Examples(t) {
		t.Run(ex.Alg, func(t *testing.T) {
			signer, err := jws.GetSignerFromJwk(ex.alg, ex.PrivateJwk, nil)
			if err != nil {
				t.Fatalf("[RFC 9964 A.1] the example private jwk is a key for %s, got %v", ex.Alg, err)
			}
			signature, err := signer.Sign(rand.Reader, ex.SigningInput, nil)
			if err != nil {
				t.Fatal(err)
			}
			validator, err := jws.GetValidatorFromJwk(ex.alg, ex.publicJwk, nil)
			if err != nil {
				t.Fatal(err)
			}
			if valid, err := validator.ValidateSignature(ex.SigningInput, signature); err != nil || !valid {
				t.Errorf("[RFC 9964 A.1] the example public jwk must verify what its private jwk signs, got %v and %v", valid, err)
			}
		})
	}
	examples := rfc9964Examples(t)
	signer, err := jws.GetSignerFromJwk(examples[1].alg, examples[0].PrivateJwk, nil)
	if !errors.Is(err, joseerror.ErrInvalidPrivateKey) || signer != nil {
		t.Errorf("[RFC 7517 4.4] an AKP jwk whose alg is %s is not a key for %s, got %v and %v", examples[0].Alg, examples[1].Alg, signer, err)
	}
}

func TestGetSignerFromJwk_RefusesAJwkWhoseAlgNamesAnotherAlgorithm(t *testing.T) {
	p256 := ecJwkPair(t, elliptic.P256()).private
	ed := ed25519JwkPair(t).private
	secret := octJwk(bytes.Repeat([]byte{2}, 64))
	tests := map[string]struct {
		alg    jwa.Algorithm
		jwk    map[string]any
		accept bool
	}{
		"alg ES256 for ES256":                {alg: jwa.ES256, jwk: with(p256, map[string]any{"alg": "ES256"}), accept: true},
		"alg EdDSA for Ed25519":              {alg: jwa.Ed25519, jwk: with(ed, map[string]any{"alg": "EdDSA"}), accept: true},
		"alg Ed25519 for Ed25519":            {alg: jwa.Ed25519, jwk: with(ed, map[string]any{"alg": "Ed25519"}), accept: true},
		"alg HS512 for HS512":                {alg: jwa.HS512, jwk: with(secret, map[string]any{"alg": "HS512"}), accept: true},
		"alg ES384 for ES256":                {alg: jwa.ES256, jwk: with(p256, map[string]any{"alg": "ES384"})},
		"alg es256, compared exactly":        {alg: jwa.ES256, jwk: with(p256, map[string]any{"alg": "es256"})},
		"alg ES256 with a trailing NUL":      {alg: jwa.ES256, jwk: with(p256, map[string]any{"alg": "ES256\x00"})},
		"alg that is a number":               {alg: jwa.ES256, jwk: with(p256, map[string]any{"alg": 7})},
		"alg that is an array":               {alg: jwa.ES256, jwk: with(p256, map[string]any{"alg": []any{"ES256"}})},
		"alg that is empty":                  {alg: jwa.ES256, jwk: with(p256, map[string]any{"alg": ""})},
		"alg HS256 for HS512":                {alg: jwa.HS512, jwk: with(secret, map[string]any{"alg": "HS256"})},
		"alg A256KW on an oct jwk for HS256": {alg: jwa.HS256, jwk: with(secret, map[string]any{"alg": "A256KW"})},
		"alg RS256 on an EC jwk for ES256":   {alg: jwa.ES256, jwk: with(p256, map[string]any{"alg": "RS256"})},
		"alg of a megabyte of unicode text":  {alg: jwa.ES256, jwk: with(p256, map[string]any{"alg": strings.Repeat("é", 1<<20)})},
	}
	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			signer, err := jws.GetSignerFromJwk(test.alg, test.jwk, nil)
			if test.accept {
				if err != nil || signer == nil {
					t.Errorf("[RFC 7517 4.4] a jwk whose alg names %s is intended for it, so it must build a signer, got %v", test.alg, err)
				}
				return
			}
			if !errors.Is(err, joseerror.ErrInvalidPrivateKey) {
				t.Errorf("[RFC 8725 3.1] each key MUST be used with exactly one algorithm, so a jwk with %s must be refused with ErrInvalidPrivateKey, got %v", name, err)
			}
			if err != nil && len(err.Error()) > 512 {
				t.Errorf("[RFC 8725 3.1] the refusal must echo a bounded part of the jwk's alg, got %d bytes", len(err.Error()))
			}
			if signer != nil {
				t.Errorf("[RFC 8725 3.1] no signer may be returned alongside the refusal, got %#v", signer)
			}
		})
	}
}

func TestGetSignerFromJwk_RefusesAJwkMarkedAsNotForSigning(t *testing.T) {
	p256 := ecJwkPair(t, elliptic.P256()).private
	manyOps := make([]any, 0, 10001)
	for i := range 10000 {
		manyOps = append(manyOps, "op"+strconv.Itoa(i))
	}
	manyOps = append(manyOps, "sign")

	tests := map[string]struct {
		members map[string]any
		accept  bool
		clause  string
	}{
		"no use and no key_ops":                  {members: map[string]any{}, accept: true, clause: "RFC 7517 4.2"},
		"use of sig":                             {members: map[string]any{"use": "sig"}, accept: true, clause: "RFC 7517 4.2"},
		"key_ops holding sign":                   {members: map[string]any{"key_ops": []any{"sign"}}, accept: true, clause: "RFC 7517 4.3"},
		"key_ops holding sign and verify":        {members: map[string]any{"key_ops": []any{"sign", "verify"}}, accept: true, clause: "RFC 7517 4.3"},
		"key_ops holding verify and sign":        {members: map[string]any{"key_ops": []any{"verify", "sign"}}, accept: true, clause: "RFC 7517 4.3"},
		"use of sig and key_ops of sign":         {members: map[string]any{"use": "sig", "key_ops": []any{"sign"}}, accept: true, clause: "RFC 7517 4.3"},
		"key_ops of sign and encrypt":            {members: map[string]any{"key_ops": []any{"sign", "encrypt"}}, accept: true, clause: "RFC 7517 4.3"},
		"key_ops of ten thousand distinct ops":   {members: map[string]any{"key_ops": manyOps}, accept: true, clause: "RFC 7517 4.3"},
		"use of enc":                             {members: map[string]any{"use": "enc"}, clause: "RFC 7517 4.2"},
		"use of SIG, compared exactly":           {members: map[string]any{"use": "SIG"}, clause: "RFC 7517 4.2"},
		"use that is empty":                      {members: map[string]any{"use": ""}, clause: "RFC 7517 4.2"},
		"use that is not a string":               {members: map[string]any{"use": 7}, clause: "RFC 7517 4.2"},
		"key_ops holding only verify":            {members: map[string]any{"key_ops": []any{"verify"}}, clause: "RFC 7517 4.3"},
		"key_ops holding Sign, compared exactly": {members: map[string]any{"key_ops": []any{"Sign"}}, clause: "RFC 7517 4.3"},
		"key_ops holding none":                   {members: map[string]any{"key_ops": []any{}}, clause: "RFC 7517 4.3"},
		"key_ops that is a string":               {members: map[string]any{"key_ops": "sign"}, clause: "RFC 7517 4.3"},
		"key_ops that is an object":              {members: map[string]any{"key_ops": map[string]any{"sign": true}}, clause: "RFC 7517 4.3"},
		"key_ops holding a number":               {members: map[string]any{"key_ops": []any{"sign", 7}}, clause: "RFC 7517 4.3"},
		"key_ops holding null":                   {members: map[string]any{"key_ops": []any{"sign", nil}}, clause: "RFC 7517 4.3"},
		"key_ops listing sign twice":             {members: map[string]any{"key_ops": []any{"sign", "sign"}}, clause: "RFC 7517 4.3"},
		"key_ops listing verify twice":           {members: map[string]any{"key_ops": []any{"verify", "sign", "verify"}}, clause: "RFC 7517 4.3"},
		"use of sig and key_ops of verify":       {members: map[string]any{"use": "sig", "key_ops": []any{"verify"}}, clause: "RFC 7517 4.3"},
		"use of enc and key_ops of sign":         {members: map[string]any{"use": "enc", "key_ops": []any{"sign"}}, clause: "RFC 7517 4.2"},
	}
	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			signer, err := jws.GetSignerFromJwk(jwa.ES256, with(p256, test.members), nil)
			if test.accept {
				if err != nil || signer == nil {
					t.Fatalf("[%s] a jwk with %s permits signing, so it must build a signer, got %v", test.clause, name, err)
				}
				return
			}
			if !errors.Is(err, joseerror.ErrInvalidPrivateKey) {
				t.Errorf("[%s] a jwk with %s is not marked for computing signatures, so it must be refused with ErrInvalidPrivateKey, got %v", test.clause, name, err)
			}
			if signer != nil {
				t.Errorf("[%s] no signer may be returned alongside the refusal, got %#v", test.clause, signer)
			}
		})
	}
}

func TestGetSignerFromJwk_StrictKeyOperationsRefusesWhatSection43SaysShouldNotBePublished(t *testing.T) {
	p256 := ecJwkPair(t, elliptic.P256()).private
	secret := octJwk(bytes.Repeat([]byte{3}, 32))
	tests := map[string]struct {
		alg     jwa.Algorithm
		jwk     map[string]any
		lenient bool
		strict  bool
	}{
		"use and key_ops together":            {jwa.ES256, with(p256, map[string]any{"use": "sig", "key_ops": []any{"sign"}}), true, false},
		"use and key_ops on an oct jwk":       {jwa.HS256, with(secret, map[string]any{"use": "sig", "key_ops": []any{"sign", "verify"}}), true, false},
		"key_ops of sign and encrypt":         {jwa.ES256, with(p256, map[string]any{"key_ops": []any{"sign", "encrypt"}}), true, false},
		"key_ops of sign, verify and wrapKey": {jwa.ES256, with(p256, map[string]any{"key_ops": []any{"sign", "verify", "wrapKey"}}), true, false},
		"key_ops of sign and verify":          {jwa.ES256, with(p256, map[string]any{"key_ops": []any{"sign", "verify"}}), true, true},
		"key_ops of sign alone":               {jwa.ES256, with(p256, map[string]any{"key_ops": []any{"sign"}}), true, true},
		"use of sig alone":                    {jwa.ES256, with(p256, map[string]any{"use": "sig"}), true, true},
	}
	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			for _, opts := range []*model.JoseOptions{nil, {}} {
				signer, err := jws.GetSignerFromJwk(test.alg, test.jwk, opts)
				if test.lenient != (err == nil && signer != nil) {
					t.Errorf("[RFC 7517 4.3] a SHOULD NOT is accepted by default, so %s must build a signer with options %v, got %v", name, opts, err)
				}
			}
			signer, err := jws.GetSignerFromJwk(test.alg, test.jwk, &model.JoseOptions{StrictKeyOperations: true})
			if test.strict {
				if err != nil || signer == nil {
					t.Errorf("[RFC 7517 4.3] %s is what section 4.3 permits, so StrictKeyOperations must accept it, got %v", name, err)
				}
				return
			}
			if !errors.Is(err, joseerror.ErrInvalidPrivateKey) || signer != nil {
				t.Errorf("[RFC 7517 4.3] %s SHOULD NOT be published, so StrictKeyOperations must refuse it with ErrInvalidPrivateKey, got %v and %v", name, signer, err)
			}
		})
	}
}

func TestGetSignerFromJwk_RefusesAnAlgorithmThatIsNotForSigningWithAJwk(t *testing.T) {
	p256 := ecJwkPair(t, elliptic.P256()).private
	secret := octJwk(bytes.Repeat([]byte{4}, 64))
	algorithms := append([]jwa.Algorithm{jwa.Unknown, jwa.Algorithm(-1), jwa.Algorithm(1 << 30)}, jweKeyManagementAlgorithms...)
	for _, alg := range algorithms {
		for name, key := range map[string]map[string]any{"EC": p256, "oct": secret} {
			t.Run(alg.String()+" "+name, func(t *testing.T) {
				signer, err := jws.GetSignerFromJwk(alg, key, nil)
				if !errors.Is(err, joseerror.ErrUnsupportedAlgorithm) || signer != nil {
					t.Errorf("[RFC 7518 3.1] %q is not a JWS signature algorithm, so it must be refused with ErrUnsupportedAlgorithm, got %v and %v", alg.String(), signer, err)
				}
			})
		}
	}
}

func TestGetSignerFromJwk_RefusesEdDSAAsGetSignerFromPrivateKeyDoes(t *testing.T) {
	pair := ed25519JwkPair(t)
	ed := pair.private
	tests := map[string]map[string]any{
		"no alg":            ed,
		"alg EdDSA":         with(ed, map[string]any{"alg": "EdDSA"}),
		"alg Ed25519":       with(ed, map[string]any{"alg": "Ed25519"}),
		"a public-only jwk": pair.public,
		"an empty jwk":      {},
		"use of enc":        with(ed, map[string]any{"use": "enc"}),
	}
	for name, key := range tests {
		t.Run(name, func(t *testing.T) {
			signer, err := jws.GetSignerFromJwk(jwa.EdDSA, key, nil)
			if !errors.Is(err, joseerror.ErrUnsupportedAlgorithm) || signer != nil {
				t.Errorf("[RFC 9864 4.1.2] EdDSA is deprecated, so signing with it must be refused with ErrUnsupportedAlgorithm, got %v and %v", signer, err)
			}
			if errors.Is(err, joseerror.ErrInvalidPrivateKey) {
				t.Errorf("[RFC 9864 4.1.2] EdDSA is refused whatever the jwk holds, so the refusal must name the algorithm, not the key, got %v", err)
			}
		})
	}
}

func TestGetSignerFromJwk_AMalformedJwkReturnsAnErrorAndNoPanic(t *testing.T) {
	tests := map[string]map[string]any{
		"a nil map":                       nil,
		"an empty map":                    {},
		"a kty that is a number":          {"kty": 7},
		"a kty that is an object":         {"kty": map[string]any{"kty": "EC"}},
		"a kty that is null":              {"kty": nil},
		"a kty that is empty":             {"kty": ""},
		"a kty that is unknown":           {"kty": "nonsense"},
		"an EC jwk with no members":       {"kty": "EC"},
		"an EC jwk with d a number":       {"kty": "EC", "crv": "P-256", "x": 1, "y": 2, "d": 3},
		"an oct jwk with k a number":      {"kty": "oct", "k": 7},
		"an oct jwk with k not base64url": {"kty": "oct", "k": "!!!!"},
	}
	for name, candidate := range tests {
		for _, alg := range []jwa.Algorithm{jwa.ES256, jwa.HS256, jwa.RS256, jwa.Ed25519, jwa.MLDSA44} {
			t.Run(name+" "+alg.String(), func(t *testing.T) {
				var signer model.Signer
				var err error
				func() {
					defer func() {
						if r := recover(); r != nil {
							t.Fatalf("[RFC 7517 4] a malformed jwk must return an error, never panic, got %v", r)
						}
					}()
					signer, err = jws.GetSignerFromJwk(alg, candidate, nil)
				}()
				if !errors.Is(err, joseerror.ErrInvalidPrivateKey) || signer != nil {
					t.Errorf("[RFC 7517 4] %s is not a private key, so it must be refused with ErrInvalidPrivateKey, got %v and %v", name, signer, err)
				}
			})
		}
	}
}

func TestGetSignerFromJwk_ReadsTheJwkThatPrivateJwkWrites(t *testing.T) {
	secret := bytes.Repeat([]byte{5}, 48)
	written, err := jwk.PrivateJwk(secret)
	if err != nil {
		t.Fatal(err)
	}
	signer, err := jws.GetSignerFromJwk(jwa.HS384, *written, nil)
	if err != nil {
		t.Fatalf("[RFC 7518 6.4] the oct jwk PrivateJwk writes for a 48-octet secret is a key for HS384, got %v", err)
	}
	mac, err := signer.Sign(rand.Reader, []byte(signerFromJwkInput), nil)
	if err != nil {
		t.Fatal(err)
	}
	want := hmac.New(sha512.New384, secret)
	want.Write([]byte(signerFromJwkInput))
	if !hmac.Equal(mac, want.Sum(nil)) {
		t.Errorf("[RFC 7518 3.2] the MAC must be under the secret PrivateJwk wrote, checked with crypto/hmac")
	}
}
