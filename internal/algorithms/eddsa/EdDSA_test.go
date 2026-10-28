package eddsa

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"strings"
	"testing"

	"github.com/MichaelFraser99/go-jose/joseerror"
	"github.com/MichaelFraser99/go-jose/jwa"
	"github.com/MichaelFraser99/go-jose/model"
)

const (
	rfc8037Seed         = "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60"
	rfc8037Public       = "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a"
	rfc8037SigningInput = "eyJhbGciOiJFZERTQSJ9.RXhhbXBsZSBvZiBFZDI1NTE5IHNpZ25pbmc"
	rfc8037Signature    = "860c98d2297f3060a33f42739672d61b53cf3adefed3d3c672f320dc021b411e9d59b8628dc351e248b88b29468e0e41855b0fb7d83bb15be902bfccb8cd0a02"
)

func rfc8037Key(t *testing.T) ed25519.PrivateKey {
	t.Helper()
	seed, err := hex.DecodeString(rfc8037Seed)
	if err != nil {
		t.Fatal(err)
	}
	return ed25519.NewKeyFromSeed(seed)
}

func mustHex(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func TestSign_MatchesTheRFC8037Ed25519Vector(t *testing.T) {
	signer, err := NewSignerFromPrivateKey(rfc8037Key(t))
	if err != nil {
		t.Fatal(err)
	}
	signature, err := signer.Sign(rand.Reader, []byte(rfc8037SigningInput), nil)
	if err != nil {
		t.Fatal(err)
	}
	if want := mustHex(t, rfc8037Signature); !bytes.Equal(signature, want) {
		t.Errorf("[RFC 8037 A.4] Ed25519 is deterministic, so the signature must be the example's\n got %x\nwant %x", signature, want)
	}
	if !bytes.Equal(signer.Public().(ed25519.PublicKey), mustHex(t, rfc8037Public)) {
		t.Errorf("[RFC 8037 A.1] the signer's public key must be the example's, got %x", signer.Public())
	}
}

func TestSign_IsPureEd25519(t *testing.T) {
	key := rfc8037Key(t)
	signer, err := NewSignerFromPrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	if signer.Alg() != jwa.Ed25519 {
		t.Errorf("[RFC 9864 4.1.1] the signer must report Ed25519, got %s", signer.Alg())
	}
	input := []byte(base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"Ed25519"}`)) + ".cGF5bG9hZA")
	signature, err := signer.Sign(rand.Reader, input, model.SignerOpts{})
	if err != nil {
		t.Fatal(err)
	}
	if want := ed25519.Sign(key, input); !bytes.Equal(signature, want) {
		t.Errorf("[RFC 9864 4.1.1] Ed25519 is EdDSA with the RFC 8032 section 5.1 parameters, so it must match crypto/ed25519\n got %x\nwant %x", signature, want)
	}
}

func TestSign_RefusesAPreHashedMode(t *testing.T) {
	signer, err := NewSignerFromPrivateKey(rfc8037Key(t))
	if err != nil {
		t.Fatal(err)
	}
	for _, hash := range []crypto.Hash{crypto.SHA512, crypto.SHA256, crypto.Hash(99)} {
		signature, err := signer.Sign(rand.Reader, []byte(rfc8037SigningInput), model.SignerOpts{Hash: hash})
		if !errors.Is(err, joseerror.ErrSigningError) || signature != nil {
			t.Errorf("[RFC 9864 4.1.1] Ed25519 is pure EdDSA, and a hash here would ask crypto/ed25519 for Ed25519ph, so %v must be refused with ErrSigningError, got %x and %v", hash, signature, err)
		}
	}
}

func TestNewSigner_GeneratesAWorkingKey(t *testing.T) {
	signer, err := NewSigner()
	if err != nil {
		t.Fatal(err)
	}
	if signer.Alg() != jwa.Ed25519 {
		t.Errorf("[RFC 9864 4.1.1] the signer must report Ed25519, got %s", signer.Alg())
	}
	signature, err := signer.Sign(rand.Reader, []byte("input"), nil)
	if err != nil {
		t.Fatal(err)
	}
	if !ed25519.Verify(signer.Public().(ed25519.PublicKey), []byte("input"), signature) {
		t.Error("[RFC 8032 5.1.6] a generated signer's signature must verify under its own public key")
	}
}

func TestNewSignerFromPrivateKey_AcceptsTheValueAndAPointer(t *testing.T) {
	key := rfc8037Key(t)
	for name, given := range map[string]crypto.PrivateKey{"value": key, "pointer": &key} {
		if _, err := NewSignerFromPrivateKey(given); err != nil {
			t.Errorf("an ed25519 private key given as a %s must be accepted, got %v", name, err)
		}
	}
}

func TestNewSignerFromPrivateKey_RefusesAKeyItCannotSignWith(t *testing.T) {
	key := rfc8037Key(t)
	mismatched := ed25519.PrivateKey(bytes.Clone(key))
	mismatched[ed25519.PrivateKeySize-1] ^= 1
	ecdsaKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	tests := map[string]crypto.PrivateKey{
		"nil":                           nil,
		"a nil pointer":                 (*ed25519.PrivateKey)(nil),
		"empty":                         ed25519.PrivateKey{},
		"the 32 byte seed alone":        ed25519.PrivateKey(key.Seed()),
		"one byte short":                key[:ed25519.PrivateKeySize-1],
		"one byte over":                 ed25519.PrivateKey(append(bytes.Clone(key), 0)),
		"a public half not of its seed": mismatched,
		"a pointer to a mismatched key": &mismatched,
		"an ecdsa key":                  ecdsaKey,
		"the public key":                key.Public(),
		"the seed as bytes":             key.Seed(),
	}
	for name, given := range tests {
		t.Run(name, func(t *testing.T) {
			signer, err := NewSignerFromPrivateKey(given)
			if !errors.Is(err, joseerror.ErrInvalidPrivateKey) {
				t.Errorf("[RFC 8032 5.1.5] an Ed25519 private key is a 32 byte seed and the public key derived from it, so this must be refused with ErrInvalidPrivateKey, got %v", err)
			}
			if signer != nil {
				t.Errorf("a refused key must build no signer, got %#v", signer)
			}
		})
	}
}

func TestNewSignerFromPrivateKey_DoesNotShareTheCallersKey(t *testing.T) {
	key := ed25519.PrivateKey(bytes.Clone(rfc8037Key(t)))
	signer, err := NewSignerFromPrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	clear(key)
	signature, err := signer.Sign(rand.Reader, []byte(rfc8037SigningInput), nil)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(signature, mustHex(t, rfc8037Signature)) {
		t.Error("[RFC 8037 A.4] zeroing the caller's key after building a signer must not change what the signer signs with")
	}
}

func TestValidateSignature_VerifiesTheRFC8037Example(t *testing.T) {
	public := ed25519.PublicKey(mustHex(t, rfc8037Public))
	signature := mustHex(t, rfc8037Signature)
	for name, given := range map[string]crypto.PublicKey{"value": public, "pointer": &public} {
		t.Run(name, func(t *testing.T) {
			validator, err := NewValidator(given)
			if err != nil {
				t.Fatal(err)
			}
			valid, err := validator.ValidateSignature([]byte(rfc8037SigningInput), signature)
			if err != nil || !valid {
				t.Errorf("[RFC 8037 A.5] the example signature must verify, got %v and %v", valid, err)
			}
			if !bytes.Equal(validator.Public().(ed25519.PublicKey), public) {
				t.Errorf("the validator must report the key it was built with, got %x", validator.Public())
			}
		})
	}
}

func TestValidateSignature_ReportsAnAlteredSignatureOrInputAsInvalid(t *testing.T) {
	validator, err := NewValidator(ed25519.PublicKey(mustHex(t, rfc8037Public)))
	if err != nil {
		t.Fatal(err)
	}
	signature := mustHex(t, rfc8037Signature)
	flippedSignature := bytes.Clone(signature)
	flippedSignature[0] ^= 1
	flippedS := bytes.Clone(signature)
	flippedS[ed25519.SignatureSize-1] ^= 0x80

	tests := map[string]struct {
		input, signature []byte
	}{
		"a bit flipped in R":    {[]byte(rfc8037SigningInput), flippedSignature},
		"a high bit set in S":   {[]byte(rfc8037SigningInput), flippedS},
		"a changed input":       {[]byte(strings.Replace(rfc8037SigningInput, "J", "K", 1)), signature},
		"an empty signature":    {[]byte(rfc8037SigningInput), nil},
		"one byte short":        {[]byte(rfc8037SigningInput), signature[:ed25519.SignatureSize-1]},
		"one byte over":         {[]byte(rfc8037SigningInput), append(bytes.Clone(signature), 0)},
		"an all zero signature": {[]byte(rfc8037SigningInput), make([]byte, ed25519.SignatureSize)},
	}
	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			valid, err := validator.ValidateSignature(tc.input, tc.signature)
			if valid || err != nil {
				t.Errorf("[RFC 7515 5.2] a signature that does not verify reports false with no error, got %v and %v", valid, err)
			}
		})
	}
}

func TestNewValidator_RefusesAKeyItCannotVerifyWith(t *testing.T) {
	public := ed25519.PublicKey(mustHex(t, rfc8037Public))
	ecdsaKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tests := map[string]crypto.PublicKey{
		"nil":             nil,
		"a nil pointer":   (*ed25519.PublicKey)(nil),
		"empty":           ed25519.PublicKey{},
		"one byte short":  public[:ed25519.PublicKeySize-1],
		"one byte over":   ed25519.PublicKey(append(bytes.Clone(public), 0)),
		"the private key": rfc8037Key(t),
		"an ecdsa key":    &ecdsaKey.PublicKey,
		"raw bytes":       []byte(public),
	}
	for name, given := range tests {
		t.Run(name, func(t *testing.T) {
			validator, err := NewValidator(given)
			if !errors.Is(err, joseerror.ErrInvalidPublicKey) {
				t.Errorf("[RFC 8032 5.1.5] an Ed25519 public key is 32 octets, so this must be refused with ErrInvalidPublicKey, got %v", err)
			}
			if validator != nil {
				t.Errorf("a refused key must build no validator, got %#v", validator)
			}
		})
	}
}

func TestNewValidator_DoesNotShareTheCallersKey(t *testing.T) {
	public := ed25519.PublicKey(mustHex(t, rfc8037Public))
	validator, err := NewValidator(public)
	if err != nil {
		t.Fatal(err)
	}
	clear(public)
	valid, err := validator.ValidateSignature([]byte(rfc8037SigningInput), mustHex(t, rfc8037Signature))
	if err != nil || !valid {
		t.Errorf("[RFC 8037 A.5] zeroing the caller's key after building a validator must not change what it verifies with, got %v and %v", valid, err)
	}
}

func TestSameAlgorithm_MatchesTheTwoEd25519IdentifiersAndNothingElse(t *testing.T) {
	tests := []struct {
		member, alg string
		same        bool
	}{
		{"EdDSA", "Ed25519", true},
		{"Ed25519", "EdDSA", true},
		{"EdDSA", "EdDSA", true},
		{"Ed25519", "Ed25519", true},
		{"ES256", "ES256", true},
		{"ES256", "EdDSA", false},
		{"EdDSA", "ES256", false},
		{"Ed448", "EdDSA", false},
		{"EdDSA", "Ed448", false},
		{"eddsa", "Ed25519", false},
		{"", "Ed25519", false},
		{"Ed25519", "", false},
	}
	for _, tc := range tests {
		if got := SameAlgorithm(tc.member, tc.alg); got != tc.same {
			t.Errorf("[RFC 8725 3.1] SameAlgorithm(%q, %q) = %v, want %v", tc.member, tc.alg, got, tc.same)
		}
	}
}
