package mldsa

import (
	"bytes"
	"crypto"
	"crypto/ed25519"
	fips204 "crypto/mldsa"
	"crypto/rand"
	"errors"
	"testing"

	"github.com/MichaelFraser99/go-jose/internal/testvectors"
	"github.com/MichaelFraser99/go-jose/joseerror"
	"github.com/MichaelFraser99/go-jose/jwa"
	"github.com/MichaelFraser99/go-jose/model"
)

type example struct {
	testvectors.MLDSAExample
	alg     jwa.Algorithm
	params  fips204.Parameters
	private *fips204.PrivateKey
	public  *fips204.PublicKey
}

func rfc9964Examples(t *testing.T) []example {
	t.Helper()
	raw, err := testvectors.RFC9964()
	if err != nil {
		t.Fatal(err)
	}
	sets := map[string]fips204.Parameters{"ML-DSA-44": fips204.MLDSA44(), "ML-DSA-65": fips204.MLDSA65(), "ML-DSA-87": fips204.MLDSA87()}
	var examples []example
	for _, r := range raw {
		params := sets[r.Alg]
		private, err := fips204.NewPrivateKey(params, r.Seed)
		if err != nil {
			t.Fatal(err)
		}
		public, err := fips204.NewPublicKey(params, r.PublicKey)
		if err != nil {
			t.Fatal(err)
		}
		examples = append(examples, example{MLDSAExample: r, alg: jwa.GetAlgorithm(r.Alg), params: params, private: private, public: public})
	}
	if len(examples) != 3 {
		t.Fatalf("[RFC 9964 A.1] expected an example for each of ML-DSA-44, ML-DSA-65 and ML-DSA-87, got %d", len(examples))
	}
	return examples
}

func TestValidateSignature_VerifiesEachRFC9964Example(t *testing.T) {
	for _, ex := range rfc9964Examples(t) {
		t.Run(ex.Alg, func(t *testing.T) {
			validator, err := NewValidator(ex.alg, ex.public)
			if err != nil {
				t.Fatal(err)
			}
			valid, err := validator.ValidateSignature(ex.SigningInput, ex.Signature)
			if !valid || err != nil {
				t.Errorf("[RFC 9964 A.1] the example signature must verify under the example key, got %v and %v", valid, err)
			}
			if !bytes.Equal(validator.Public().(*fips204.PublicKey).Bytes(), ex.PublicKey) {
				t.Error("[RFC 9964 A.1] the validator must report the key it was built with")
			}
		})
	}
}

func TestSign_ProducesASignatureTheRFC9964ExampleKeyVerifies(t *testing.T) {
	for _, ex := range rfc9964Examples(t) {
		t.Run(ex.Alg, func(t *testing.T) {
			signer, err := NewSignerFromPrivateKey(ex.alg, ex.private)
			if err != nil {
				t.Fatal(err)
			}
			if signer.Alg() != ex.alg {
				t.Errorf("[RFC 9964 5] the signer must report %s, got %s", ex.alg, signer.Alg())
			}
			if !bytes.Equal(signer.Public().(*fips204.PublicKey).Bytes(), ex.PublicKey) {
				t.Error("[RFC 9964 A.1] the signer's public key must be the one the example seed derives")
			}
			signature, err := signer.Sign(rand.Reader, ex.SigningInput, nil)
			if err != nil {
				t.Fatal(err)
			}
			if len(signature) != ex.params.SignatureSize() {
				t.Errorf("[RFC 9964 5] an %s signature is %d bytes, got %d", ex.Alg, ex.params.SignatureSize(), len(signature))
			}
			if err := fips204.Verify(ex.public, ex.SigningInput, signature, nil); err != nil {
				t.Errorf("[RFC 9964 5] the signature must verify under the example public key with an empty context, got %v", err)
			}
			again, err := signer.Sign(rand.Reader, ex.SigningInput, nil)
			if err != nil {
				t.Fatal(err)
			}
			if bytes.Equal(signature, again) {
				t.Error("[FIPS 204 3.4] the signer uses the hedged variant, so two signatures of one input must differ")
			}
		})
	}
}

func TestSign_RefusesAPreHashedModeOrAContext(t *testing.T) {
	ex := rfc9964Examples(t)[0]
	signer, err := NewSignerFromPrivateKey(ex.alg, ex.private)
	if err != nil {
		t.Fatal(err)
	}
	tests := map[string]crypto.SignerOpts{
		"an external mu":                       crypto.MLDSAMu,
		"a SHA-512 hash":                       crypto.SHA512,
		"a pre-hash in this library's options": model.SignerOpts{Hash: crypto.SHA256},
		"a non-empty context":                  &fips204.Options{Context: "jose"},
	}
	for name, opts := range tests {
		t.Run(name, func(t *testing.T) {
			signature, err := signer.Sign(rand.Reader, ex.SigningInput, opts)
			if !errors.Is(err, joseerror.ErrSigningError) || signature != nil {
				t.Errorf("[RFC 9964 5] JOSE signs the whole input with an empty context, so this must be refused with ErrSigningError, got %x and %v", signature, err)
			}
		})
	}
	for name, opts := range map[string]crypto.SignerOpts{"nil options": nil, "an empty context": &fips204.Options{}, "a nil *Options": (*fips204.Options)(nil), "zero SignerOpts": model.SignerOpts{}} {
		t.Run(name, func(t *testing.T) {
			signature, err := signer.Sign(rand.Reader, ex.SigningInput, opts)
			if err != nil {
				t.Fatalf("[RFC 9964 5] %s asks for JOSE signing, got %v", name, err)
			}
			if err := fips204.Verify(ex.public, ex.SigningInput, signature, nil); err != nil {
				t.Errorf("[RFC 9964 5] the signature must verify with an empty context, got %v", err)
			}
		})
	}
}

func TestNewSigner_GeneratesAKeyOfEachParameterSet(t *testing.T) {
	for _, ex := range rfc9964Examples(t) {
		t.Run(ex.Alg, func(t *testing.T) {
			signer, err := NewSigner(ex.alg)
			if err != nil {
				t.Fatal(err)
			}
			public := signer.Public().(*fips204.PublicKey)
			if len(public.Bytes()) != ex.params.PublicKeySize() {
				t.Errorf("[RFC 9964 5] an %s public key is %d bytes, got %d", ex.Alg, ex.params.PublicKeySize(), len(public.Bytes()))
			}
			signature, err := signer.Sign(rand.Reader, []byte("input"), nil)
			if err != nil {
				t.Fatal(err)
			}
			if err := fips204.Verify(public, []byte("input"), signature, nil); err != nil {
				t.Errorf("[FIPS 204 5.3] a generated signer's signature must verify under its own key, got %v", err)
			}
		})
	}
}

func TestNewSignerFromPrivateKey_RefusesAKeyItCannotSignWith(t *testing.T) {
	examples := rfc9964Examples(t)
	_, edKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tests := map[string]crypto.PrivateKey{
		"nil":                            nil,
		"a nil pointer":                  (*fips204.PrivateKey)(nil),
		"a zero-value key":               &fips204.PrivateKey{},
		"an ML-DSA-65 key for ML-DSA-44": examples[1].private,
		"an ML-DSA-87 key for ML-DSA-44": examples[2].private,
		"the public key":                 examples[0].public,
		"an ed25519 key":                 edKey,
		"the seed as bytes":              examples[0].Seed,
	}
	for name, given := range tests {
		t.Run(name, func(t *testing.T) {
			signer, err := NewSignerFromPrivateKey(jwa.MLDSA44, given)
			if !errors.Is(err, joseerror.ErrInvalidPrivateKey) {
				t.Errorf("[RFC 9964 5] an ML-DSA-44 signer needs an ML-DSA-44 private key, so this must be refused with ErrInvalidPrivateKey, got %v", err)
			}
			if signer != nil {
				t.Errorf("a refused key must build no signer, got %#v", signer)
			}
		})
	}
}

func TestNewValidator_RefusesAKeyItCannotVerifyWith(t *testing.T) {
	examples := rfc9964Examples(t)
	edPublic, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tests := map[string]crypto.PublicKey{
		"nil":                            nil,
		"a nil pointer":                  (*fips204.PublicKey)(nil),
		"a zero-value key":               &fips204.PublicKey{},
		"an ML-DSA-65 key for ML-DSA-44": examples[1].public,
		"an ML-DSA-87 key for ML-DSA-44": examples[2].public,
		"the private key":                examples[0].private,
		"an ed25519 key":                 edPublic,
		"the encoding as bytes":          examples[0].PublicKey,
	}
	for name, given := range tests {
		t.Run(name, func(t *testing.T) {
			validator, err := NewValidator(jwa.MLDSA44, given)
			if !errors.Is(err, joseerror.ErrInvalidPublicKey) {
				t.Errorf("[RFC 9964 5] an ML-DSA-44 validator needs an ML-DSA-44 public key, so this must be refused with ErrInvalidPublicKey, got %v", err)
			}
			if validator != nil {
				t.Errorf("a refused key must build no validator, got %#v", validator)
			}
		})
	}
}

func TestValidateSignature_ReportsASignatureThatDoesNotVerifyAsInvalid(t *testing.T) {
	examples := rfc9964Examples(t)
	ex := examples[0]
	validator, err := NewValidator(ex.alg, ex.public)
	if err != nil {
		t.Fatal(err)
	}
	flipped := bytes.Clone(ex.Signature)
	flipped[len(flipped)/2] ^= 1
	withContext, err := ex.private.Sign(nil, ex.SigningInput, &fips204.Options{Context: "jose"})
	if err != nil {
		t.Fatal(err)
	}
	tests := map[string]struct{ input, signature []byte }{
		"a bit flipped":              {ex.SigningInput, flipped},
		"a changed input":            {append(bytes.Clone(ex.SigningInput), '.'), ex.Signature},
		"an empty signature":         {ex.SigningInput, nil},
		"one byte short":             {ex.SigningInput, ex.Signature[:len(ex.Signature)-1]},
		"one byte over":              {ex.SigningInput, append(bytes.Clone(ex.Signature), 0)},
		"all zero":                   {ex.SigningInput, make([]byte, len(ex.Signature))},
		"an ML-DSA-65 signature":     {examples[1].SigningInput, examples[1].Signature},
		"a signature with a context": {ex.SigningInput, withContext},
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
