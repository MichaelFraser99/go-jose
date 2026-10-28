package jws_test

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"errors"
	"testing"

	"github.com/MichaelFraser99/go-jose/joseerror"
	"github.com/MichaelFraser99/go-jose/jwa"
	"github.com/MichaelFraser99/go-jose/jwk"
	"github.com/MichaelFraser99/go-jose/jws"
	"github.com/MichaelFraser99/go-jose/model"
)

const (
	rfc8037D       = "nWGxne_9WmC6hEr0kuwsxERJxWl7MmkZcDusAxyuf2A"
	rfc8037X       = "11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo"
	rfc8037Input   = "eyJhbGciOiJFZERTQSJ9.RXhhbXBsZSBvZiBFZDI1NTE5IHNpZ25pbmc"
	rfc8037SigB64  = "hgyY0il_MGCjP0JzlnLWG1PPOt7-09PGcvMg3AIbQR6dWbhijcNR4ki4iylGjg5BhVsPt9g7sVvpAr_MuM0KAg"
	rfc8037Compact = rfc8037Input + "." + rfc8037SigB64
)

func rfc8037PublicJwk() map[string]any {
	return map[string]any{"kty": "OKP", "crv": "Ed25519", "x": rfc8037X}
}

func rfc8037PrivateKey(t *testing.T) crypto.PrivateKey {
	t.Helper()
	key, err := jwk.PrivateFromJwk(map[string]any{"kty": "OKP", "crv": "Ed25519", "d": rfc8037D, "x": rfc8037X})
	if err != nil {
		t.Fatal(err)
	}
	return key
}

func retrieving(keys ...crypto.PublicKey) model.Retriever {
	return func() ([]crypto.PublicKey, error) { return keys, nil }
}

func newEd25519Key(t *testing.T) ed25519.PrivateKey {
	t.Helper()
	_, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return key
}

func TestGetSignerFromPrivateKey_ReproducesTheRFC8037Ed25519Signature(t *testing.T) {
	signer, err := jws.GetSignerFromPrivateKey(jwa.Ed25519, rfc8037PrivateKey(t))
	if err != nil {
		t.Fatal(err)
	}
	signature, err := signer.Sign(rand.Reader, []byte(rfc8037Input), nil)
	if err != nil {
		t.Fatal(err)
	}
	if got := base64.RawURLEncoding.EncodeToString(signature); got != rfc8037SigB64 {
		t.Errorf("[RFC 8037 A.4] Ed25519 is deterministic, so the example key over the example input must give the example signature\n got %s\nwant %s", got, rfc8037SigB64)
	}

	validator, err := jws.GetValidatorFromJwk(jwa.Ed25519, rfc8037PublicJwk())
	if err != nil {
		t.Fatal(err)
	}
	if valid, err := validator.ValidateSignature([]byte(rfc8037Input), signature); !valid || err != nil {
		t.Errorf("[RFC 8037 A.5] a validator built from the example jwk must accept the example signature, got %v and %v", valid, err)
	}
}

func TestVerify_ATokenNamingTheDeprecatedEdDSAIsRefusedBeforeAnyKeyIsSought(t *testing.T) {
	if alg := jwa.GetAlgorithm("EdDSA"); alg != jwa.Unknown {
		t.Errorf("[RFC 9864 4.1.2] EdDSA is deprecated and this library implements Ed25519 in its place, so the name must map to Unknown, got %s", alg)
	}
	public, err := jwk.PublicFromJwk(rfc8037PublicJwk())
	if err != nil {
		t.Fatal(err)
	}
	called := false
	retriever := func() ([]crypto.PublicKey, error) {
		called = true
		return []crypto.PublicKey{public}, nil
	}
	_, _, err = jws.Verify(context.Background(), rfc8037Compact, retriever, nil)
	if !errors.Is(err, joseerror.ErrUnsupportedAlgorithm) {
		t.Errorf("[RFC 9864 4.1.2] the RFC 8037 example JWS names EdDSA, so it must be refused with ErrUnsupportedAlgorithm even under its own key, got %v", err)
	}
	if called {
		t.Error("[RFC 7515 5.2 step 5] a token whose alg is not supported must be refused before any key is sought")
	}
}

func TestGetSigner_SignsAnEd25519TokenItsValidatorAccepts(t *testing.T) {
	signer, err := jws.GetSigner(jwa.Ed25519, nil)
	if err != nil {
		t.Fatal(err)
	}
	if signer.Alg() != jwa.Ed25519 {
		t.Errorf("[RFC 7515 4.1.1] the signer must report Ed25519, got %s", signer.Alg())
	}
	head := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"Ed25519"}`))
	input := head + "." + base64.RawURLEncoding.EncodeToString([]byte(`{"sub":"test"}`))
	signature, err := signer.Sign(rand.Reader, []byte(input), nil)
	if err != nil {
		t.Fatal(err)
	}
	token := input + "." + base64.RawURLEncoding.EncodeToString(signature)
	if _, _, err := jws.VerifyCompactSerialization(context.Background(), token, retrieving(signer.Public()), nil); err != nil {
		t.Errorf("[RFC 7515 5.2] a token signed with Ed25519 must verify under the signer's public key, got %v", err)
	}
	if _, _, err := jws.VerifyCompactSerialization(context.Background(), token, retrieving(newEd25519Key(t).Public()), nil); err == nil {
		t.Error("[RFC 7515 5.2 step 8] a token must not verify under an unrelated Ed25519 key")
	}
}

func TestGetValidatorFromJwk_BindsAnOKPKeyToEd25519(t *testing.T) {
	ecdsaKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	ecJwk, err := jwk.PublicJwk(&ecdsaKey.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	with := func(member string, value any) map[string]any {
		key := rfc8037PublicJwk()
		key[member] = value
		return key
	}

	tests := map[string]struct {
		alg    jwa.Algorithm
		jwk    map[string]any
		want   error
		clause string
	}{
		"a key for EdDSA asked for Ed25519": {jwa.Ed25519, with("alg", "EdDSA"), joseerror.ErrInvalidPublicKey, "RFC 8725 3.1"},
		"an X25519 key":                     {jwa.Ed25519, with("crv", "X25519"), joseerror.ErrUnsupportedAlgorithm, "RFC 9864 4.1.1"},
		"an Ed448 key":                      {jwa.Ed25519, with("crv", "Ed448"), joseerror.ErrUnsupportedAlgorithm, "RFC 9864 4.1.1"},
		"an EC key":                         {jwa.Ed25519, *ecJwk, joseerror.ErrInvalidPublicKey, "RFC 9864 4.1.1"},
		"an Ed25519 key asked for ES256":    {jwa.ES256, rfc8037PublicJwk(), joseerror.ErrInvalidPublicKey, "RFC 7518 3.4"},
		"an Ed25519 key asked for RS256":    {jwa.RS256, rfc8037PublicJwk(), joseerror.ErrInvalidPublicKey, "RFC 7518 3.3"},
	}
	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			validator, err := jws.GetValidatorFromJwk(tc.alg, tc.jwk)
			if !errors.Is(err, tc.want) {
				t.Errorf("[%s] want %v, got %v", tc.clause, tc.want, err)
			}
			if validator != nil {
				t.Errorf("[%s] a refused construction must return a nil Validator, got %#v", tc.clause, validator)
			}
		})
	}

	if _, err := jws.GetValidatorFromJwk(jwa.Ed25519, with("alg", "Ed25519")); err != nil {
		t.Errorf("[RFC 8725 3.1] a key whose alg names Ed25519 must build an Ed25519 validator, got %v", err)
	}
}

func TestGetValidator_RefusesAKeyOfAnotherFamilyForEd25519(t *testing.T) {
	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	edPublic := newEd25519Key(t).Public()
	tests := map[string]struct {
		alg jwa.Algorithm
		key crypto.PublicKey
	}{
		"an rsa key for Ed25519":   {jwa.Ed25519, &rsaKey.PublicKey},
		"an ed25519 key for ES256": {jwa.ES256, edPublic},
		"an ed25519 key for PS256": {jwa.PS256, edPublic},
	}
	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			validator, err := jws.GetValidator(tc.alg, tc.key)
			if !errors.Is(err, joseerror.ErrInvalidPublicKey) || validator != nil {
				t.Errorf("[RFC 8725 3.1] an alg fixes the key type it verifies with, so this must be refused with ErrInvalidPublicKey and no validator, got %#v and %v", validator, err)
			}
		})
	}
}

func TestVerify_AnEd25519KeyTheTokenCarriesIsUsedOnlyWhenOptedIn(t *testing.T) {
	key := newEd25519Key(t)
	publicJwk, err := jwk.PublicJwk(key.Public())
	if err != nil {
		t.Fatal(err)
	}
	token := signWithHeader(t, jwa.Ed25519, key, map[string]any{"jwk": *publicJwk})

	if _, _, err := jws.Verify(context.Background(), token, nil, &model.JoseOptions{UseTokenProvidedKeys: true}); err != nil {
		t.Errorf("[RFC 7515 4.1.3] an opted-in caller must have the token's own Ed25519 jwk verify it, got %v", err)
	}
	if _, _, err := jws.Verify(context.Background(), token, nil, nil); err == nil {
		t.Error("[RFC 7515 10.3] the token's own key authenticates nothing, so it must not verify unless the caller opts in")
	}
}

func TestVerify_AnEd25519KeyInAnX5cChainToATrustedRoot(t *testing.T) {
	root := rootCA(t, newEd25519Key(t))
	leafKey := newEd25519Key(t)
	token := signWithX5c(t, jwa.Ed25519, leafKey, []string{der64(leaf(t, leafKey, root))})

	if _, _, err := jws.Verify(context.Background(), token, nil, &model.JoseOptions{X509Roots: roots(root)}); err != nil {
		t.Errorf("[RFC 7515 4.1.6] an Ed25519 certificate that chains to a configured root must verify the token, got %v", err)
	}
	if _, _, err := jws.Verify(context.Background(), token, nil, &model.JoseOptions{X509Roots: roots(rootCA(t, p256Key(t)))}); err == nil {
		t.Error("[RFC 7515 4.1.6] an Ed25519 certificate that chains to no configured root must not verify the token")
	}
}
