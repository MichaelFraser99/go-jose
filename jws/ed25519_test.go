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
	"encoding/json"
	"errors"
	"maps"
	"net/http"
	"net/http/httptest"
	"strings"
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

func TestVerify_TheRFC8037ExampleJWSNamingTheDeprecatedEdDSA(t *testing.T) {
	public, err := jwk.PublicFromJwk(rfc8037PublicJwk())
	if err != nil {
		t.Fatal(err)
	}
	head, payload, err := jws.Verify(context.Background(), rfc8037Compact, retrieving(public), nil)
	if err != nil {
		t.Fatalf("[RFC 9864 4.4] a deprecated identifier is to be avoided by new producers, not refused by verifiers, so the RFC 8037 A.5 example must verify under its own key, got %v", err)
	}
	if head["alg"] != "EdDSA" || string(payload) != "Example of Ed25519 signing" {
		t.Errorf("[RFC 8037 A.4] the example's header and payload must come back as signed, got %v and %q", head, payload)
	}

	validator, err := jws.GetValidatorFromJwk(jwa.EdDSA, rfc8037PublicJwk())
	if err != nil {
		t.Fatal(err)
	}
	signature, err := base64.RawURLEncoding.DecodeString(rfc8037SigB64)
	if err != nil {
		t.Fatal(err)
	}
	if valid, err := validator.ValidateSignature([]byte(rfc8037Input), signature); !valid || err != nil {
		t.Errorf("[RFC 8037 A.5] an EdDSA validator from the example jwk must accept the example signature, got %v and %v", valid, err)
	}

	tampered := rfc8037Input + "." + "AAAA" + rfc8037SigB64[4:]
	if _, _, err := jws.Verify(context.Background(), tampered, retrieving(public), nil); err == nil {
		t.Error("[RFC 7515 5.2 step 8] an altered EdDSA signature must not verify")
	}
}

func TestGetSigner_RefusesToSignWithTheDeprecatedEdDSA(t *testing.T) {
	for name, build := range map[string]func() (model.Signer, error){
		"GetSigner":               func() (model.Signer, error) { return jws.GetSigner(jwa.EdDSA, nil) },
		"GetSignerFromPrivateKey": func() (model.Signer, error) { return jws.GetSignerFromPrivateKey(jwa.EdDSA, rfc8037PrivateKey(t)) },
	} {
		t.Run(name, func(t *testing.T) {
			signer, err := build()
			if !errors.Is(err, joseerror.ErrUnsupportedAlgorithm) || signer != nil {
				t.Errorf("[RFC 9864 4.1.2] new producers SHOULD use Ed25519 in place of the deprecated EdDSA, so %s must refuse it with ErrUnsupportedAlgorithm and no signer, got %#v and %v", name, signer, err)
			}
			if err != nil && !strings.Contains(err.Error(), "sign with Ed25519") {
				t.Errorf("[RFC 9864 4.1.2] the refusal must name Ed25519 as the replacement, got %v", err)
			}
		})
	}
}

func TestVerify_AnAllowListNamingOneEdDSAIdentifierRefusesTheOther(t *testing.T) {
	signer, err := jws.GetSigner(jwa.Ed25519, nil)
	if err != nil {
		t.Fatal(err)
	}
	head := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"Ed25519"}`))
	input := head + "." + base64.RawURLEncoding.EncodeToString([]byte(`{"sub":"test"}`))
	signature, err := signer.Sign(rand.Reader, []byte(input), nil)
	if err != nil {
		t.Fatal(err)
	}
	ed25519Token := input + "." + base64.RawURLEncoding.EncodeToString(signature)
	public, err := jwk.PublicFromJwk(rfc8037PublicJwk())
	if err != nil {
		t.Fatal(err)
	}

	tests := map[string]struct {
		token   string
		key     crypto.PublicKey
		allowed jwa.Algorithm
	}{
		"an Ed25519 token with only EdDSA allowed": {ed25519Token, signer.Public(), jwa.EdDSA},
		"an EdDSA token with only Ed25519 allowed": {rfc8037Compact, public, jwa.Ed25519},
	}
	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			_, _, err := jws.Verify(context.Background(), tc.token, retrieving(tc.key), &model.JoseOptions{AllowedSigningAlgorithms: []jwa.Algorithm{tc.allowed}})
			if !errors.Is(err, joseerror.ErrUnsupportedAlgorithm) {
				t.Errorf("[RFC 7515 4.1.1] EdDSA and Ed25519 are distinct alg values, so a caller allowing only one must not be handed a token naming the other, got %v", err)
			}
		})
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

func TestGetValidatorFromJwk_BindsAnOKPKeyToEitherEdDSAIdentifier(t *testing.T) {
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
	ecNamedEdDSA := maps.Clone(*ecJwk)
	ecNamedEdDSA["alg"] = "EdDSA"

	tests := map[string]struct {
		alg    jwa.Algorithm
		jwk    map[string]any
		want   error
		clause string
	}{
		"an X25519 key for Ed25519":            {jwa.Ed25519, with("crv", "X25519"), joseerror.ErrUnsupportedAlgorithm, "RFC 9864 4.1.1"},
		"an X25519 key for EdDSA":              {jwa.EdDSA, with("crv", "X25519"), joseerror.ErrUnsupportedAlgorithm, "RFC 8037 3.1"},
		"an Ed448 key for Ed25519":             {jwa.Ed25519, with("crv", "Ed448"), joseerror.ErrUnsupportedAlgorithm, "RFC 9864 4.1.1"},
		"an Ed448 key for EdDSA":               {jwa.EdDSA, with("crv", "Ed448"), joseerror.ErrUnsupportedAlgorithm, "RFC 8037 3.1"},
		"an EC key for Ed25519":                {jwa.Ed25519, *ecJwk, joseerror.ErrInvalidPublicKey, "RFC 9864 4.1.1"},
		"an EC key for EdDSA":                  {jwa.EdDSA, *ecJwk, joseerror.ErrInvalidPublicKey, "RFC 8037 3.1"},
		"an EC key whose alg is EdDSA":         {jwa.Ed25519, ecNamedEdDSA, joseerror.ErrInvalidPublicKey, "RFC 8037 3.1"},
		"an Ed25519 key for EdDSA named ES256": {jwa.EdDSA, with("alg", "ES256"), joseerror.ErrInvalidPublicKey, "RFC 8725 3.1"},
		"an Ed25519 key for ES256":             {jwa.ES256, rfc8037PublicJwk(), joseerror.ErrInvalidPublicKey, "RFC 7518 3.4"},
		"an Ed25519 key for ES256 named EdDSA": {jwa.ES256, with("alg", "EdDSA"), joseerror.ErrInvalidPublicKey, "RFC 8725 3.1"},
		"an Ed25519 key for RS256":             {jwa.RS256, rfc8037PublicJwk(), joseerror.ErrInvalidPublicKey, "RFC 7518 3.3"},
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

	for _, alg := range []jwa.Algorithm{jwa.EdDSA, jwa.Ed25519} {
		for _, member := range []any{nil, "EdDSA", "Ed25519"} {
			key := rfc8037PublicJwk()
			if member != nil {
				key["alg"] = member
			}
			if _, err := jws.GetValidatorFromJwk(alg, key); err != nil {
				t.Errorf("[RFC 9864 4.1.1] EdDSA with this library's one curve and Ed25519 name the same algorithm, so an Ed25519 key whose alg is %v must build a %s validator, got %v", member, alg, err)
			}
		}
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
		"an rsa key for EdDSA":     {jwa.EdDSA, &rsaKey.PublicKey},
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

func TestVerify_AJkuMemberNamingEitherEdDSAIdentifierVerifiesATokenNamingTheOther(t *testing.T) {
	key := newEd25519Key(t)
	publicJwk, err := jwk.PublicJwk(key.Public())
	if err != nil {
		t.Fatal(err)
	}

	tests := map[string]struct {
		memberAlg, tokenAlg string
		verifies            bool
	}{
		"a member for EdDSA and an Ed25519 token": {"EdDSA", "Ed25519", true},
		"a member for Ed25519 and an EdDSA token": {"Ed25519", "EdDSA", true},
		"a member for EdDSA and an EdDSA token":   {"EdDSA", "EdDSA", true},
		"a member for ES256 and an Ed25519 token": {"ES256", "Ed25519", false},
		"a member for ES256 and an EdDSA token":   {"ES256", "EdDSA", false},
	}
	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			member := maps.Clone(*publicJwk)
			member["alg"] = tc.memberAlg
			document, err := json.Marshal(map[string]any{"keys": []map[string]any{member}})
			if err != nil {
				t.Fatal(err)
			}
			server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				_, _ = w.Write(document)
			}))
			defer server.Close()

			head, err := json.Marshal(map[string]any{"alg": tc.tokenAlg, "jku": server.URL})
			if err != nil {
				t.Fatal(err)
			}
			input := base64.RawURLEncoding.EncodeToString(head) + "." + base64.RawURLEncoding.EncodeToString([]byte(`{"sub":"test"}`))
			token := input + "." + base64.RawURLEncoding.EncodeToString(ed25519.Sign(key, []byte(input)))

			_, _, err = jws.Verify(context.Background(), token, nil, &model.JoseOptions{UseTokenProvidedKeys: true, HttpClient: server.Client()})
			if tc.verifies && err != nil {
				t.Errorf("[RFC 9864 4.1.1] EdDSA with an Ed25519 key and Ed25519 name one algorithm, so a member for %s must verify a %s token, got %v", tc.memberAlg, tc.tokenAlg, err)
			}
			if !tc.verifies && err == nil {
				t.Errorf("[RFC 8725 3.1] a member for %s must not verify a %s token", tc.memberAlg, tc.tokenAlg)
			}
		})
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
