package jws_test

import (
	"context"
	"crypto"
	"crypto/ed25519"
	"crypto/mldsa"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"maps"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/MichaelFraser99/go-jose/internal/testvectors"
	"github.com/MichaelFraser99/go-jose/joseerror"
	"github.com/MichaelFraser99/go-jose/jwa"
	"github.com/MichaelFraser99/go-jose/jwk"
	"github.com/MichaelFraser99/go-jose/jws"
	"github.com/MichaelFraser99/go-jose/model"
)

type mldsaExample struct {
	testvectors.MLDSAExample
	alg       jwa.Algorithm
	public    crypto.PublicKey
	private   crypto.PrivateKey
	publicJwk map[string]any
}

func rfc9964Examples(t *testing.T) []mldsaExample {
	t.Helper()
	raw, err := testvectors.RFC9964()
	if err != nil {
		t.Fatal(err)
	}
	var examples []mldsaExample
	for _, r := range raw {
		private, err := jwk.PrivateFromJwk(r.PrivateJwk)
		if err != nil {
			t.Fatal(err)
		}
		publicJwk := maps.Clone(r.PrivateJwk)
		delete(publicJwk, "priv")
		public, err := jwk.PublicFromJwk(publicJwk)
		if err != nil {
			t.Fatal(err)
		}
		examples = append(examples, mldsaExample{MLDSAExample: r, alg: jwa.GetAlgorithm(r.Alg), public: public, private: private, publicJwk: publicJwk})
	}
	return examples
}

func TestVerify_EachRFC9964ExampleJWS(t *testing.T) {
	for _, ex := range rfc9964Examples(t) {
		t.Run(ex.Alg, func(t *testing.T) {
			head, payload, err := jws.Verify(context.Background(), ex.JWS, retrieving(ex.public), nil)
			if err != nil {
				t.Fatalf("[RFC 9964 A.1] the example JWS must verify under the example key, got %v", err)
			}
			if head["alg"] != ex.Alg || head["kid"] != ex.PrivateJwk["kid"] || string(payload) != "It’s a dangerous business, Frodo, going out your door." {
				t.Errorf("[RFC 9964 A.1] the example's header and payload must come back as signed, got %v and %q", head, payload)
			}

			validator, err := jws.GetValidatorFromJwk(ex.alg, ex.publicJwk)
			if err != nil {
				t.Fatal(err)
			}
			if valid, err := validator.ValidateSignature(ex.SigningInput, ex.Signature); !valid || err != nil {
				t.Errorf("[RFC 9964 A.1] a validator from the example jwk must accept the example signature, got %v and %v", valid, err)
			}

			segments := strings.Split(ex.JWS, ".")
			tampered := segments[0] + "." + segments[1] + "." + "AAAA" + segments[2][4:]
			if _, _, err := jws.Verify(context.Background(), tampered, retrieving(ex.public), nil); err == nil {
				t.Error("[RFC 7515 5.2 step 8] an altered ML-DSA signature must not verify")
			}
		})
	}
}

func TestVerify_AnRFC9964ExampleUnderTheKeyOfAnotherParameterSet(t *testing.T) {
	examples := rfc9964Examples(t)
	for i, ex := range examples {
		other := examples[(i+1)%len(examples)]
		t.Run(ex.Alg+" under "+other.Alg, func(t *testing.T) {
			if _, _, err := jws.Verify(context.Background(), ex.JWS, retrieving(other.public), nil); err == nil {
				t.Errorf("[RFC 9964 5] the alg fixes the parameter set, so an %s token must not verify under an %s key", ex.Alg, other.Alg)
			}
			if validator, err := jws.GetValidator(ex.alg, other.public); !errors.Is(err, joseerror.ErrInvalidPublicKey) || validator != nil {
				t.Errorf("[RFC 9964 5] GetValidator(%s) must refuse an %s key with ErrInvalidPublicKey, got %#v and %v", ex.Alg, other.Alg, validator, err)
			}
			if validator, err := jws.GetValidatorFromJwk(ex.alg, other.publicJwk); !errors.Is(err, joseerror.ErrInvalidPublicKey) || validator != nil {
				t.Errorf("[RFC 8725 3.1] GetValidatorFromJwk(%s) must refuse a jwk whose alg is %s, got %#v and %v", ex.Alg, other.Alg, validator, err)
			}
		})
	}
}

func TestGetSigner_EachMLDSAParameterSetSignsATokenItsValidatorAccepts(t *testing.T) {
	for _, ex := range rfc9964Examples(t) {
		t.Run(ex.Alg, func(t *testing.T) {
			for name, build := range map[string]func() (model.Signer, error){
				"GetSigner":                              func() (model.Signer, error) { return jws.GetSigner(ex.alg, nil) },
				"GetSignerFromPrivateKey of the example": func() (model.Signer, error) { return jws.GetSignerFromPrivateKey(ex.alg, ex.private) },
			} {
				signer, err := build()
				if err != nil {
					t.Fatalf("%s: %v", name, err)
				}
				if signer.Alg() != ex.alg {
					t.Errorf("[RFC 7515 4.1.1] %s must report %s, got %s", name, ex.alg, signer.Alg())
				}
				head := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"` + ex.Alg + `"}`))
				input := head + "." + base64.RawURLEncoding.EncodeToString([]byte(`{"sub":"test"}`))
				signature, err := signer.Sign(rand.Reader, []byte(input), nil)
				if err != nil {
					t.Fatal(err)
				}
				token := input + "." + base64.RawURLEncoding.EncodeToString(signature)
				if _, _, err := jws.VerifyCompactSerialization(context.Background(), token, retrieving(signer.Public()), nil); err != nil {
					t.Errorf("[RFC 7515 5.2] %s: a token signed with %s must verify under the signer's public key, got %v", name, ex.alg, err)
				}
			}
		})
	}
}

func TestGetValidatorFromJwk_BindsAnAKPKeyToItsAlg(t *testing.T) {
	ex := rfc9964Examples(t)[0]
	edPublic, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	edJwk, err := jwk.PublicJwk(edPublic)
	if err != nil {
		t.Fatal(err)
	}
	noAlg := maps.Clone(ex.publicJwk)
	delete(noAlg, "alg")

	tests := map[string]struct {
		alg  jwa.Algorithm
		jwk  map[string]any
		want error
	}{
		"an AKP jwk with no alg":       {jwa.MLDSA44, noAlg, joseerror.ErrInvalidPublicKey},
		"an ML-DSA-44 jwk for ES256":   {jwa.ES256, ex.publicJwk, joseerror.ErrInvalidPublicKey},
		"an ML-DSA-44 jwk for Ed25519": {jwa.Ed25519, ex.publicJwk, joseerror.ErrInvalidPublicKey},
		"an Ed25519 jwk for ML-DSA-44": {jwa.MLDSA44, *edJwk, joseerror.ErrInvalidPublicKey},
	}
	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			validator, err := jws.GetValidatorFromJwk(tc.alg, tc.jwk)
			if !errors.Is(err, tc.want) || validator != nil {
				t.Errorf("[RFC 9964 3] want %v and no validator, got %#v and %v", tc.want, validator, err)
			}
		})
	}
}

func TestVerify_AJkuSetOfAKPKeysVerifiesWithTheMemberForTheTokensAlg(t *testing.T) {
	examples := rfc9964Examples(t)
	members := []map[string]any{
		{"kty": "AKP", "alg": "SLH-DSA-SHA2-128s", "pub": "AQAB", "kid": "unsupported"},
	}
	for _, ex := range examples {
		members = append(members, ex.publicJwk)
	}
	document, err := json.Marshal(map[string]any{"keys": members})
	if err != nil {
		t.Fatal(err)
	}
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(document)
	}))
	defer server.Close()

	for _, ex := range examples {
		t.Run(ex.Alg, func(t *testing.T) {
			token := signWithHeader(t, ex.alg, ex.private, map[string]any{"jku": server.URL, "kid": ex.PrivateJwk["kid"]})
			if _, _, err := jws.Verify(context.Background(), token, nil, &model.JoseOptions{UseTokenProvidedKeys: true, HttpClient: server.Client()}); err != nil {
				t.Errorf("[RFC 7515 4.1.2] the set's %s member must verify the token, beside members it cannot read, got %v", ex.Alg, err)
			}
		})
	}
}

func TestVerify_AnMLDSAKeyTheTokenCarriesIsUsedOnlyWhenOptedIn(t *testing.T) {
	ex := rfc9964Examples(t)[1]
	token := signWithHeader(t, ex.alg, ex.private, map[string]any{"jwk": ex.publicJwk})
	if _, _, err := jws.Verify(context.Background(), token, nil, &model.JoseOptions{UseTokenProvidedKeys: true}); err != nil {
		t.Errorf("[RFC 7515 4.1.3] an opted-in caller must have the token's own AKP jwk verify it, got %v", err)
	}
	if _, _, err := jws.Verify(context.Background(), token, nil, nil); err == nil {
		t.Error("[RFC 7515 10.3] the token's own key authenticates nothing, so it must not verify unless the caller opts in")
	}
}

func TestVerify_AnMLDSAKeyInAnX5cChainToATrustedRoot(t *testing.T) {
	rootKey, err := mldsa.GenerateKey(mldsa.MLDSA65())
	if err != nil {
		t.Fatal(err)
	}
	leafKey, err := mldsa.GenerateKey(mldsa.MLDSA44())
	if err != nil {
		t.Fatal(err)
	}
	root := rootCA(t, rootKey)
	token := signWithX5c(t, jwa.MLDSA44, leafKey, []string{der64(leaf(t, leafKey, root))})

	if _, _, err := jws.Verify(context.Background(), token, nil, &model.JoseOptions{X509Roots: roots(root)}); err != nil {
		t.Errorf("[RFC 7515 4.1.6] an ML-DSA certificate that chains to a configured root must verify the token, got %v", err)
	}
	if _, _, err := jws.Verify(context.Background(), token, nil, &model.JoseOptions{X509Roots: roots(rootCA(t, p256Key(t)))}); err == nil {
		t.Error("[RFC 7515 4.1.6] an ML-DSA certificate that chains to no configured root must not verify the token")
	}
}
