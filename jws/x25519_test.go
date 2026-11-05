package jws_test

import (
	"context"
	"crypto"
	"crypto/ecdh"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"maps"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/MichaelFraser99/go-jose/joseerror"
	"github.com/MichaelFraser99/go-jose/jwa"
	"github.com/MichaelFraser99/go-jose/jws"
	"github.com/MichaelFraser99/go-jose/model"
)

var signatureAlgorithms = []jwa.Algorithm{
	jwa.ES256, jwa.ES384, jwa.ES512,
	jwa.RS256, jwa.RS384, jwa.RS512,
	jwa.PS256, jwa.PS384, jwa.PS512,
	jwa.HS256, jwa.HS384, jwa.HS512,
	jwa.EdDSA, jwa.Ed25519,
	jwa.MLDSA44, jwa.MLDSA65, jwa.MLDSA87,
}

func rfc8037A6RecipientJwk() map[string]any {
	return map[string]any{"kty": "OKP", "crv": "X25519", "kid": "Bob", "x": "3p7bfXt9wbTTW2HC7OQ1Nz-DQ8hbeGdNrfx-FG-IK08"}
}

func ecdhKeys(t *testing.T) map[string]*ecdh.PrivateKey {
	t.Helper()
	keys := map[string]*ecdh.PrivateKey{}
	for name, curve := range map[string]ecdh.Curve{"X25519": ecdh.X25519(), "P-256": ecdh.P256()} {
		key, err := curve.GenerateKey(rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		keys[name] = key
	}
	return keys
}

func TestGetValidatorFromJwk_RefusesAnX25519KeyForEveryAlgorithm(t *testing.T) {
	for _, alg := range signatureAlgorithms {
		t.Run(alg.String(), func(t *testing.T) {
			want := joseerror.ErrInvalidPublicKey
			if alg == jwa.HS256 || alg == jwa.HS384 || alg == jwa.HS512 {
				want = joseerror.ErrUnsupportedAlgorithm
			}
			validator, err := jws.GetValidatorFromJwk(alg, rfc8037A6RecipientJwk())
			if !errors.Is(err, want) {
				t.Errorf("[RFC 8037 3.2] an X25519 key MUST NOT be used for signing, so a %s validator must be refused with %v, got %v", alg, want, err)
			}
			if validator != nil {
				t.Errorf("[RFC 8037 3.2] a refused construction must return a nil Validator, got %#v", validator)
			}
		})
	}
}

func TestGetValidator_RefusesAnECDHKeyForEveryAlgorithm(t *testing.T) {
	for curve, key := range ecdhKeys(t) {
		for _, alg := range signatureAlgorithms {
			t.Run(curve+" "+alg.String(), func(t *testing.T) {
				validator, err := jws.GetValidator(alg, key.PublicKey())
				if !errors.Is(err, joseerror.ErrInvalidPublicKey) {
					t.Errorf("[RFC 8037 3.2] an *ecdh.PublicKey is a key agreement key, so a %s validator must be refused with ErrInvalidPublicKey, got %v", alg, err)
				}
				if validator != nil {
					t.Errorf("[RFC 8037 3.2] a refused construction must return a nil Validator, got %#v", validator)
				}
			})
		}
	}
}

func TestGetSignerFromPrivateKey_RefusesAnECDHKeyForEveryAlgorithm(t *testing.T) {
	for curve, key := range ecdhKeys(t) {
		for _, alg := range signatureAlgorithms {
			t.Run(curve+" "+alg.String(), func(t *testing.T) {
				signer, err := jws.GetSignerFromPrivateKey(alg, key)
				if !errors.Is(err, joseerror.ErrInvalidPrivateKey) && !errors.Is(err, joseerror.ErrUnsupportedAlgorithm) {
					t.Errorf("[RFC 8037 3.2] an *ecdh.PrivateKey MUST NOT be used for signing, so a %s signer must be refused, got %v", alg, err)
				}
				if signer != nil {
					t.Errorf("[RFC 8037 3.2] a refused construction must return a nil Signer, got %#v", signer)
				}
			})
		}
	}
}

func ed25519TokenCarrying(t *testing.T, key ed25519.PrivateKey, alg string, header map[string]any) string {
	t.Helper()
	header["alg"] = alg
	head, err := json.Marshal(header)
	if err != nil {
		t.Fatal(err)
	}
	input := base64.RawURLEncoding.EncodeToString(head) + "." + base64.RawURLEncoding.EncodeToString([]byte(`{"sub":"test"}`))
	return input + "." + base64.RawURLEncoding.EncodeToString(ed25519.Sign(key, []byte(input)))
}

func TestVerify_AnX25519KeyTheTokenCarriesNeverVerifiesIt(t *testing.T) {
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	sameOctets := map[string]any{"kty": "OKP", "kid": "k", "x": base64.RawURLEncoding.EncodeToString(public)}

	for _, crv := range []string{"X25519", "Ed25519"} {
		member := maps.Clone(sameOctets)
		member["crv"] = crv
		document, err := json.Marshal(map[string]any{"keys": []map[string]any{member}})
		if err != nil {
			t.Fatal(err)
		}
		server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			if _, err := w.Write(document); err != nil {
				return
			}
		}))
		t.Cleanup(server.Close)
		opts := &model.JoseOptions{UseTokenProvidedKeys: true, HttpClient: server.Client()}

		for _, alg := range []string{"Ed25519", "EdDSA"} {
			sources := map[string]map[string]any{
				"an inline jwk":  {"jwk": member},
				"a jku key set":  {"jku": server.URL, "kid": "k"},
				"both, together": {"jwk": member, "jku": server.URL, "kid": "k"},
			}
			for source, header := range sources {
				t.Run(crv+" "+alg+" "+source, func(t *testing.T) {
					token := ed25519TokenCarrying(t, private, alg, header)
					_, _, err := jws.Verify(context.Background(), token, nil, opts)
					if crv == "Ed25519" {
						if err != nil {
							t.Errorf("[RFC 7515 4.1.3] the fixture must verify when the same octets are named Ed25519, got %v", err)
						}
						return
					}
					if err == nil {
						t.Errorf("[RFC 8037 3.2] an X25519 key MUST NOT be used for signing, so a token must not verify under one even when its x is the signer's Ed25519 public key")
					}
				})
			}
		}
	}
}

func TestVerify_AnOutOfBandX25519KeyNeverVerifies(t *testing.T) {
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	asX25519, err := ecdh.X25519().NewPublicKey(public)
	if err != nil {
		t.Fatal(err)
	}
	token := ed25519TokenCarrying(t, private, "Ed25519", map[string]any{})
	retriever := func() ([]crypto.PublicKey, error) { return []crypto.PublicKey{asX25519}, nil }
	if _, _, err := jws.Verify(context.Background(), token, retriever, nil); !errors.Is(err, joseerror.ErrInvalidSignature) {
		t.Errorf("[RFC 8037 3.2] an X25519 key MUST NOT be used for signing, so it must be skipped and the token refused with ErrInvalidSignature, got %v", err)
	}
}
