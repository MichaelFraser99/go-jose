package jwt

import (
	"context"
	"crypto"
	"crypto/ecdh"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"maps"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/MichaelFraser99/go-jose/internal/jose/header"
	"github.com/MichaelFraser99/go-jose/joseerror"
	"github.com/MichaelFraser99/go-jose/jwa"
	"github.com/MichaelFraser99/go-jose/jwe"
	"github.com/MichaelFraser99/go-jose/jwk"
	"github.com/MichaelFraser99/go-jose/jws"
	"github.com/MichaelFraser99/go-jose/model"
)

var nestedRSAKey = sync.OnceValues(func() (*rsa.PrivateKey, error) {
	return rsa.GenerateKey(rand.Reader, 2048)
})

type recipient struct {
	encrypter model.Encrypter
	decrypter model.Decrypter
}

func randomSecret(t *testing.T) []byte {
	t.Helper()
	secret := make([]byte, 16)
	if _, err := rand.Read(secret); err != nil {
		t.Fatal(err)
	}
	return secret
}

var recipientKeys = map[jwa.Algorithm]func(t *testing.T) (public, private any){
	jwa.RSAOAEP256: func(t *testing.T) (any, any) {
		key, err := nestedRSAKey()
		if err != nil {
			t.Fatal(err)
		}
		return &key.PublicKey, key
	},
	jwa.RSAOAEP:      rsaKeys,
	jwa.RSAOAEP384:   rsaKeys,
	jwa.RSAOAEP512:   rsaKeys,
	jwa.ECDHES:       x25519Keys,
	jwa.ECDHESA128KW: x25519Keys,
	jwa.ECDHESA192KW: x25519Keys,
	jwa.ECDHESA256KW: x25519Keys,
	jwa.A128KW:       sharedSecretOf(16),
	jwa.A192KW:       sharedSecretOf(24),
	jwa.A256KW:       sharedSecretOf(32),
	jwa.A128GCMKW:    sharedSecretOf(16),
	jwa.A192GCMKW:    sharedSecretOf(24),
	jwa.A256GCMKW:    sharedSecretOf(32),
	jwa.Dir: func(t *testing.T) (any, any) {
		key := jwe.DirectKey{Key: randomSecret(t), Enc: jwa.A128GCM}
		return key, key
	},
	jwa.PBES2HS256A128KW: passwordKeys,
	jwa.PBES2HS384A192KW: passwordKeys,
	jwa.PBES2HS512A256KW: passwordKeys,
}

func rsaKeys(t *testing.T) (any, any) {
	key, err := nestedRSAKey()
	if err != nil {
		t.Fatal(err)
	}
	return &key.PublicKey, key
}

func x25519Keys(t *testing.T) (any, any) {
	key, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return key.PublicKey(), key
}

func sharedSecretOf(size int) func(*testing.T) (any, any) {
	return func(t *testing.T) (any, any) {
		secret := make([]byte, size)
		if _, err := rand.Read(secret); err != nil {
			t.Fatal(err)
		}
		return secret, secret
	}
}

func passwordKeys(*testing.T) (any, any) {
	key := jwe.PasswordKey{Password: []byte("correct horse battery staple"), Count: 1000}
	return key, key
}

func recipientFor(t *testing.T, alg jwa.Algorithm) recipient {
	t.Helper()
	keys, ok := recipientKeys[alg]
	if !ok {
		t.Fatalf("no recipient for %s", alg)
	}
	public, private := keys(t)
	encrypter, err := jwe.GetEncrypter(alg, public)
	if err != nil {
		t.Fatal(err)
	}
	decrypter, err := jwe.GetDecrypter(alg, private)
	if err != nil {
		t.Fatal(err)
	}
	return recipient{encrypter: encrypter, decrypter: decrypter}
}

var sharedKeyAlgorithms = []jwa.Algorithm{jwa.Dir, jwa.A128KW, jwa.A192KW, jwa.A256KW, jwa.A128GCMKW, jwa.A192GCMKW, jwa.A256GCMKW, jwa.PBES2HS256A128KW, jwa.PBES2HS384A192KW, jwa.PBES2HS512A256KW}

var publicKeyAlgorithms = []jwa.Algorithm{jwa.RSAOAEP, jwa.RSAOAEP256, jwa.RSAOAEP384, jwa.RSAOAEP512, jwa.ECDHES, jwa.ECDHESA128KW, jwa.ECDHESA192KW, jwa.ECDHESA256KW}

func signedJWT(t *testing.T, claims map[string]any) (string, model.Retriever) {
	t.Helper()
	signer, err := jws.GetSigner(jwa.ES256, nil)
	if err != nil {
		t.Fatal(err)
	}
	token, err := New(signer, map[string]any{"typ": "JWT"}, claims, Opts{})
	if err != nil {
		t.Fatal(err)
	}
	return *token, newTestRetriever(signer.Public())
}

func encryptOnly(t *testing.T, r recipient, claims any) string {
	t.Helper()
	plaintext, err := json.Marshal(claims)
	if err != nil {
		t.Fatal(err)
	}
	token, err := jwe.Encrypt(r.encrypter, jwa.A128GCM, plaintext, nil)
	if err != nil {
		t.Fatal(err)
	}
	return token
}

func TestValidate_ANestedJWTUnderEveryKindOfKey(t *testing.T) {
	for _, alg := range append(sharedKeyAlgorithms, publicKeyAlgorithms...) {
		t.Run(alg.String(), func(t *testing.T) {
			r := recipientFor(t, alg)
			signed, retriever := signedJWT(t, map[string]any{"sub": "alice"})
			token, err := Encrypt(r.encrypter, jwa.A128GCM, signed, map[string]any{"kid": "recipient"})
			if err != nil {
				t.Fatal(err)
			}
			validated, err := Validate(context.Background(), token, retriever, []model.Decrypter{r.decrypter}, nil, nil)
			if err != nil {
				t.Fatalf("[RFC 7519 7.2 step 8] a Nested JWT must decrypt and verify, got %v", err)
			}
			if validated.Claims["sub"] != "alice" || validated.SignatureHeader["alg"] != "ES256" || validated.SignatureHeader["typ"] != "JWT" {
				t.Errorf("[RFC 7519 7.2] want the inner JWS's claims and header, got %+v", validated)
			}
			if validated.EncryptionHeader["cty"] != "JWT" || validated.EncryptionHeader["kid"] != "recipient" || validated.EncryptionHeader["alg"] != alg.String() || validated.Decrypter != r.decrypter {
				t.Errorf("[RFC 7519 5.2] want the JWE header, naming cty JWT, and the decrypter used, got %+v", validated)
			}
		})
	}
}

func TestValidate_ASignedJWTIsUnchangedByDecrypters(t *testing.T) {
	signed, retriever := signedJWT(t, map[string]any{"sub": "alice"})
	r := recipientFor(t, jwa.A128KW)
	for name, decrypters := range map[string][]model.Decrypter{"none": nil, "some": {r.decrypter}} {
		t.Run(name, func(t *testing.T) {
			validated, err := Validate(context.Background(), signed, retriever, decrypters, nil, &model.JWEOptions{AllowedKeyManagementAlgorithms: []jwa.Algorithm{jwa.Dir}})
			if err != nil || validated.Claims["sub"] != "alice" || validated.SignatureHeader == nil || validated.EncryptionHeader != nil || validated.Decrypter != nil {
				t.Errorf("[RFC 7519 7.2] a JWS is verified, and the decrypters and JWE options are not read, got %+v and %v", validated, err)
			}
		})
	}
}

func TestValidate_AnEncryptOnlyJWTUnderASharedKeyIsAccepted(t *testing.T) {
	for _, alg := range sharedKeyAlgorithms {
		t.Run(alg.String(), func(t *testing.T) {
			r := recipientFor(t, alg)
			token := encryptOnly(t, r, map[string]any{"sub": "alice"})
			validated, err := Validate(context.Background(), token, nil, []model.Decrypter{r.decrypter}, nil, nil)
			if err != nil {
				t.Fatalf("[RFC 7519 7.2 step 8] only a holder of the %s key can encrypt this JWT, so it must be accepted, got %v", alg, err)
			}
			if validated.Claims["sub"] != "alice" || validated.SignatureHeader != nil || validated.EncryptionHeader == nil || validated.Decrypter != r.decrypter {
				t.Errorf("[RFC 7519 7.2 step 10] want the claims, no JWS header, the JWE header and the decrypter, got %+v", validated)
			}
		})
	}
}

func TestValidate_AnEncryptOnlyJWTUnderAPublicKeyNeedsAllowUnauthenticatedJWT(t *testing.T) {
	for _, alg := range publicKeyAlgorithms {
		t.Run(alg.String(), func(t *testing.T) {
			r := recipientFor(t, alg)
			token := encryptOnly(t, r, map[string]any{"sub": "admin"})
			_, retriever := signedJWT(t, nil)
			for name, c := range map[string]struct {
				opts    *model.JoseOptions
				jweOpts *model.JWEOptions
			}{
				"no options":                       {},
				"RequireSignedJWT over the flag":   {opts: &model.JoseOptions{RequireSignedJWT: true}, jweOpts: &model.JWEOptions{AllowUnauthenticatedJWT: true}},
				"the JWE options without the flag": {jweOpts: &model.JWEOptions{AllowedKeyManagementAlgorithms: []jwa.Algorithm{alg}}},
			} {
				if validated, err := Validate(context.Background(), token, retriever, []model.Decrypter{r.decrypter}, c.opts, c.jweOpts); !errors.Is(err, joseerror.ErrInvalidSignature) || validated != nil {
					t.Errorf("[RFC 8725 2.1] with %s, anyone holding the recipient's public key could have written this JWT, so it must be refused with ErrInvalidSignature, got %v", name, err)
				}
			}
			validated, err := Validate(context.Background(), token, retriever, []model.Decrypter{r.decrypter}, nil, &model.JWEOptions{AllowUnauthenticatedJWT: true})
			if err != nil || validated.Claims["sub"] != "admin" || validated.SignatureHeader != nil {
				t.Errorf("[RFC 7519 7.2 step 10] with AllowUnauthenticatedJWT in the JWE options, the encrypt-only JWT must be accepted, got %+v and %v", validated, err)
			}
		})
	}
}

func TestValidate_TheClaimRulesApplyToEveryShape(t *testing.T) {
	past := float64(time.Now().Add(-time.Hour).Unix())
	shared := recipientFor(t, jwa.A128KW)
	for name, claims := range map[string]map[string]any{
		"an expired token":        {"exp": past},
		"another audience":        {"aud": "someone-else"},
		"an iss that is a number": {"iss": 1},
	} {
		want := map[string]error{"an expired token": joseerror.ErrExpired, "another audience": joseerror.ErrAudienceMismatch, "an iss that is a number": joseerror.ErrMalformedClaim}[name]
		opts := &model.JoseOptions{ExpectedAudience: []string{"me"}}
		if name != "another audience" {
			claims = maps.Clone(claims)
			claims["aud"] = "me"
		}
		t.Run(name, func(t *testing.T) {
			signed, retriever := signedJWT(t, claims)
			nested, err := Encrypt(shared.encrypter, jwa.A128GCM, signed, nil)
			if err != nil {
				t.Fatal(err)
			}
			for shape, token := range map[string]string{"signed": signed, "nested": nested, "encrypt-only": encryptOnly(t, shared, claims)} {
				if validated, err := Validate(context.Background(), token, retriever, []model.Decrypter{shared.decrypter}, opts, nil); !errors.Is(err, want) || validated != nil {
					t.Errorf("[RFC 7519 4.1] a %s token with %s must be refused with %v, got %v", shape, name, want, err)
				}
			}
		})
	}
}

func TestValidate_EachLayerHasItsOwnOptions(t *testing.T) {
	shared := recipientFor(t, jwa.A128KW)
	signed, retriever := signedJWT(t, map[string]any{"sub": "alice"})
	token, err := Encrypt(shared.encrypter, jwa.A128GCM, signed, nil)
	if err != nil {
		t.Fatal(err)
	}
	decrypters := []model.Decrypter{shared.decrypter}
	if _, err := Validate(context.Background(), token, retriever, decrypters, &model.JoseOptions{AcceptedTypes: []string{"JWT"}, RequireKeyIdentifier: false}, nil); err != nil {
		t.Errorf("[RFC 7519 5.1] AcceptedTypes in the JWS options applies to the inner JWS, whose typ is JWT, not to the JWE, which has none, got %v", err)
	}
	if _, err := Validate(context.Background(), token, retriever, decrypters, nil, &model.JWEOptions{AcceptedTypes: []string{"JWT"}}); !errors.Is(err, joseerror.ErrMissingClaim) {
		t.Errorf("[RFC 7519 5.1] AcceptedTypes in the JWE options applies to the JWE, which has no typ, got %v", err)
	}
	if _, err := Validate(context.Background(), token, retriever, decrypters, nil, &model.JWEOptions{AllowedKeyManagementAlgorithms: []jwa.Algorithm{jwa.A256KW}}); !errors.Is(err, joseerror.ErrUnsupportedAlgorithm) {
		t.Errorf("[RFC 8725 3.1] the JWE options' allow-list applies to the JWE's alg, got %v", err)
	}
	if _, err := Validate(context.Background(), token, retriever, decrypters, &model.JoseOptions{AllowedSigningAlgorithms: []jwa.Algorithm{jwa.RS256}}, nil); !errors.Is(err, joseerror.ErrUnsupportedAlgorithm) {
		t.Errorf("[RFC 8725 3.1] the JWS options' allow-list applies to the inner JWS's alg, got %v", err)
	}
	if _, err := Validate(context.Background(), token, retriever, decrypters, &model.JoseOptions{ExpectedAudience: []string{""}}, nil); !errors.Is(err, joseerror.ErrInvalidOptions) {
		t.Errorf("options that are wrong whatever the token must be refused with ErrInvalidOptions, got %v", err)
	}
}

func TestValidate_RefusesANestedJWTThatIsNotAValidJWS(t *testing.T) {
	shared := recipientFor(t, jwa.A128KW)
	signed, retriever := signedJWT(t, map[string]any{"sub": "alice"})
	_, otherRetriever := signedJWT(t, nil)
	parts := strings.Split(signed, ".")
	signature, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil {
		t.Fatal(err)
	}
	signature[0] ^= 1
	tampered := parts[0] + "." + parts[1] + "." + base64.RawURLEncoding.EncodeToString(signature)
	innerJWE, err := Encrypt(shared.encrypter, jwa.A128GCM, signed, nil)
	if err != nil {
		t.Fatal(err)
	}
	for _, c := range []struct {
		name      string
		plaintext string
		cty       string
		retriever model.Retriever
		want      error
		clause    string
	}{
		{name: "a signature that does not verify", plaintext: tampered, cty: "JWT", retriever: retriever, want: joseerror.ErrInvalidSignature, clause: "RFC 7515 5.2"},
		{name: "a JWS signed by another key", plaintext: signed, cty: "JWT", retriever: otherRetriever, want: joseerror.ErrInvalidSignature, clause: "RFC 7515 5.2"},
		{name: "a claims set where a Nested JWT is named", plaintext: `{"sub":"alice"}`, cty: "JWT", retriever: retriever, want: joseerror.ErrMalformedToken, clause: "RFC 7519 7.2 step 8"},
		{name: "a JWE nested in the JWE", plaintext: innerJWE, cty: "JWT", retriever: retriever, want: joseerror.ErrUnsupportedAlgorithm, clause: "RFC 7519 7.2 step 8"},
		{name: "four segments under a cty of JWT", plaintext: "a.b.c.d", cty: "JWT", retriever: retriever, want: joseerror.ErrMalformedToken, clause: "RFC 7519 7.2 step 8"},
		{name: "a JWS with no cty naming it", plaintext: signed, retriever: retriever, want: joseerror.ErrMalformedToken, clause: "RFC 7519 5.2"},
	} {
		t.Run(c.name, func(t *testing.T) {
			head := map[string]any{}
			if c.cty != "" {
				head["cty"] = c.cty
			}
			token, err := jwe.Encrypt(shared.encrypter, jwa.A128GCM, []byte(c.plaintext), head)
			if err != nil {
				t.Fatal(err)
			}
			if validated, err := Validate(context.Background(), token, c.retriever, []model.Decrypter{shared.decrypter}, nil, nil); !errors.Is(err, c.want) || validated != nil {
				t.Errorf("[%s] want %v, got %v", c.clause, c.want, err)
			}
		})
	}
}

func TestValidate_ACtyNamesANestedJWTAsAMediaType(t *testing.T) {
	shared := recipientFor(t, jwa.A128KW)
	signed, retriever := signedJWT(t, map[string]any{"sub": "alice"})
	for _, cty := range []string{"JWT", "jwt", "application/jwt", "application/JWT"} {
		token, err := jwe.Encrypt(shared.encrypter, jwa.A128GCM, []byte(signed), map[string]any{"cty": cty})
		if err != nil {
			t.Fatal(err)
		}
		if validated, err := Validate(context.Background(), token, retriever, []model.Decrypter{shared.decrypter}, nil, nil); err != nil || validated.SignatureHeader == nil {
			t.Errorf("[RFC 7515 4.1.10] a cty of %q names the JWT media type, so the plaintext is a Nested JWT, got %v", cty, err)
		}
	}
}

func TestValidate_AnEncryptOnlyPlaintextMustBeAJSONObject(t *testing.T) {
	shared := recipientFor(t, jwa.Dir)
	for name, plaintext := range map[string]string{"an array": `["sub"]`, "null": `null`, "a string": `"alice"`, "not JSON": `sub=alice`, "empty": ``} {
		t.Run(name, func(t *testing.T) {
			token, err := jwe.Encrypt(shared.encrypter, jwa.A128GCM, []byte(plaintext), nil)
			if err != nil {
				t.Fatal(err)
			}
			if validated, err := Validate(context.Background(), token, nil, []model.Decrypter{shared.decrypter}, nil, nil); !errors.Is(err, joseerror.ErrMalformedToken) || validated != nil {
				t.Errorf("[RFC 7519 7.2 step 10] the claims set must be a JSON object, got %v", err)
			}
		})
	}
}

func TestValidate_AJWEThatDoesNotDecryptIsTheUniformFailure(t *testing.T) {
	signed, retriever := signedJWT(t, map[string]any{"sub": "alice"})
	token, err := Encrypt(recipientFor(t, jwa.A128KW).encrypter, jwa.A128GCM, signed, nil)
	if err != nil {
		t.Fatal(err)
	}
	if validated, err := Validate(context.Background(), token, retriever, []model.Decrypter{recipientFor(t, jwa.A128KW).decrypter}, nil, nil); !errors.Is(err, joseerror.ErrDecryptionFailed) || validated != nil {
		t.Errorf("[RFC 7516 11.5] a JWE under another key must be ErrDecryptionFailed, got %v", err)
	}
}

func TestEncrypt_RefusesWhatIsNotASignedJWT(t *testing.T) {
	r := recipientFor(t, jwa.A128KW)
	signed, _ := signedJWT(t, nil)
	parts := strings.Split(signed, ".")
	for _, c := range []struct {
		name   string
		token  string
		head   map[string]any
		want   error
		clause string
	}{
		{name: "two segments", token: parts[0] + "." + parts[1], want: joseerror.ErrMalformedToken, clause: "RFC 7515 7.1"},
		{name: "five segments", token: signed + ".a.b", want: joseerror.ErrMalformedToken, clause: "RFC 7515 7.1"},
		{name: "a header that is not base64url", token: "!!." + parts[1] + "." + parts[2], want: joseerror.ErrMalformedToken, clause: "RFC 7515 7.1"},
		{name: "a header that is not a JSON object", token: base64.RawURLEncoding.EncodeToString([]byte(`[1]`)) + "." + parts[1] + "." + parts[2], want: joseerror.ErrMalformedToken, clause: "RFC 7515 7.1"},
		{name: "a signature that is not base64url", token: parts[0] + "." + parts[1] + ".a=b", want: joseerror.ErrMalformedToken, clause: "RFC 7515 7.1"},
		{name: "an alg of none", token: base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"none"}`)) + "." + parts[1] + ".", want: joseerror.ErrUnsupportedAlgorithm, clause: "RFC 8725 3.1"},
		{name: "a key management alg", token: base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"RSA-OAEP"}`)) + "." + parts[1] + "." + parts[2], want: joseerror.ErrUnsupportedAlgorithm, clause: "RFC 7515 4.1.1"},
		{name: "no alg", token: base64.RawURLEncoding.EncodeToString([]byte(`{"typ":"JWT"}`)) + "." + parts[1] + "." + parts[2], want: joseerror.ErrUnsupportedAlgorithm, clause: "RFC 7515 4.1.1"},
		{name: "a cty naming another type", token: signed, head: map[string]any{"cty": "json"}, want: joseerror.ErrMalformedClaim, clause: "RFC 7519 5.2"},
		{name: "a cty that is not a string", token: signed, head: map[string]any{"cty": 1}, want: joseerror.ErrMalformedClaim, clause: "RFC 7519 5.2"},
		{name: "a zip", token: signed, head: map[string]any{"zip": "DEF"}, want: joseerror.ErrUnsupportedAlgorithm, clause: "RFC 8725bis 3.6"},
	} {
		t.Run(c.name, func(t *testing.T) {
			if token, err := Encrypt(r.encrypter, jwa.A128GCM, c.token, c.head); !errors.Is(err, c.want) || token != "" {
				t.Errorf("[%s] want %v and no token, got %v", c.clause, c.want, err)
			}
		})
	}
}

func TestEncrypt_SetsCtyAndLeavesTheHeadAlone(t *testing.T) {
	r := recipientFor(t, jwa.A128KW)
	signed, retriever := signedJWT(t, map[string]any{"sub": "alice"})
	for _, cty := range []any{nil, "JWT", "application/jwt"} {
		head := map[string]any{"kid": "k"}
		if cty != nil {
			head["cty"] = cty
		}
		before := maps.Clone(head)
		token, err := Encrypt(r.encrypter, jwa.A128GCM, signed, head)
		if err != nil {
			t.Fatalf("[RFC 7519 5.2] a cty of %v names a Nested JWT, got %v", cty, err)
		}
		if !maps.Equal(head, before) {
			t.Errorf("Encrypt must not write into the caller's head, got %v", head)
		}
		validated, err := Validate(context.Background(), token, retriever, []model.Decrypter{r.decrypter}, nil, nil)
		if err != nil || validated.EncryptionHeader["cty"] != "JWT" || validated.EncryptionHeader["kid"] != "k" {
			t.Errorf("[RFC 7519 5.2] the JWE's cty must be JWT, got %+v and %v", validated, err)
		}
	}
}

func TestValidate_RequireSignedJWTAndRequireEncryptedJWTPinTheShape(t *testing.T) {
	shared := recipientFor(t, jwa.A128KW)
	public := recipientFor(t, jwa.RSAOAEP256)
	signed, retriever := signedJWT(t, map[string]any{"sub": "alice"})
	nested, err := Encrypt(shared.encrypter, jwa.A128GCM, signed, nil)
	if err != nil {
		t.Fatal(err)
	}
	sharedOnly := encryptOnly(t, shared, map[string]any{"sub": "alice"})
	publicOnly := encryptOnly(t, public, map[string]any{"sub": "alice"})
	decrypters := []model.Decrypter{shared.decrypter, public.decrypter}
	allow := &model.JWEOptions{AllowUnauthenticatedJWT: true}
	for _, c := range []struct {
		name  string
		token string
		opts  *model.JoseOptions
		want  error
	}{
		{name: "a signed JWT, signature required", token: signed, opts: &model.JoseOptions{RequireSignedJWT: true}},
		{name: "a Nested JWT, signature required", token: nested, opts: &model.JoseOptions{RequireSignedJWT: true}},
		{name: "a shared-key encrypt-only JWT, signature required", token: sharedOnly, opts: &model.JoseOptions{RequireSignedJWT: true}, want: joseerror.ErrInvalidSignature},
		{name: "a public-key encrypt-only JWT allowed by jweOpts, signature required", token: publicOnly, opts: &model.JoseOptions{RequireSignedJWT: true}, want: joseerror.ErrInvalidSignature},
		{name: "a signed JWT, encryption required", token: signed, opts: &model.JoseOptions{RequireEncryptedJWT: true}, want: joseerror.ErrUnsupportedAlgorithm},
		{name: "a Nested JWT, encryption required", token: nested, opts: &model.JoseOptions{RequireEncryptedJWT: true}},
		{name: "a shared-key encrypt-only JWT, encryption required", token: sharedOnly, opts: &model.JoseOptions{RequireEncryptedJWT: true}},
		{name: "a Nested JWT, both required", token: nested, opts: &model.JoseOptions{RequireSignedJWT: true, RequireEncryptedJWT: true}},
		{name: "a signed JWT, both required", token: signed, opts: &model.JoseOptions{RequireSignedJWT: true, RequireEncryptedJWT: true}, want: joseerror.ErrUnsupportedAlgorithm},
		{name: "a shared-key encrypt-only JWT, both required", token: sharedOnly, opts: &model.JoseOptions{RequireSignedJWT: true, RequireEncryptedJWT: true}, want: joseerror.ErrInvalidSignature},
		{name: "a signed JWT, neither required", token: signed},
		{name: "a shared-key encrypt-only JWT, neither required", token: sharedOnly},
	} {
		t.Run(c.name, func(t *testing.T) {
			validated, err := Validate(context.Background(), c.token, retriever, decrypters, c.opts, allow)
			if c.want == nil && (err != nil || validated == nil) {
				t.Errorf("[RFC 7519 7.2] this shape meets the options, so it must be accepted, got %v", err)
			}
			if c.want != nil && (!errors.Is(err, c.want) || validated != nil) {
				t.Errorf("[RFC 7519 7.2] this shape is not the one the options require, so want %v, got %v", c.want, err)
			}
		})
	}
}

func TestValidate_AnEncryptOnlyJWTIsRefusedUnderEveryAlgThatIsNotASharedSecret(t *testing.T) {
	for _, alg := range header.KeyManagementAlgorithms {
		if slices.Contains(sharedKeyAlgorithms, alg) {
			continue
		}
		t.Run(alg.String(), func(t *testing.T) {
			r := recipientFor(t, alg)
			token := encryptOnly(t, r, map[string]any{"sub": "admin"})
			if validated, err := Validate(context.Background(), token, nil, []model.Decrypter{r.decrypter}, nil, nil); !errors.Is(err, joseerror.ErrInvalidSignature) || validated != nil {
				t.Errorf("[RFC 8725 2.1] only a shared key or password shows who encrypted a JWT, so an encrypt-only JWT under %s must be refused by default, got %v", alg, err)
			}
		})
	}
}

type countingDecrypter struct {
	model.Decrypter
	calls int
}

func (c *countingDecrypter) Decrypt(random io.Reader, msg []byte, opts crypto.DecrypterOpts) ([]byte, error) {
	c.calls++
	return c.Decrypter.Decrypt(random, msg, opts)
}

func TestValidate_RefusesAnUnauthenticatedJWTBeforeAnyDecrypterRuns(t *testing.T) {
	public := recipientFor(t, jwa.RSAOAEP256)
	shared := recipientFor(t, jwa.A128KW)
	for name, c := range map[string]struct {
		r    recipient
		opts *model.JoseOptions
	}{
		"a public-key encrypt-only JWT":                        {r: public},
		"a shared-key encrypt-only JWT under RequireSignedJWT": {r: shared, opts: &model.JoseOptions{RequireSignedJWT: true}},
	} {
		t.Run(name, func(t *testing.T) {
			counter := &countingDecrypter{Decrypter: c.r.decrypter}
			token := encryptOnly(t, c.r, map[string]any{"sub": "admin"})
			if _, err := Validate(context.Background(), token, nil, []model.Decrypter{counter}, c.opts, nil); !errors.Is(err, joseerror.ErrInvalidSignature) || counter.calls != 0 {
				t.Errorf("[RFC 7519 7.2] the refusal depends only on the protected header, so it must come before any decrypter runs; got %v after %d decryptions", err, counter.calls)
			}
		})
	}
}

func TestValidate_AcceptedTypesJudgesTheTypOfEveryShapeOfJWT(t *testing.T) {
	shared := recipientFor(t, jwa.A256KW)
	signer, err := jws.GetSigner(jwa.ES256, nil)
	if err != nil {
		t.Fatal(err)
	}
	retriever := newTestRetriever(signer.Public())
	signedAs := func(typ string) string {
		token, err := New(signer, map[string]any{"typ": typ}, map[string]any{"sub": "alice"}, Opts{})
		if err != nil {
			t.Fatal(err)
		}
		return *token
	}
	nested := func(typ string) string {
		token, err := Encrypt(shared.encrypter, jwa.A128GCM, signedAs(typ), nil)
		if err != nil {
			t.Fatal(err)
		}
		return token
	}
	encryptedAs := func(typ any) string {
		head := map[string]any{}
		if typ != nil {
			head["typ"] = typ
		}
		token, err := jwe.Encrypt(shared.encrypter, jwa.A128GCM, []byte(`{"sub":"alice"}`), head)
		if err != nil {
			t.Fatal(err)
		}
		return token
	}
	opts := &model.JoseOptions{AcceptedTypes: []string{"at+jwt"}}
	for _, c := range []struct {
		name  string
		token string
		want  error
	}{
		{name: "a signed JWT of the accepted typ", token: signedAs("at+jwt")},
		{name: "a signed JWT of another typ", token: signedAs("dpop+jwt"), want: joseerror.ErrMalformedClaim},
		{name: "a Nested JWT whose JWS has the accepted typ and whose JWE has none", token: nested("at+jwt")},
		{name: "a Nested JWT whose JWS has another typ", token: nested("dpop+jwt"), want: joseerror.ErrMalformedClaim},
		{name: "an encrypt-only JWT of the accepted typ", token: encryptedAs("application/at+jwt")},
		{name: "an encrypt-only JWT of another typ", token: encryptedAs("dpop+jwt"), want: joseerror.ErrMalformedClaim},
		{name: "an encrypt-only JWT with no typ", token: encryptedAs(nil), want: joseerror.ErrMissingClaim},
	} {
		t.Run(c.name, func(t *testing.T) {
			counter := &countingDecrypter{Decrypter: shared.decrypter}
			validated, err := Validate(context.Background(), c.token, retriever, []model.Decrypter{counter}, opts, nil)
			if c.want == nil && (err != nil || validated == nil) {
				t.Errorf("[RFC 8725 3.11] the JWT's typ is accepted, so it must validate, got %v", err)
			}
			if c.want != nil && (!errors.Is(err, c.want) || validated != nil) {
				t.Errorf("[RFC 7519 5.1, RFC 8725 3.11] the JWT's own typ is not accepted, so want %v, got %v", c.want, err)
			}
			if c.want != nil && strings.HasPrefix(c.name, "an encrypt-only") && counter.calls != 0 {
				t.Errorf("[RFC 8725 3.11] the typ is in the protected header, so it must be judged before any decrypter runs, but %d ran", counter.calls)
			}
		})
	}
}

type ctyRewriter struct {
	model.Encrypter
	rewrite func(map[string]any)
}

func (c ctyRewriter) WrapKey(random io.Reader, enc jwa.Encryption, head map[string]any) ([]byte, []byte, error) {
	cek, key, err := c.Encrypter.WrapKey(random, enc, head)
	c.rewrite(head)
	return cek, key, err
}

func TestEncrypt_RefusesAnEncrypterThatUndoesTheCtyOfANestedJWT(t *testing.T) {
	r := recipientFor(t, jwa.A128KW)
	signed, _ := signedJWT(t, nil)
	for name, rewrite := range map[string]func(map[string]any){
		"removes it":           func(h map[string]any) { delete(h, "cty") },
		"names another type":   func(h map[string]any) { h["cty"] = "json" },
		"changes it to a list": func(h map[string]any) { h["cty"] = []any{"JWT"} },
	} {
		if token, err := Encrypt(ctyRewriter{Encrypter: r.encrypter, rewrite: rewrite}, jwa.A128GCM, signed, nil); !errors.Is(err, joseerror.ErrEncryptionError) || token != "" {
			t.Errorf("[RFC 7519 5.2] an encrypter that %s leaves a Nested JWT that does not say so, so want ErrEncryptionError and no token, got %v", name, err)
		}
	}
}

func TestValidate_ADecryptOnlyRecipientBlamesTheTokenForASignatureItCannotVerify(t *testing.T) {
	r := recipientFor(t, jwa.A128KW)
	decrypters := []model.Decrypter{r.decrypter}
	peerSigned, _ := signedJWT(t, map[string]any{"sub": "admin", "iss": "https://peer.example"})
	peerNested, err := Encrypt(r.encrypter, jwa.A128GCM, peerSigned, nil)
	if err != nil {
		t.Fatal(err)
	}
	for name, c := range map[string]struct {
		token   string
		jweOpts *model.JWEOptions
	}{
		"a nested JWT signed with the peer's own key":         {token: peerNested},
		"the same with AllowUnauthenticatedJWT":               {token: peerNested, jweOpts: &model.JWEOptions{AllowUnauthenticatedJWT: true}},
		"a JWS signed with the peer's own key, not encrypted": {token: peerSigned},
	} {
		t.Run(name, func(t *testing.T) {
			validated, err := Validate(context.Background(), c.token, nil, decrypters, nil, c.jweOpts)
			if errors.Is(err, joseerror.ErrInvalidOptions) {
				t.Fatalf("[RFC 7519 7.2] an encrypt-only JWT can pass these options, so a peer's token must not be reported as a configuration fault, got %v", err)
			}
			if !errors.Is(err, joseerror.ErrInvalidSignature) || !errors.Is(err, joseerror.ErrNoKeyIdentifierMatch) || validated != nil {
				t.Errorf("[RFC 7515 5.2 step 8] no key of the recipient's verifies the signature, so want ErrInvalidSignature matching ErrNoKeyIdentifierMatch, got %v", err)
			}
		})
	}

	encryptOnlyToken := encryptOnly(t, r, map[string]any{"sub": "alice"})
	if validated, err := Validate(context.Background(), encryptOnlyToken, nil, decrypters, nil, nil); err != nil || validated.Claims["sub"] != "alice" {
		t.Errorf("[RFC 7519 7.2 step 10] the encrypt-only JWT these options exist for must still pass, got %+v and %v", validated, err)
	}
	if _, err := Validate(context.Background(), peerSigned, nil, nil, nil, nil); !errors.Is(err, joseerror.ErrInvalidOptions) {
		t.Errorf("with no retriever, no decrypters and no token key allowed, no token can pass, so want ErrInvalidOptions, got %v", err)
	}
}

func TestValidate_ADecryptOnlyRecipientStillUsesAKeyTheTokenNames(t *testing.T) {
	r := recipientFor(t, jwa.A128KW)
	signer, err := jws.GetSigner(jwa.ES256, nil)
	if err != nil {
		t.Fatal(err)
	}
	publicJwk, err := jwk.PublicJwk(signer.Public())
	if err != nil {
		t.Fatal(err)
	}
	signed, err := New(signer, map[string]any{"jwk": *publicJwk}, map[string]any{"sub": "alice"}, Opts{})
	if err != nil {
		t.Fatal(err)
	}
	token, err := Encrypt(r.encrypter, jwa.A128GCM, *signed, nil)
	if err != nil {
		t.Fatal(err)
	}
	validated, err := Validate(context.Background(), token, nil, []model.Decrypter{r.decrypter}, &model.JoseOptions{UseTokenProvidedKeys: true}, nil)
	if err != nil || validated.Claims["sub"] != "alice" {
		t.Errorf("[RFC 7515 4.1.3] with UseTokenProvidedKeys, the jwk the token names must verify it, got %+v and %v", validated, err)
	}
}

func TestValidate_ErrTooManyKeysComesOnlyFromTheSignatureAndTooManyDecryptersAreAnOptionsFault(t *testing.T) {
	r := recipientFor(t, jwa.A128KW)
	signed, _ := signedJWT(t, map[string]any{"sub": "alice"})
	nested, err := Encrypt(r.encrypter, jwa.A128GCM, signed, nil)
	if err != nil {
		t.Fatal(err)
	}
	var wrongKeys []crypto.PublicKey
	for range 3 {
		other, err := jws.GetSigner(jwa.ES256, nil)
		if err != nil {
			t.Fatal(err)
		}
		wrongKeys = append(wrongKeys, other.Public())
	}
	wrong := func() ([]crypto.PublicKey, error) { return wrongKeys, nil }

	if _, err := Validate(context.Background(), nested, wrong, []model.Decrypter{r.decrypter}, &model.JoseOptions{MaxKeysTried: 2}, nil); !errors.Is(err, joseerror.ErrTooManyKeys) || errors.Is(err, joseerror.ErrInvalidOptions) {
		t.Errorf("[RFC 7519 7.2 step 8] the signature of the Nested JWT did not verify under the 2 keys allowed, so want ErrTooManyKeys alone, got %v", err)
	}
	for name, token := range map[string]string{"a nested JWT": nested, "a JWS": signed} {
		decrypters := []model.Decrypter{r.decrypter, r.decrypter, r.decrypter}
		if _, err := Validate(context.Background(), token, wrong, decrypters, nil, &model.JWEOptions{MaxKeysTried: 2}); !errors.Is(err, joseerror.ErrInvalidOptions) || errors.Is(err, joseerror.ErrTooManyKeys) {
			t.Errorf("3 decrypters of one alg are more than the 2 MaxKeysTried allows, so want ErrInvalidOptions for %s, whatever the token, got %v", name, err)
		}
	}
}
