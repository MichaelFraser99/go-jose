package jwt

import (
	"context"
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
	"errors"
	"strings"
	"testing"

	"github.com/MichaelFraser99/go-jose/joseerror"
	"github.com/MichaelFraser99/go-jose/jwa"
	"github.com/MichaelFraser99/go-jose/jwe"
	"github.com/MichaelFraser99/go-jose/jws"
	"github.com/MichaelFraser99/go-jose/model"
)

type signingAlgDecrypter struct {
	model.Decrypter
}

func (signingAlgDecrypter) Alg() jwa.Algorithm {
	return jwa.ES256
}

func TestCheckOptions_RefusesArgumentsUnderWhichNoTokenCanPass(t *testing.T) {
	shared := recipientFor(t, jwa.A128KW)
	public := recipientFor(t, jwa.RSAOAEP256)
	signed, retriever := signedJWT(t, map[string]any{"sub": "alice"})
	nested, err := Encrypt(shared.encrypter, jwa.A128GCM, signed, nil)
	if err != nil {
		t.Fatal(err)
	}
	sharedOnly := encryptOnly(t, shared, map[string]any{"sub": "alice"})
	publicOnly := encryptOnly(t, public, map[string]any{"sub": "alice"})
	onlyDir := &model.JWEOptions{AllowedKeyManagementAlgorithms: []jwa.Algorithm{jwa.Dir}}
	for name, tt := range map[string]struct {
		retriever  model.Retriever
		decrypters []model.Decrypter
		opts       *model.JoseOptions
		jweOpts    *model.JWEOptions
		tokens     []string
	}{
		"RequireEncryptedJWT with no decrypters": {
			retriever: retriever, opts: &model.JoseOptions{RequireEncryptedJWT: true}, tokens: []string{signed, nested},
		},
		"RequireEncryptedJWT with no decrypter of a permitted alg": {
			retriever: retriever, decrypters: []model.Decrypter{shared.decrypter}, opts: &model.JoseOptions{RequireEncryptedJWT: true}, jweOpts: onlyDir, tokens: []string{signed, nested},
		},
		"RequireEncryptedJWT with only a decrypter whose alg is not key management": {
			retriever: retriever, decrypters: []model.Decrypter{signingAlgDecrypter{shared.decrypter}}, opts: &model.JoseOptions{RequireEncryptedJWT: true}, tokens: []string{signed, nested},
		},
		"RequireSignedJWT with decrypters and no key source": {
			decrypters: []model.Decrypter{shared.decrypter}, opts: &model.JoseOptions{RequireSignedJWT: true}, tokens: []string{signed, nested, sharedOnly},
		},
		"no key source and no decrypters": {
			tokens: []string{signed},
		},
		"no key source and only a public-key decrypter": {
			decrypters: []model.Decrypter{public.decrypter}, tokens: []string{signed, publicOnly},
		},
		"only HMAC algorithms allowed, with KeySet and no retriever": {
			decrypters: []model.Decrypter{public.decrypter}, opts: &model.JoseOptions{KeySet: &model.Jwks{}, AllowedSigningAlgorithms: []jwa.Algorithm{jwa.HS256}}, tokens: []string{signed, publicOnly},
		},
		"only HMAC algorithms allowed, with UseTokenProvidedKeys and no retriever": {
			opts: &model.JoseOptions{UseTokenProvidedKeys: true, AllowedSigningAlgorithms: []jwa.Algorithm{jwa.HS256, jwa.HS512}}, tokens: []string{signed},
		},
		"only HMAC algorithms allowed, with X509Roots and no retriever": {
			opts: &model.JoseOptions{X509Roots: x509.NewCertPool(), AllowedSigningAlgorithms: []jwa.Algorithm{jwa.HS384}}, tokens: []string{signed},
		},
		"no key source and a shared-key decrypter the JWE options do not permit": {
			decrypters: []model.Decrypter{shared.decrypter}, jweOpts: onlyDir, tokens: []string{signed, nested, sharedOnly},
		},
	} {
		t.Run(name, func(t *testing.T) {
			if err := CheckOptions(tt.retriever, tt.decrypters, tt.opts, tt.jweOpts); !errors.Is(err, joseerror.ErrInvalidOptions) {
				t.Errorf("[README Errors] no token can pass with %s, so CheckOptions must refuse it with ErrInvalidOptions, got %v", name, err)
			}
			if err := CheckOptions(tt.retriever, tt.decrypters, tt.opts, tt.jweOpts); strings.HasPrefix(name, "only HMAC") && (err == nil || !strings.Contains(err.Error(), "only HMAC algorithms")) {
				t.Errorf("[README Errors] the refusal must name its cause, that only HMAC algorithms are allowed, got %v", err)
			}
			for _, token := range tt.tokens {
				if validated, err := Validate(context.Background(), token, tt.retriever, tt.decrypters, tt.opts, tt.jweOpts); !errors.Is(err, joseerror.ErrInvalidOptions) || validated != nil {
					t.Errorf("[README Errors] no token can pass with %s, so Validate must refuse every token with ErrInvalidOptions, got %v", name, err)
				}
			}
		})
	}
}

func TestCheckOptions_AcceptsArgumentsUnderWhichSomeTokenPasses(t *testing.T) {
	shared := recipientFor(t, jwa.A128KW)
	secret := make([]byte, 32)
	if _, err := rand.Read(secret); err != nil {
		t.Fatal(err)
	}
	hmacSigner, err := jws.GetSigner(jwa.HS256, &model.Opts{SecretKey: &secret})
	if err != nil {
		t.Fatal(err)
	}
	hmacToken, err := New(hmacSigner, nil, map[string]any{"sub": "alice"}, Opts{})
	if err != nil {
		t.Fatal(err)
	}
	hmacSigned, hmacRetriever := *hmacToken, newTestRetriever(hmacSigner.Public())
	public := recipientFor(t, jwa.RSAOAEP256)
	signed, retriever := signedJWT(t, map[string]any{"sub": "alice"})
	nested, err := Encrypt(shared.encrypter, jwa.A128GCM, signed, nil)
	if err != nil {
		t.Fatal(err)
	}
	for name, tt := range map[string]struct {
		retriever  model.Retriever
		decrypters []model.Decrypter
		opts       *model.JoseOptions
		jweOpts    *model.JWEOptions
		token      string
	}{
		"RequireEncryptedJWT with a permitted decrypter": {
			retriever: retriever, decrypters: []model.Decrypter{shared.decrypter}, opts: &model.JoseOptions{RequireEncryptedJWT: true}, token: nested,
		},
		"RequireSignedJWT with decrypters and a retriever": {
			retriever: retriever, decrypters: []model.Decrypter{shared.decrypter}, opts: &model.JoseOptions{RequireSignedJWT: true}, token: nested,
		},
		"only HMAC algorithms allowed, with a retriever": {
			retriever: hmacRetriever, opts: &model.JoseOptions{AllowedSigningAlgorithms: []jwa.Algorithm{jwa.HS256}}, token: hmacSigned,
		},
		"no key source and a shared-key decrypter": {
			decrypters: []model.Decrypter{shared.decrypter}, token: encryptOnly(t, shared, map[string]any{"sub": "alice"}),
		},
		"no key source and a public-key decrypter with AllowUnauthenticatedJWT": {
			decrypters: []model.Decrypter{public.decrypter}, jweOpts: &model.JWEOptions{AllowUnauthenticatedJWT: true}, token: encryptOnly(t, public, map[string]any{"sub": "alice"}),
		},
	} {
		t.Run(name, func(t *testing.T) {
			if err := CheckOptions(tt.retriever, tt.decrypters, tt.opts, tt.jweOpts); err != nil {
				t.Errorf("[README Errors] a token can pass with %s, so CheckOptions must accept it, got %v", name, err)
			}
			if validated, err := Validate(context.Background(), tt.token, tt.retriever, tt.decrypters, tt.opts, tt.jweOpts); err != nil || validated.Claims["sub"] != "alice" {
				t.Errorf("[README Errors] want the token to pass with %s, got %v", name, err)
			}
		})
	}
	for name, opts := range map[string]*model.JoseOptions{
		"KeySet with HMAC and ES256 allowed": {RequireSignedJWT: true, KeySet: &model.Jwks{}, AllowedSigningAlgorithms: []jwa.Algorithm{jwa.HS256, jwa.ES256}},
		"KeySet":                             {RequireSignedJWT: true, KeySet: &model.Jwks{}},
		"UseTokenProvidedKeys":               {RequireSignedJWT: true, UseTokenProvidedKeys: true},
		"X509Roots":                          {RequireSignedJWT: true, X509Roots: x509.NewCertPool()},
	} {
		if err := CheckOptions(nil, []model.Decrypter{shared.decrypter}, opts, nil); err != nil {
			t.Errorf("[RFC 7515 4.1] %s is a key source a signed token can pass under, so CheckOptions must accept it, got %v", name, err)
		}
	}
}

func signRaw(t *testing.T, head, payload string) (string, model.Retriever) {
	t.Helper()
	signer, err := jws.GetSigner(jwa.ES256, nil)
	if err != nil {
		t.Fatal(err)
	}
	input := base64.RawURLEncoding.EncodeToString([]byte(head)) + "." + base64.RawURLEncoding.EncodeToString([]byte(payload))
	signature, err := signer.Sign(rand.Reader, []byte(input), nil)
	if err != nil {
		t.Fatal(err)
	}
	return input + "." + base64.RawURLEncoding.EncodeToString(signature), newTestRetriever(signer.Public())
}

func TestEncrypt_RefusesASignedJWTThatValidateWouldRefuse(t *testing.T) {
	r := recipientFor(t, jwa.A128KW)
	understood := &model.JoseOptions{UnderstoodCriticalHeaders: []string{"exp", "b64"}}
	for name, tt := range map[string]struct {
		head, payload string
		want          error
	}{
		"a header and claims set Validate accepts": {head: `{"alg":"ES256","kid":"k","typ":"JWT"}`, payload: `{"sub":"alice"}`},
		"a kid that is not a string":               {head: `{"alg":"ES256","kid":123}`, payload: `{}`, want: joseerror.ErrMalformedToken},
		"a b64 of false":                           {head: `{"alg":"ES256","b64":false,"crit":["b64"]}`, payload: `{}`, want: joseerror.ErrMalformedToken},
		"a crit naming a member not present":       {head: `{"alg":"ES256","crit":["exp"]}`, payload: `{}`, want: joseerror.ErrMalformedToken},
		"a jku that is not https":                  {head: `{"alg":"ES256","jku":"http://example.com/jwks"}`, payload: `{}`, want: joseerror.ErrMalformedToken},
		"a typ that is not a string":               {head: `{"alg":"ES256","typ":1}`, payload: `{}`, want: joseerror.ErrMalformedToken},
		"a cty naming JWT":                         {head: `{"alg":"ES256","cty":"JWT"}`, payload: `{}`, want: joseerror.ErrUnsupportedAlgorithm},
		"a payload of null":                        {head: `{"alg":"ES256"}`, payload: `null`, want: joseerror.ErrMalformedToken},
		"a payload that is an array":               {head: `{"alg":"ES256"}`, payload: `[]`, want: joseerror.ErrMalformedToken},
		"a payload that is not JSON":               {head: `{"alg":"ES256"}`, payload: `alice`, want: joseerror.ErrMalformedToken},
	} {
		t.Run(name, func(t *testing.T) {
			signed, retriever := signRaw(t, tt.head, tt.payload)
			if _, err := Validate(context.Background(), signed, retriever, nil, understood, nil); (err == nil) != (tt.want == nil) {
				t.Fatalf("[RFC 7519 7.2] the premise is that Validate refuses a JWS with %s only when Encrypt must, got %v", name, err)
			}
			token, err := Encrypt(r.encrypter, jwa.A128GCM, signed, nil)
			if tt.want == nil {
				if _, err := Validate(context.Background(), token, retriever, []model.Decrypter{r.decrypter}, understood, nil); err != nil {
					t.Errorf("[RFC 7519 5.2] Encrypt must nest a JWS with %s, and Validate accept it, got %v", name, err)
				}
				return
			}
			if !errors.Is(err, tt.want) || token != "" {
				t.Errorf("[RFC 7519 5.2] Encrypt must not nest a JWS with %s, which Validate refuses, so want %v, got %v", name, tt.want, err)
			}
		})
	}
}

func TestValidate_ANestedPlaintextOfFiveSegmentsIsAJWEOnlyWhenItsHeaderIsOne(t *testing.T) {
	r := recipientFor(t, jwa.A128KW)
	jweHeader := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"A128KW","enc":"A128GCM"}`))
	for name, tt := range map[string]struct {
		plaintext string
		want      error
	}{
		"five segments of garbage":           {plaintext: "a.b.c.d.e", want: joseerror.ErrMalformedToken},
		"a JWS header in five segments":      {plaintext: base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"ES256"}`)) + ".b.c.d.e", want: joseerror.ErrMalformedToken},
		"a JWE header, a JWE inside the JWE": {plaintext: jweHeader + ".b.c.d.e", want: joseerror.ErrUnsupportedAlgorithm},
	} {
		t.Run(name, func(t *testing.T) {
			token, err := jwe.Encrypt(r.encrypter, jwa.A128GCM, []byte(tt.plaintext), map[string]any{"cty": "JWT"})
			if err != nil {
				t.Fatal(err)
			}
			if validated, err := Validate(context.Background(), token, newTestRetriever(nil), []model.Decrypter{r.decrypter}, nil, nil); !errors.Is(err, tt.want) || validated != nil {
				t.Errorf("[RFC 7516 9] a JWE header holds 'enc', so a plaintext of %s wants %v, got %v", name, tt.want, err)
			}
		})
	}
}
