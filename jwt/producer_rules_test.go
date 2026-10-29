package jwt

import (
	"bytes"
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/mldsa"
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"errors"
	"math/big"
	"testing"

	"github.com/MichaelFraser99/go-jose/internal/algorithms/es256"
	"github.com/MichaelFraser99/go-jose/joseerror"
	"github.com/MichaelFraser99/go-jose/jwa"
	"github.com/MichaelFraser99/go-jose/model"
)

type algOverrideSigner struct {
	model.Signer
	alg jwa.Algorithm
}

func (a algOverrideSigner) Alg() jwa.Algorithm {
	return a.alg
}

func producerTestModulus(bits int) *big.Int {
	return new(big.Int).Add(new(big.Int).Lsh(big.NewInt(1), uint(bits-1)), big.NewInt(1))
}

func TestNew_RefusesAnRSAKeyUnder2048Bits(t *testing.T) {
	rsa1024, err := rsa.GenerateKey(rand.Reader, 1024)
	if err != nil {
		t.Fatalf("generating a 1024-bit rsa key: %s", err)
	}
	modulus2047 := fixedOutputSigner{public: &rsa.PublicKey{N: producerTestModulus(2047), E: 65537}, output: make([]byte, 256)}

	tests := []struct {
		name   string
		signer crypto.Signer
		alg    jwa.Algorithm
		clause string
	}{
		{name: "RS256 with a 1024-bit *rsa.PrivateKey", signer: rsa1024, alg: jwa.RS256, clause: "RFC 7518 3.3"},
		{name: "PS256 with a 1024-bit *rsa.PrivateKey", signer: rsa1024, alg: jwa.PS256, clause: "RFC 7518 3.5"},
		{name: "RS256 with an opaque crypto.Signer over a 1024-bit key", signer: opaqueSigner{rsa1024}, alg: jwa.RS256, clause: "RFC 7518 3.3"},
		{name: "PS512 with an opaque crypto.Signer over a 1024-bit key", signer: opaqueSigner{rsa1024}, alg: jwa.PS512, clause: "RFC 7518 3.5"},
		{name: "RS384 with a signer whose public modulus is 2047 bits", signer: modulus2047, alg: jwa.RS384, clause: "RFC 7518 3.3"},
		{name: "PS384 with a signer whose public modulus is 2047 bits", signer: modulus2047, alg: jwa.PS384, clause: "RFC 7518 3.5"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			token, err := New(tt.signer, nil, nil, Opts{Algorithm: tt.alg})
			if err == nil {
				t.Fatalf("[%s] a key of size 2048 bits or larger MUST be used, but New signed %s", tt.clause, *token)
			}
			if !errors.Is(err, joseerror.ErrInvalidPrivateKey) || token != nil {
				t.Errorf("[%s] want ErrInvalidPrivateKey and no token, got %v and %q", tt.clause, token, err)
			}
		})
	}
}

func TestNew_RefusesAKeyTheSignerConstructorsRefuseWithoutPanicking(t *testing.T) {
	ecdsaKey := newTestECDSAKey(t, elliptic.P256())
	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generating an rsa key: %s", err)
	}
	_, edKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generating an ed25519 key: %s", err)
	}
	foreignPublicHalf := append(ed25519.PrivateKey{}, edKey...)
	foreignPublicHalf[ed25519.PrivateKeySize-1] ^= 1
	shortEdKey := make(ed25519.PrivateKey, 10)

	tests := []struct {
		name   string
		signer crypto.Signer
		alg    jwa.Algorithm
	}{
		{name: "a nil signer", signer: nil, alg: jwa.ES256},
		{name: "a nil signer with no algorithm named", signer: nil},
		{name: "a nil *ecdsa.PrivateKey", signer: (*ecdsa.PrivateKey)(nil), alg: jwa.ES256},
		{name: "a nil *rsa.PrivateKey", signer: (*rsa.PrivateKey)(nil), alg: jwa.RS256},
		{name: "a nil *mldsa.PrivateKey", signer: (*mldsa.PrivateKey)(nil), alg: jwa.MLDSA44},
		{name: "a nil *ed25519.PrivateKey", signer: (*ed25519.PrivateKey)(nil), alg: jwa.Ed25519},
		{name: "a nil signer of this library", signer: (*es256.Signer)(nil)},
		{name: "a nil ed25519.PrivateKey", signer: ed25519.PrivateKey(nil), alg: jwa.Ed25519},
		{name: "an ed25519.PrivateKey of 10 octets", signer: make(ed25519.PrivateKey, 10), alg: jwa.Ed25519},
		{name: "an ed25519.PrivateKey of 10 octets asked for ES256", signer: make(ed25519.PrivateKey, 10), alg: jwa.ES256},
		{name: "an ed25519.PrivateKey of 63 octets", signer: make(ed25519.PrivateKey, 63), alg: jwa.Ed25519},
		{name: "a zero-value *ecdsa.PrivateKey", signer: &ecdsa.PrivateKey{}, alg: jwa.ES256},
		{name: "an *ecdsa.PrivateKey with no scalar d", signer: &ecdsa.PrivateKey{PublicKey: ecdsaKey.PublicKey}, alg: jwa.ES256},
		{name: "an *rsa.PrivateKey with no private exponent d", signer: &rsa.PrivateKey{PublicKey: rsaKey.PublicKey}, alg: jwa.RS256},
		{name: "a pointer to an ed25519.PrivateKey of 10 octets", signer: &shortEdKey, alg: jwa.Ed25519},
		{name: "an ed25519.PrivateKey whose public half is not derived from its seed", signer: foreignPublicHalf, alg: jwa.Ed25519},
		{name: "a zero-value *rsa.PrivateKey", signer: &rsa.PrivateKey{}, alg: jwa.RS256},
		{name: "a zero-value *mldsa.PrivateKey", signer: &mldsa.PrivateKey{}, alg: jwa.MLDSA44},
		{name: "a zero-value *mldsa.PrivateKey asked for ES256", signer: &mldsa.PrivateKey{}, alg: jwa.ES256},
		{name: "a signer whose public key is a nil *ecdsa.PublicKey", signer: fixedOutputSigner{public: (*ecdsa.PublicKey)(nil)}, alg: jwa.ES256},
		{name: "a signer whose public key has no curve", signer: fixedOutputSigner{public: &ecdsa.PublicKey{}}, alg: jwa.ES256},
		{name: "a signer whose public key is a nil *rsa.PublicKey", signer: fixedOutputSigner{public: (*rsa.PublicKey)(nil)}, alg: jwa.RS256},
		{name: "a signer whose public key has no modulus", signer: fixedOutputSigner{public: &rsa.PublicKey{}}, alg: jwa.PS256},
		{name: "a signer whose public key is a nil ed25519.PublicKey", signer: fixedOutputSigner{public: ed25519.PublicKey(nil)}, alg: jwa.Ed25519},
		{name: "a signer whose public key is a 31-octet ed25519.PublicKey", signer: fixedOutputSigner{public: make(ed25519.PublicKey, 31)}, alg: jwa.Ed25519},
		{name: "a signer whose public key is a 33-octet ed25519.PublicKey", signer: fixedOutputSigner{public: make(ed25519.PublicKey, 33)}, alg: jwa.Ed25519},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var token *string
			var err error
			func() {
				defer func() {
					if recovered := recover(); recovered != nil {
						t.Fatalf("[jwt.New refuses a key the signer constructors refuse, without panicking] New panicked: %v", recovered)
					}
				}()
				token, err = New(tt.signer, nil, nil, Opts{Algorithm: tt.alg})
			}()
			if !errors.Is(err, joseerror.ErrInvalidPrivateKey) || token != nil {
				t.Errorf("[jwt.New refuses a key the signer constructors refuse, without panicking] want ErrInvalidPrivateKey and no token, got %v and %v", token, err)
			}
		})
	}
}

func TestNew_RefusesAnAlgorithmWithNoName(t *testing.T) {
	inner, err := es256.NewSigner()
	if err != nil {
		t.Fatalf("building an ES256 signer: %s", err)
	}
	stdlibKey := newTestECDSAKey(t, elliptic.P256())

	tests := []struct {
		name   string
		signer crypto.Signer
		opts   Opts
	}{
		{name: "a model.Signer whose Alg is outside the enumeration", signer: algOverrideSigner{Signer: inner, alg: jwa.Algorithm(999)}},
		{name: "a model.Signer whose Alg is Unknown", signer: algOverrideSigner{Signer: inner, alg: jwa.Unknown}},
		{name: "a standard library signer and opts naming an algorithm outside the enumeration", signer: stdlibKey, opts: Opts{Algorithm: jwa.Algorithm(999)}},
		{name: "a standard library signer and opts naming a negative algorithm", signer: stdlibKey, opts: Opts{Algorithm: jwa.Algorithm(-1)}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			token, err := New(tt.signer, nil, nil, tt.opts)
			if err == nil {
				t.Fatalf("[RFC 7515 4.1.1] alg MUST be present and understood, but New emitted the header %s", newTestSegment(t, *token, 0))
			}
			if !errors.Is(err, joseerror.ErrUnsupportedAlgorithm) || token != nil {
				t.Errorf("[RFC 7515 4.1.1] want ErrUnsupportedAlgorithm and no token, got %v and %q", token, err)
			}
		})
	}
}

func TestNew_RefusesAHeadThatBreaksAJwsProducerRule(t *testing.T) {
	es256Signer, err := es256.NewSigner()
	if err != nil {
		t.Fatalf("building an ES256 signer: %s", err)
	}
	stdlibKey := newTestECDSAKey(t, elliptic.P256())

	tests := []struct {
		name   string
		head   map[string]any
		want   error
		clause string
	}{
		{name: "an empty crit array", head: map[string]any{"crit": []any{}}, want: joseerror.ErrMalformedClaim, clause: "RFC 7515 4.1.11"},
		{name: "an empty crit slice of strings", head: map[string]any{"crit": []string{}}, want: joseerror.ErrMalformedClaim, clause: "RFC 7515 4.1.11"},
		{name: "a crit naming alg", head: map[string]any{"crit": []string{"alg"}}, want: joseerror.ErrMalformedClaim, clause: "RFC 7515 4.1.11"},
		{name: "a crit naming typ", head: map[string]any{"crit": []string{"typ"}}, want: joseerror.ErrMalformedClaim, clause: "RFC 7515 4.1.11"},
		{name: "a crit naming kid with kid present", head: map[string]any{"kid": "k1", "crit": []string{"kid"}}, want: joseerror.ErrMalformedClaim, clause: "RFC 7515 4.1.11"},
		{name: "a crit naming crit", head: map[string]any{"crit": []string{"crit"}}, want: joseerror.ErrMalformedClaim, clause: "RFC 7515 4.1.11"},
		{name: "a crit naming one extension twice", head: map[string]any{"exp": 1, "crit": []string{"exp", "exp"}}, want: joseerror.ErrMalformedClaim, clause: "RFC 7515 4.1.11"},
		{name: "a crit naming a parameter the header does not hold", head: map[string]any{"crit": []string{"exp"}}, want: joseerror.ErrMissingCriticalClaim, clause: "RFC 7515 4.1.11"},
		{name: "a crit that is a string", head: map[string]any{"exp": 1, "crit": "exp"}, want: joseerror.ErrMalformedClaim, clause: "RFC 7515 4.1.11"},
		{name: "a crit holding a number", head: map[string]any{"crit": []any{5}}, want: joseerror.ErrMalformedClaim, clause: "RFC 7515 4.1.11"},
		{name: "a crit of null", head: map[string]any{"crit": nil}, want: joseerror.ErrMalformedClaim, clause: "RFC 7515 4.1.11"},
		{name: "an empty crit beside a number beyond the float64 range", head: map[string]any{"n": json.Number("1e400"), "crit": []any{}}, want: joseerror.ErrMalformedClaim, clause: "RFC 7515 4.1.11"},
		{name: "a b64 of false beside a number beyond the float64 range", head: map[string]any{"n": json.Number("-1e400"), "b64": false}, want: joseerror.ErrMissingCriticalClaim, clause: "RFC 7797 3"},
		{name: "a kid that is a number", head: map[string]any{"kid": 5}, want: joseerror.ErrMalformedClaim, clause: "RFC 7515 4.1.4"},
		{name: "a kid that is a number beyond the float64 range", head: map[string]any{"kid": json.Number("1e400")}, want: joseerror.ErrMalformedClaim, clause: "RFC 7515 4.1.4"},
		{name: "an x5t that is a number", head: map[string]any{"x5t": 5}, want: joseerror.ErrMalformedClaim, clause: "RFC 7515 4.1.7"},
		{name: "an x5t that is not base64url", head: map[string]any{"x5t": "a+b/"}, want: joseerror.ErrMalformedClaim, clause: "RFC 7515 4.1.7"},
		{name: "an x5t#S256 that is not base64url", head: map[string]any{"x5t#S256": "a+b/"}, want: joseerror.ErrMalformedClaim, clause: "RFC 7515 4.1.8"},
		{name: "a jku over plain http", head: map[string]any{"jku": "http://example.com/jwks"}, want: joseerror.ErrMalformedClaim, clause: "RFC 7515 4.1.2"},
		{name: "an x5u over plain http", head: map[string]any{"x5u": "http://example.com/chain.pem"}, want: joseerror.ErrMalformedClaim, clause: "RFC 7515 4.1.5"},
		{name: "an x5c that is a string", head: map[string]any{"x5c": "abc"}, want: joseerror.ErrMalformedClaim, clause: "RFC 7515 4.1.6"},
		{name: "an x5c whose entry is not a DER certificate", head: map[string]any{"x5c": []string{"abc"}}, want: joseerror.ErrMalformedClaim, clause: "RFC 7515 4.1.6"},
		{name: "a jwk that is a string", head: map[string]any{"jwk": "x"}, want: joseerror.ErrMalformedClaim, clause: "RFC 7515 4.1.3"},
		{name: "a typ that is a number", head: map[string]any{"typ": 5}, want: joseerror.ErrMalformedClaim, clause: "RFC 7515 4.1.9"},
		{name: "a cty that is a number", head: map[string]any{"cty": 5}, want: joseerror.ErrMalformedClaim, clause: "RFC 7515 4.1.10"},
		{name: "a b64 that is the string false", head: map[string]any{"b64": "false", "crit": []string{"b64"}}, want: joseerror.ErrMalformedClaim, clause: "RFC 7797 3"},
		{name: "a b64 of true without crit", head: map[string]any{"b64": true}, want: joseerror.ErrMissingCriticalClaim, clause: "RFC 7797 6"},
		{name: "a b64 of true with a crit that does not name it", head: map[string]any{"b64": true, "exp": 1, "crit": []string{"exp"}}, want: joseerror.ErrMissingCriticalClaim, clause: "RFC 7797 6"},
		{name: "a b64 of false", head: map[string]any{"b64": false, "crit": []string{"b64"}}, want: joseerror.ErrMissingCriticalClaim, clause: "RFC 7797 3"},
		{name: "a b64 of false without crit", head: map[string]any{"b64": false}, want: joseerror.ErrMissingCriticalClaim, clause: "RFC 7797 3"},
	}

	for _, signer := range []struct {
		name   string
		signer crypto.Signer
	}{{"a signer of this library", es256Signer}, {"a standard library signer", stdlibKey}} {
		for _, tt := range tests {
			t.Run(signer.name+" and "+tt.name, func(t *testing.T) {
				token, err := New(signer.signer, tt.head, map[string]any{"sub": "a"}, Opts{Algorithm: jwa.ES256})
				if err == nil {
					t.Fatalf("[%s] New signed a header a producer MUST NOT emit: %s", tt.clause, newTestSegment(t, *token, 0))
				}
				if !errors.Is(err, tt.want) || token != nil {
					t.Errorf("[%s] want %q and no token, got %v and %q", tt.clause, tt.want, token, err)
				}
			})
		}
	}
}

func TestNew_SignsAHeadThatKeepsTheJwsProducerRules(t *testing.T) {
	signer, err := es256.NewSigner()
	if err != nil {
		t.Fatalf("building an ES256 signer: %s", err)
	}

	tests := []struct {
		name       string
		head       map[string]any
		understood []string
	}{
		{name: "a crit naming one extension the header holds", head: map[string]any{"exp": 1, "crit": []string{"exp"}}, understood: []string{"exp"}},
		{name: "a crit naming two extensions the header holds", head: map[string]any{"exp": 1, "nbf": 0, "crit": []any{"exp", "nbf"}}, understood: []string{"exp", "nbf"}},
		{name: "a b64 of true named in crit", head: map[string]any{"b64": true, "crit": []string{"b64"}}, understood: []string{"b64"}},
		{name: "a b64 of true named in crit beside another extension", head: map[string]any{"b64": true, "exp": 1, "crit": []string{"exp", "b64"}}, understood: []string{"exp", "b64"}},
		{name: "string media types and a kid", head: map[string]any{"typ": "JWT", "cty": "example", "kid": "k1"}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			token, err := New(signer, tt.head, map[string]any{"sub": "a"}, Opts{})
			if err != nil {
				t.Fatalf("[RFC 7515 4.1, RFC 7797 3 and 6] New refused a header that keeps every producer rule: %s", err)
			}
			if _, _, err := Validate(context.Background(), *token, newTestRetriever(signer.Public()), &model.JoseOptions{UnderstoodCriticalHeaders: tt.understood}); err != nil {
				t.Errorf("[RFC 7515 5.2] the token does not verify: %s", err)
			}
		})
	}
}

func TestNew_SignsAHeaderNumberBeyondTheFloat64Range(t *testing.T) {
	signer, err := es256.NewSigner()
	if err != nil {
		t.Fatalf("building an ES256 signer: %s", err)
	}
	token, err := New(signer, map[string]any{"n": json.Number("1e400")}, nil, Opts{})
	if err != nil {
		t.Fatalf("[RFC 8259 6] 1e400 is a JSON number, and no producer rule of RFC 7515 forbids it in a header, but New refused it: %s", err)
	}
	if head := newTestSegment(t, *token, 0); !bytes.Contains(head, []byte(`"n":1e400`)) {
		t.Errorf("[RFC 8259 6] want the header to carry the number as given, got %s", head)
	}
}

func TestValidate_RefusesATokenOfTheWrongShape(t *testing.T) {
	tests := []struct {
		name   string
		token  string
		want   error
		clause string
	}{
		{name: "an empty token", token: "", want: joseerror.ErrMalformedToken, clause: "RFC 7519 7.2 step 1"},
		{name: "one segment", token: "eyJhbGciOiJFUzI1NiJ9", want: joseerror.ErrMalformedToken, clause: "RFC 7519 7.2 step 1"},
		{name: "two segments", token: "eyJhbGciOiJFUzI1NiJ9.e30", want: joseerror.ErrMalformedToken, clause: "RFC 7515 7.1"},
		{name: "four segments", token: "a.b.c.d", want: joseerror.ErrMalformedToken, clause: "RFC 7515 7.1"},
		{name: "six segments", token: "a.b.c.d.e.f", want: joseerror.ErrMalformedToken, clause: "RFC 7515 7.1"},
		{name: "five segments, the shape of a JWE", token: "a.b.c.d.e", want: joseerror.ErrUnsupportedAlgorithm, clause: "RFC 7516 9"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			head, body, err := Validate(context.Background(), tt.token, nil, nil)
			if !errors.Is(err, tt.want) || head != nil || body != nil {
				t.Errorf("[%s] want %q and no head or body, got %v, %v and %q", tt.clause, tt.want, head, body, err)
			}
		})
	}
}
