package jwt

import (
	"bytes"
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"encoding/asn1"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"maps"
	"math/big"
	"strings"
	"sync"
	"testing"

	"github.com/MichaelFraser99/go-jose/internal/algorithms/es256"
	"github.com/MichaelFraser99/go-jose/internal/algorithms/hs256"
	"github.com/MichaelFraser99/go-jose/joseerror"
	"github.com/MichaelFraser99/go-jose/jwa"
	"github.com/MichaelFraser99/go-jose/model"
)

type opaqueSigner struct {
	crypto.Signer
}

type fixedOutputSigner struct {
	public crypto.PublicKey
	output []byte
}

func (f fixedOutputSigner) Public() crypto.PublicKey {
	return f.public
}

func (f fixedOutputSigner) Sign(io.Reader, []byte, crypto.SignerOpts) ([]byte, error) {
	return f.output, nil
}

type joseModeOnlySigner struct {
	model.Signer
}

func (j joseModeOnlySigner) Sign(random io.Reader, signingInput []byte, opts crypto.SignerOpts) ([]byte, error) {
	if opts != nil && opts.HashFunc() != 0 {
		return nil, errors.New("this signer takes the JWS Signing Input, not a digest")
	}
	return j.Signer.Sign(random, signingInput, opts)
}

func newTestSegment(t *testing.T, token string, index int) []byte {
	t.Helper()
	segments := strings.Split(token, ".")
	if len(segments) != 3 {
		t.Fatalf("a JWS compact serialization has three segments, got %d", len(segments))
	}
	raw, err := base64.RawURLEncoding.DecodeString(segments[index])
	if err != nil {
		t.Fatalf("segment %d is not base64url: %s", index, err)
	}
	return raw
}

func newTestHeader(t *testing.T, token string) map[string]any {
	t.Helper()
	var head map[string]any
	if err := json.Unmarshal(newTestSegment(t, token, 0), &head); err != nil {
		t.Fatalf("the header is not a JSON object: %s", err)
	}
	return head
}

func newTestRetriever(public crypto.PublicKey) model.Retriever {
	return func() ([]crypto.PublicKey, error) {
		return []crypto.PublicKey{public}, nil
	}
}

func newTestECDSAKey(t *testing.T, curve elliptic.Curve) *ecdsa.PrivateKey {
	t.Helper()
	key, err := ecdsa.GenerateKey(curve, rand.Reader)
	if err != nil {
		t.Fatalf("generating an ecdsa key: %s", err)
	}
	return key
}

func newTestDER(t *testing.T, r, s *big.Int) []byte {
	t.Helper()
	der, err := asn1.Marshal(struct{ R, S *big.Int }{r, s})
	if err != nil {
		t.Fatalf("marshalling a DER signature: %s", err)
	}
	return der
}

func TestNew_TheAlgHeaderNamesTheAlgorithmThatSigned(t *testing.T) {
	es256Signer, err := es256.NewSigner()
	if err != nil {
		t.Fatalf("building an ES256 signer: %s", err)
	}
	hs256Signer, err := hs256.NewSigner(model.Pointer(bytes.Repeat([]byte("k"), hs256.MinimumSecretBytes)))
	if err != nil {
		t.Fatalf("building an HS256 signer: %s", err)
	}
	stdlibKey := newTestECDSAKey(t, elliptic.P256())

	tests := []struct {
		name    string
		signer  crypto.Signer
		head    map[string]any
		opts    Opts
		wantAlg string
	}{
		{name: "a signer of this library fills in its own alg", signer: es256Signer, head: map[string]any{}, wantAlg: "ES256"},
		{name: "a signer of this library keeps an alg that names its algorithm", signer: es256Signer, head: map[string]any{"alg": "ES256"}, opts: Opts{Algorithm: jwa.ES256}, wantAlg: "ES256"},
		{name: "an HMAC signer of this library fills in its own alg", signer: hs256Signer, head: map[string]any{}, wantAlg: "HS256"},
		{name: "a signer of this library refuses an alg of another family", signer: es256Signer, head: map[string]any{"alg": "HS256"}},
		{name: "a signer of this library refuses an alg of none", signer: es256Signer, head: map[string]any{"alg": "none"}},
		{name: "a signer of this library refuses an alg of another key type", signer: es256Signer, head: map[string]any{"alg": "RS256"}},
		{name: "a signer of this library refuses an alg that is not a string", signer: es256Signer, head: map[string]any{"alg": 5}},
		{name: "a signer of this library refuses an alg that prints as its algorithm but is not a string", signer: es256Signer, head: map[string]any{"alg": jwa.ES256}},
		{name: "a signer of this library refuses an alg differing only in case", signer: es256Signer, head: map[string]any{"alg": "es256"}},
		{name: "a signer of this library refuses opts naming another algorithm", signer: es256Signer, head: map[string]any{}, opts: Opts{Algorithm: jwa.RS256}},
		{name: "a signer of this library refuses opts naming another algorithm when the head agrees with the signer", signer: es256Signer, head: map[string]any{"alg": "ES256"}, opts: Opts{Algorithm: jwa.ES384}},
		{name: "a standard library signer takes its alg from opts", signer: stdlibKey, head: map[string]any{}, opts: Opts{Algorithm: jwa.ES256}, wantAlg: "ES256"},
		{name: "a standard library signer takes its alg from the head", signer: stdlibKey, head: map[string]any{"alg": "ES256"}, wantAlg: "ES256"},
		{name: "a standard library signer with no alg anywhere is refused", signer: stdlibKey, head: map[string]any{}},
		{name: "a standard library signer refuses a head and opts that disagree", signer: stdlibKey, head: map[string]any{"alg": "ES384"}, opts: Opts{Algorithm: jwa.ES256}},
		{name: "a standard library signer refuses an alg of none", signer: stdlibKey, head: map[string]any{"alg": "none"}},
		{name: "a standard library signer refuses a null alg", signer: stdlibKey, head: map[string]any{"alg": nil}, opts: Opts{Algorithm: jwa.ES256}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			token, err := New(tt.signer, tt.head, map[string]any{"sub": "a"}, tt.opts)
			if tt.wantAlg == "" {
				if err == nil {
					t.Fatalf("[RFC 7515 4.1.1] New emitted a header the signature does not match: %s", newTestSegment(t, *token, 0))
				}
				if !errors.Is(err, joseerror.ErrUnsupportedAlgorithm) {
					t.Errorf("[RFC 7515 4.1.1] want ErrUnsupportedAlgorithm, got %q", err)
				}
				return
			}
			if err != nil {
				t.Fatalf("[RFC 7515 4.1.1] New refused a consistent signer, head and opts: %s", err)
			}
			if alg := newTestHeader(t, *token)["alg"]; alg != tt.wantAlg {
				t.Errorf("[RFC 7515 4.1.1] want alg %q, got %v", tt.wantAlg, alg)
			}
			if _, _, err := Validate(context.Background(), *token, newTestRetriever(tt.signer.Public()), nil); err != nil {
				t.Errorf("[RFC 7515 5.2] the token does not verify under the alg its header names: %s", err)
			}
		})
	}
}

func TestNew_CallsAModelSignerWithTheJwsSigningInput(t *testing.T) {
	inner, err := es256.NewSigner()
	if err != nil {
		t.Fatalf("building an ES256 signer: %s", err)
	}
	signer := joseModeOnlySigner{inner}

	token, err := New(signer, map[string]any{}, map[string]any{"sub": "a"}, Opts{Algorithm: jwa.ES256})
	if err != nil {
		t.Fatalf("[model.Signer JOSE mode] New handed a model.Signer a digest rather than the JWS Signing Input: %s", err)
	}
	if _, _, err := Validate(context.Background(), *token, newTestRetriever(signer.Public()), nil); err != nil {
		t.Errorf("[RFC 7515 5.1] the token does not verify: %s", err)
	}
}

func TestNew_StandardLibrarySignersProduceJwsSignatures(t *testing.T) {
	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generating an rsa key: %s", err)
	}
	p256 := newTestECDSAKey(t, elliptic.P256())
	p384 := newTestECDSAKey(t, elliptic.P384())
	p521 := newTestECDSAKey(t, elliptic.P521())
	_, edKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generating an ed25519 key: %s", err)
	}

	sum := func(h crypto.Hash, input []byte) []byte {
		hasher := h.New()
		hasher.Write(input)
		return hasher.Sum(nil)
	}
	verifyECDSA := func(size int, h crypto.Hash) func(t *testing.T, public crypto.PublicKey, input, signature []byte) {
		return func(t *testing.T, public crypto.PublicKey, input, signature []byte) {
			if len(signature) != 2*size {
				t.Fatalf("[RFC 7518 3.4] the signature must be the %d-octet R||S, got %d octets", 2*size, len(signature))
			}
			r := new(big.Int).SetBytes(signature[:size])
			s := new(big.Int).SetBytes(signature[size:])
			if !ecdsa.Verify(public.(*ecdsa.PublicKey), sum(h, input), r, s) {
				t.Error("[RFC 7518 3.4] R||S does not verify under crypto/ecdsa")
			}
		}
	}
	verifyPSS := func(h crypto.Hash) func(t *testing.T, public crypto.PublicKey, input, signature []byte) {
		return func(t *testing.T, public crypto.PublicKey, input, signature []byte) {
			if err := rsa.VerifyPSS(public.(*rsa.PublicKey), h, sum(h, input), signature, &rsa.PSSOptions{SaltLength: rsa.PSSSaltLengthEqualsHash}); err != nil {
				t.Errorf("[RFC 7518 3.5] not an RSASSA-PSS signature with a salt the size of the hash: %s", err)
			}
		}
	}
	verifyPKCS1 := func(h crypto.Hash) func(t *testing.T, public crypto.PublicKey, input, signature []byte) {
		return func(t *testing.T, public crypto.PublicKey, input, signature []byte) {
			if err := rsa.VerifyPKCS1v15(public.(*rsa.PublicKey), h, sum(h, input), signature); err != nil {
				t.Errorf("[RFC 7518 3.3] not an RSASSA-PKCS1-v1_5 signature: %s", err)
			}
		}
	}

	tests := []struct {
		name           string
		signer         crypto.Signer
		alg            jwa.Algorithm
		verify         func(t *testing.T, public crypto.PublicKey, input, signature []byte)
		viaThisLibrary bool
	}{
		{name: "ES256 with *ecdsa.PrivateKey", signer: p256, alg: jwa.ES256, verify: verifyECDSA(32, crypto.SHA256), viaThisLibrary: true},
		{name: "ES384 with *ecdsa.PrivateKey", signer: p384, alg: jwa.ES384, verify: verifyECDSA(48, crypto.SHA384), viaThisLibrary: true},
		{name: "ES512 with *ecdsa.PrivateKey", signer: p521, alg: jwa.ES512, verify: verifyECDSA(66, crypto.SHA512), viaThisLibrary: true},
		{name: "ES256 with an opaque crypto.Signer over an ecdsa key", signer: opaqueSigner{p256}, alg: jwa.ES256, verify: verifyECDSA(32, crypto.SHA256), viaThisLibrary: true},
		{name: "ES512 with an opaque crypto.Signer over an ecdsa key", signer: opaqueSigner{p521}, alg: jwa.ES512, verify: verifyECDSA(66, crypto.SHA512), viaThisLibrary: true},
		{name: "PS256 with *rsa.PrivateKey", signer: rsaKey, alg: jwa.PS256, verify: verifyPSS(crypto.SHA256), viaThisLibrary: true},
		{name: "PS384 with *rsa.PrivateKey", signer: rsaKey, alg: jwa.PS384, verify: verifyPSS(crypto.SHA384), viaThisLibrary: true},
		{name: "PS512 with *rsa.PrivateKey", signer: rsaKey, alg: jwa.PS512, verify: verifyPSS(crypto.SHA512), viaThisLibrary: true},
		{name: "PS256 with an opaque crypto.Signer over an rsa key", signer: opaqueSigner{rsaKey}, alg: jwa.PS256, verify: verifyPSS(crypto.SHA256), viaThisLibrary: true},
		{name: "RS256 with *rsa.PrivateKey", signer: rsaKey, alg: jwa.RS256, verify: verifyPKCS1(crypto.SHA256), viaThisLibrary: true},
		{name: "RS512 with an opaque crypto.Signer over an rsa key", signer: opaqueSigner{rsaKey}, alg: jwa.RS512, verify: verifyPKCS1(crypto.SHA512), viaThisLibrary: true},
		{name: "EdDSA with ed25519.PrivateKey", signer: edKey, alg: jwa.EdDSA, verify: func(t *testing.T, public crypto.PublicKey, input, signature []byte) {
			if !ed25519.Verify(public.(ed25519.PublicKey), input, signature) {
				t.Error("[RFC 8037 3.1] not an Ed25519 signature over the JWS Signing Input")
			}
		}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			token, err := New(tt.signer, map[string]any{}, map[string]any{"sub": "a"}, Opts{Algorithm: tt.alg})
			if err != nil {
				t.Fatalf("New refused a standard library signer for %s: %s", tt.alg, err)
			}
			segments := strings.Split(*token, ".")
			tt.verify(t, tt.signer.Public(), []byte(segments[0]+"."+segments[1]), newTestSegment(t, *token, 2))
			if !tt.viaThisLibrary {
				return
			}
			if _, _, err := Validate(context.Background(), *token, newTestRetriever(tt.signer.Public()), nil); err != nil {
				t.Errorf("[RFC 7518 3] this library's validator refuses the token: %s", err)
			}
		})
	}
}

func TestNew_AnECDSASignatureIsRAndSAtTheCurvesFixedWidth(t *testing.T) {
	belowOrder := func(curve elliptic.Curve) *big.Int {
		return new(big.Int).Sub(curve.Params().N, big.NewInt(1))
	}
	tests := []struct {
		name  string
		curve elliptic.Curve
		alg   jwa.Algorithm
		r, s  *big.Int
		want  []byte
	}{
		{name: "ES256 keeps the leading zero octets of a small R and S", curve: elliptic.P256(), alg: jwa.ES256, r: big.NewInt(1), s: big.NewInt(2), want: append(append(make([]byte, 31), 1), append(make([]byte, 31), 2)...)},
		{name: "ES384 keeps the leading zero octets of a small R and S", curve: elliptic.P384(), alg: jwa.ES384, r: big.NewInt(1), s: big.NewInt(2), want: append(append(make([]byte, 47), 1), append(make([]byte, 47), 2)...)},
		{name: "ES512 keeps the leading zero octets of a small R and S", curve: elliptic.P521(), alg: jwa.ES512, r: big.NewInt(1), s: big.NewInt(2), want: append(append(make([]byte, 65), 1), append(make([]byte, 65), 2)...)},
		{name: "ES256 takes an R and S of n-1", curve: elliptic.P256(), alg: jwa.ES256, r: belowOrder(elliptic.P256()), s: belowOrder(elliptic.P256()), want: bytes.Repeat(belowOrder(elliptic.P256()).FillBytes(make([]byte, 32)), 2)},
		{name: "ES384 takes an R and S of n-1", curve: elliptic.P384(), alg: jwa.ES384, r: belowOrder(elliptic.P384()), s: belowOrder(elliptic.P384()), want: bytes.Repeat(belowOrder(elliptic.P384()).FillBytes(make([]byte, 48)), 2)},
		{name: "ES512 takes an R and S of n-1", curve: elliptic.P521(), alg: jwa.ES512, r: belowOrder(elliptic.P521()), s: belowOrder(elliptic.P521()), want: bytes.Repeat(belowOrder(elliptic.P521()).FillBytes(make([]byte, 66)), 2)},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			signer := fixedOutputSigner{
				public: &newTestECDSAKey(t, tt.curve).PublicKey,
				output: newTestDER(t, tt.r, tt.s),
			}
			token, err := New(signer, map[string]any{}, map[string]any{}, Opts{Algorithm: tt.alg})
			if err != nil {
				t.Fatalf("[RFC 7518 3.4, FIPS 186-5 6.4.1] New refused a well formed DER signature: %s", err)
			}
			if got := newTestSegment(t, *token, 2); !bytes.Equal(got, tt.want) {
				t.Errorf("[RFC 7518 3.4 step 2] want %x, got %x", tt.want, got)
			}
		})
	}
}

func TestNew_RefusesAStandardLibrarySignerThatCannotSignTheAlgorithm(t *testing.T) {
	p256 := newTestECDSAKey(t, elliptic.P256())
	p384 := newTestECDSAKey(t, elliptic.P384())
	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generating an rsa key: %s", err)
	}
	p521 := newTestECDSAKey(t, elliptic.P521())
	oversized := new(big.Int).Lsh(big.NewInt(1), 256)
	p256Order := elliptic.P256().Params().N
	p521Order := elliptic.P521().Params().N
	widest528 := new(big.Int).Sub(new(big.Int).Lsh(big.NewInt(1), 528), big.NewInt(1))
	der := func(r, s *big.Int) fixedOutputSigner {
		return fixedOutputSigner{public: &p256.PublicKey, output: newTestDER(t, r, s)}
	}
	derP521 := func(r, s *big.Int) fixedOutputSigner {
		return fixedOutputSigner{public: &p521.PublicKey, output: newTestDER(t, r, s)}
	}
	threeIntegers, err := asn1.Marshal(struct{ R, S, X *big.Int }{big.NewInt(1), big.NewInt(2), big.NewInt(3)})
	if err != nil {
		t.Fatalf("marshalling: %s", err)
	}

	tests := []struct {
		name   string
		signer crypto.Signer
		alg    jwa.Algorithm
		want   error
		clause string
	}{
		{name: "ES256 with a P-384 key", signer: p384, alg: jwa.ES256, want: joseerror.ErrInvalidPrivateKey, clause: "RFC 7518 3.4"},
		{name: "ES384 with a P-256 key", signer: p256, alg: jwa.ES384, want: joseerror.ErrInvalidPrivateKey, clause: "RFC 7518 3.4"},
		{name: "ES256 with an rsa key", signer: rsaKey, alg: jwa.ES256, want: joseerror.ErrInvalidPrivateKey, clause: "RFC 7518 3.4"},
		{name: "PS256 with an ecdsa key", signer: p256, alg: jwa.PS256, want: joseerror.ErrInvalidPrivateKey, clause: "RFC 7518 3.5"},
		{name: "RS256 with an ecdsa key", signer: p256, alg: jwa.RS256, want: joseerror.ErrInvalidPrivateKey, clause: "RFC 7518 3.3"},
		{name: "EdDSA with an ecdsa key", signer: p256, alg: jwa.EdDSA, want: joseerror.ErrInvalidPrivateKey, clause: "RFC 8037 3.1"},
		{name: "HS256 with an ecdsa key", signer: p256, alg: jwa.HS256, want: joseerror.ErrInvalidPrivateKey, clause: "RFC 7518 3.2"},
		{name: "HS256 with an rsa key", signer: rsaKey, alg: jwa.HS256, want: joseerror.ErrInvalidPrivateKey, clause: "RFC 7518 3.2"},
		{name: "ES256 output that is empty", signer: fixedOutputSigner{public: &p256.PublicKey, output: []byte{}}, alg: jwa.ES256, want: joseerror.ErrSigningError, clause: "RFC 7518 3.4"},
		{name: "ES256 output that is not DER", signer: fixedOutputSigner{public: &p256.PublicKey, output: bytes.Repeat([]byte{1}, 64)}, alg: jwa.ES256, want: joseerror.ErrSigningError, clause: "RFC 7518 3.4"},
		{name: "ES256 DER followed by a trailing octet", signer: fixedOutputSigner{public: &p256.PublicKey, output: append(newTestDER(t, big.NewInt(1), big.NewInt(2)), 0)}, alg: jwa.ES256, want: joseerror.ErrSigningError, clause: "RFC 7518 3.4"},
		{name: "ES256 DER holding three integers", signer: fixedOutputSigner{public: &p256.PublicKey, output: threeIntegers}, alg: jwa.ES256, want: joseerror.ErrSigningError, clause: "RFC 7518 3.4"},
		{name: "ES256 DER with an R of zero", signer: der(big.NewInt(0), big.NewInt(2)), alg: jwa.ES256, want: joseerror.ErrSigningError, clause: "RFC 7518 3.4"},
		{name: "ES256 DER with a negative R", signer: der(big.NewInt(-1), big.NewInt(2)), alg: jwa.ES256, want: joseerror.ErrSigningError, clause: "RFC 7518 3.4"},
		{name: "ES256 DER with an S of zero", signer: der(big.NewInt(1), big.NewInt(0)), alg: jwa.ES256, want: joseerror.ErrSigningError, clause: "RFC 7518 3.4"},
		{name: "ES256 DER with an R of 257 bits", signer: der(oversized, big.NewInt(2)), alg: jwa.ES256, want: joseerror.ErrSigningError, clause: "RFC 7518 3.4"},
		{name: "ES256 DER with an S of 257 bits", signer: der(big.NewInt(1), oversized), alg: jwa.ES256, want: joseerror.ErrSigningError, clause: "RFC 7518 3.4"},
		{name: "ES256 DER with an R of n", signer: der(p256Order, big.NewInt(2)), alg: jwa.ES256, want: joseerror.ErrSigningError, clause: "FIPS 186-5 6.4.1"},
		{name: "ES256 DER with an S of n", signer: der(big.NewInt(1), p256Order), alg: jwa.ES256, want: joseerror.ErrSigningError, clause: "FIPS 186-5 6.4.1"},
		{name: "ES256 DER with an R of 2^256-1", signer: der(new(big.Int).Sub(oversized, big.NewInt(1)), big.NewInt(2)), alg: jwa.ES256, want: joseerror.ErrSigningError, clause: "FIPS 186-5 6.4.1"},
		{name: "ES512 DER with an R of n", signer: derP521(p521Order, big.NewInt(2)), alg: jwa.ES512, want: joseerror.ErrSigningError, clause: "FIPS 186-5 6.4.1"},
		{name: "ES512 DER with an S of n", signer: derP521(big.NewInt(1), p521Order), alg: jwa.ES512, want: joseerror.ErrSigningError, clause: "FIPS 186-5 6.4.1"},
		{name: "ES512 DER with an R of 528 bits", signer: derP521(widest528, big.NewInt(2)), alg: jwa.ES512, want: joseerror.ErrSigningError, clause: "FIPS 186-5 6.4.1"},
		{name: "ES512 DER with an S of 528 bits", signer: derP521(big.NewInt(1), widest528), alg: jwa.ES512, want: joseerror.ErrSigningError, clause: "FIPS 186-5 6.4.1"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			token, err := New(tt.signer, map[string]any{}, map[string]any{}, Opts{Algorithm: tt.alg})
			if err == nil {
				t.Fatalf("[%s] New emitted a token whose signature is not a %s signature: %s", tt.clause, tt.alg, *token)
			}
			if !errors.Is(err, tt.want) {
				t.Errorf("[%s] want %q, got %q", tt.clause, tt.want, err)
			}
		})
	}
}

func TestNew_DoesNotWriteIntoTheCallersHead(t *testing.T) {
	es256Signer, err := es256.NewSigner()
	if err != nil {
		t.Fatalf("building an ES256 signer: %s", err)
	}
	stdlibKey := newTestECDSAKey(t, elliptic.P256())

	tests := []struct {
		name   string
		signer crypto.Signer
		head   map[string]any
	}{
		{name: "a signer of this library and a head with no alg or typ", signer: es256Signer, head: map[string]any{"kid": "k1"}},
		{name: "a standard library signer and a head with no alg or typ", signer: stdlibKey, head: map[string]any{"kid": "k1"}},
		{name: "a signer of this library and a head that already names alg", signer: es256Signer, head: map[string]any{"alg": "ES256"}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			before := maps.Clone(tt.head)
			body := map[string]any{"sub": "a"}
			if _, err := New(tt.signer, tt.head, body, Opts{Algorithm: jwa.ES256}); err != nil {
				t.Fatalf("New refused a consistent signer, head and opts: %s", err)
			}
			if !maps.Equal(tt.head, before) {
				t.Errorf("[jwt.New does not modify its arguments] the caller's head was %v and is now %v", before, tt.head)
			}
			if !maps.Equal(body, map[string]any{"sub": "a"}) {
				t.Errorf("[jwt.New does not modify its arguments] the caller's body is now %v", body)
			}
		})
	}
}

func TestNew_IsSafeToCallConcurrentlyWithOneHead(t *testing.T) {
	signer, err := es256.NewSigner()
	if err != nil {
		t.Fatalf("building an ES256 signer: %s", err)
	}
	head := map[string]any{"kid": "k1"}

	var wg sync.WaitGroup
	for i := 0; i < 16; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < 10; j++ {
				if _, err := New(signer, head, map[string]any{"sub": "a"}, Opts{}); err != nil {
					t.Errorf("New refused a consistent signer and head: %s", err)
				}
			}
		}()
	}
	wg.Wait()
	if !maps.Equal(head, map[string]any{"kid": "k1"}) {
		t.Errorf("[jwt.New does not modify its arguments] the shared head is now %v", head)
	}
}

func TestNew_ANilHeadIsAnEmptyHeader(t *testing.T) {
	es256Signer, err := es256.NewSigner()
	if err != nil {
		t.Fatalf("building an ES256 signer: %s", err)
	}

	tests := []struct {
		name   string
		signer crypto.Signer
		opts   Opts
	}{
		{name: "a signer of this library", signer: es256Signer},
		{name: "a standard library signer", signer: newTestECDSAKey(t, elliptic.P256()), opts: Opts{Algorithm: jwa.ES256}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			token, err := New(tt.signer, nil, map[string]any{"sub": "a"}, tt.opts)
			if err != nil {
				t.Fatalf("[RFC 7515 4] New refused a nil head, which holds no members: %s", err)
			}
			want := map[string]any{"alg": "ES256", "typ": "JWT"}
			if got := newTestHeader(t, *token); !maps.Equal(got, want) {
				t.Errorf("[RFC 7515 4.1.1] want header %v, got %v", want, got)
			}
		})
	}
}

func TestNew_ANilBodyIsAnEmptyClaimsSet(t *testing.T) {
	signer, err := es256.NewSigner()
	if err != nil {
		t.Fatalf("building an ES256 signer: %s", err)
	}

	token, err := New(signer, map[string]any{}, nil, Opts{})
	if err != nil {
		t.Fatalf("[RFC 7519 4] New refused a nil body, which holds no claims: %s", err)
	}
	if payload := newTestSegment(t, *token, 1); string(payload) != "{}" {
		t.Errorf("[RFC 7519 4] the JWT Claims Set must be a JSON object, got %s", payload)
	}
	_, body, err := Validate(context.Background(), *token, newTestRetriever(signer.Public()), nil)
	if err != nil {
		t.Fatalf("[RFC 7519 7.2] the token does not validate: %s", err)
	}
	if body == nil || len(body) != 0 {
		t.Errorf("[RFC 7519 7.2 step 10] want an empty claims set, got %v", body)
	}
}
