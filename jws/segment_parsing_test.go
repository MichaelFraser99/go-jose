package jws

import (
	"bytes"
	"context"
	"crypto"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/MichaelFraser99/go-jose/joseerror"
	"github.com/MichaelFraser99/go-jose/jwa"
	"github.com/MichaelFraser99/go-jose/model"
)

const base64urlAlphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"

type segmentSigner struct {
	signer    model.Signer
	retriever model.Retriever
	calls     *atomic.Int32
}

func newSegmentSigner(t *testing.T) segmentSigner {
	t.Helper()
	signer, err := GetSigner(jwa.ES256, nil)
	if err != nil {
		t.Fatal(err)
	}
	calls := &atomic.Int32{}
	return segmentSigner{
		signer: signer,
		calls:  calls,
		retriever: func() ([]crypto.PublicKey, error) {
			calls.Add(1)
			return []crypto.PublicKey{signer.Public()}, nil
		},
	}
}

func (s segmentSigner) signSegments(t *testing.T, header, payload string) string {
	t.Helper()
	input := header + "." + payload
	signature, err := s.signer.Sign(rand.Reader, []byte(input), nil)
	if err != nil {
		t.Fatal(err)
	}
	return input + "." + base64.RawURLEncoding.EncodeToString(signature)
}

func (s segmentSigner) sign(t *testing.T, header, payload []byte) string {
	t.Helper()
	return s.signSegments(t, base64.RawURLEncoding.EncodeToString(header), base64.RawURLEncoding.EncodeToString(payload))
}

func flipPadBit(t *testing.T, segment string) string {
	t.Helper()
	if len(segment)%4 == 0 {
		t.Fatalf("segment %q has no unused bits in its last character", segment)
	}
	last := strings.IndexByte(base64urlAlphabet, segment[len(segment)-1])
	flipped := segment[:len(segment)-1] + string(base64urlAlphabet[last^1])
	lenient, err := base64.RawURLEncoding.DecodeString(flipped)
	if err != nil {
		t.Fatal(err)
	}
	canonical, err := base64.RawURLEncoding.DecodeString(segment)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(lenient, canonical) {
		t.Fatalf("flipping the last bit of %q changed the decoded octets, so it was not a pad bit", segment)
	}
	return flipped
}

func insertAt(segment string, extra string) string {
	cut := len(segment) / 2
	return segment[:cut] + extra + segment[cut:]
}

func TestVerify_RefusesASegmentThatIsNotExactlyBase64url(t *testing.T) {
	s := newSegmentSigner(t)
	header := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"ES256","kid":"a"}`))
	payload := base64.RawURLEncoding.EncodeToString([]byte(`{"sub":"a"}`))

	signed := func(h, p string) func(t *testing.T) string {
		return func(t *testing.T) string { return s.signSegments(t, h, p) }
	}
	signatureEdited := func(edit func(t *testing.T, sig string) string) func(t *testing.T) string {
		return func(t *testing.T) string {
			token := s.signSegments(t, header, payload)
			dot := strings.LastIndexByte(token, '.')
			return token[:dot+1] + edit(t, token[dot+1:])
		}
	}

	tests := map[string]struct {
		token  func(t *testing.T) string
		clause string
	}{
		"header with non-zero pad bits, signed as sent":  {signed(flipPadBit(t, header), payload), "RFC 7515 2, RFC 4648 3.5"},
		"payload with non-zero pad bits, signed as sent": {signed(header, flipPadBit(t, payload)), "RFC 7515 2, RFC 4648 3.5"},
		"signature with non-zero pad bits":               {signatureEdited(func(t *testing.T, sig string) string { return flipPadBit(t, sig) }), "RFC 7515 2, RFC 4648 3.5"},
	}
	for name, extra := range map[string]string{"LF": "\n", "CRLF": "\r\n", "CR": "\r", "space": " ", "tab": "\t", "padding": "=", "standard alphabet plus": "+", "standard alphabet slash": "/"} {
		tests["header containing "+name+", signed as sent"] = struct {
			token  func(t *testing.T) string
			clause string
		}{signed(insertAt(header, extra), payload), "RFC 7515 5.2 step 2"}
		tests["payload containing "+name+", signed as sent"] = struct {
			token  func(t *testing.T) string
			clause string
		}{signed(header, insertAt(payload, extra)), "RFC 7515 5.2 step 6"}
		tests["signature containing "+name] = struct {
			token  func(t *testing.T) string
			clause string
		}{signatureEdited(func(t *testing.T, sig string) string { return insertAt(sig, extra) }), "RFC 7515 5.2 step 7"}
	}

	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			token := test.token(t)
			_, _, err := Verify(context.Background(), token, s.retriever, nil)
			if !errors.Is(err, joseerror.ErrMalformedToken) {
				t.Errorf("[%s] Verify accepted or misclassified %q: %v", test.clause, token, err)
			}
			_, _, err = VerifyCompactSerialization(context.Background(), token, s.retriever, nil)
			if !errors.Is(err, joseerror.ErrMalformedToken) {
				t.Errorf("[%s] VerifyCompactSerialization accepted or misclassified %q: %v", test.clause, token, err)
			}
		})
	}

	t.Run("the canonical encoding verifies", func(t *testing.T) {
		if _, _, err := VerifyCompactSerialization(context.Background(), s.signSegments(t, header, payload), s.retriever, nil); err != nil {
			t.Fatalf("[RFC 7515 5.2] the canonical token was refused: %v", err)
		}
	})
}

func TestVerifyCompactSerialization_RefusesAHeaderOrClaimsSetThatIsNotAUTF8JSONObject(t *testing.T) {
	s := newSegmentSigner(t)
	tests := map[string]struct {
		header, payload string
		clause          string
	}{
		"header holding the byte 0xff":                    {"{\"alg\":\"ES256\",\"kid\":\"k\xff\"}", `{"sub":"a"}`, "RFC 7515 5.2 step 3, RFC 8725 3.7"},
		"header holding a lone surrogate encoded as CESU": {"{\"alg\":\"ES256\",\"kid\":\"\xed\xa0\x80\"}", `{"sub":"a"}`, "RFC 7515 5.2 step 3, RFC 8725 3.7"},
		"payload holding the byte 0xff":                   {`{"alg":"ES256"}`, "{\"sub\":\"a\xffb\"}", "RFC 7519 7.2 step 10, RFC 8725 3.7"},
		"header of null":                                  {`null`, `{"sub":"a"}`, "RFC 7515 5.2 step 3"},
		"payload of null":                                 {`{"alg":"ES256"}`, `null`, "RFC 7519 7.2 step 10"},
		"payload of null within spaces":                   {`{"alg":"ES256"}`, ` null `, "RFC 7519 7.2 step 10"},
		"payload of an array":                             {`{"alg":"ES256"}`, `[1,2]`, "RFC 7519 7.2 step 10"},
	}
	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			token := s.sign(t, []byte(test.header), []byte(test.payload))
			head, body, err := VerifyCompactSerialization(context.Background(), token, s.retriever, nil)
			if !errors.Is(err, joseerror.ErrMalformedToken) {
				t.Fatalf("[%s] accepted or misclassified: header=%v body=%v (nil=%t) err=%v", test.clause, head, body, body == nil, err)
			}
		})
	}
}

func TestVerify_ReturnsTheSignedPayloadOctetsUnparsed(t *testing.T) {
	s := newSegmentSigner(t)
	for name, payload := range map[string][]byte{
		"text":                     []byte("It's a dangerous business, Frodo, going out your door."),
		"binary":                   {0x00, 0xff, 0x10},
		"empty":                    {},
		"array":                    []byte(`[1,2]`),
		"null":                     []byte(`null`),
		"object":                   []byte(`{"sub":"a"}`),
		"bytes that are not UTF-8": {'a', 0xff, 'b'},
	} {
		t.Run(name, func(t *testing.T) {
			token := s.sign(t, []byte(`{"alg":"ES256"}`), payload)
			head, got, err := Verify(context.Background(), token, s.retriever, nil)
			if err != nil {
				t.Fatalf("[RFC 7515 2 'The payload can contain an arbitrary sequence of octets'] validly signed payload refused: %v", err)
			}
			if !bytes.Equal(got, payload) {
				t.Errorf("[RFC 7515 5.2 step 6] payload returned as %x, signed as %x", got, payload)
			}
			if head["alg"] != "ES256" {
				t.Errorf("[RFC 7515 5.2 step 3] header returned as %v", head)
			}
		})
	}
}

func TestVerify_RefusesWhatVerifyCompactSerializationRefusesAboutTheSignature(t *testing.T) {
	s := newSegmentSigner(t)
	other := newSegmentSigner(t)
	token := other.sign(t, []byte(`{"alg":"ES256"}`), []byte("octets"))
	head, payload, err := Verify(context.Background(), token, s.retriever, nil)
	if !errors.Is(err, joseerror.ErrInvalidSignature) {
		t.Fatalf("[RFC 7515 5.2 step 8] a payload signed by another key was returned: header=%v payload=%q err=%v", head, payload, err)
	}
	if head != nil || payload != nil {
		t.Errorf("[RFC 7515 5.2] a refused token still returned header=%v payload=%q", head, payload)
	}
}

func TestVerify_RefusesAnUnencodedPayloadWhateverTheCallerUnderstands(t *testing.T) {
	s := newSegmentSigner(t)
	tests := map[string]struct {
		header string
		opts   *model.JoseOptions
	}{
		"b64 false, crit b64, caller lists b64": {`{"alg":"ES256","b64":false,"crit":["b64"]}`, &model.JoseOptions{UnderstoodCriticalHeaders: []string{"b64"}}},
		"b64 false without crit":                {`{"alg":"ES256","b64":false}`, nil},
	}
	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			token := s.signSegments(t, base64.RawURLEncoding.EncodeToString([]byte(test.header)), "e30")
			if _, payload, err := Verify(context.Background(), token, s.retriever, test.opts); !errors.Is(err, joseerror.ErrMissingCriticalClaim) {
				t.Errorf("[RFC 7797 3, 8] literal payload \"e30\" was read as %q: %v", payload, err)
			}
			if _, body, err := VerifyCompactSerialization(context.Background(), token, s.retriever, test.opts); !errors.Is(err, joseerror.ErrMissingCriticalClaim) {
				t.Errorf("[RFC 7797 3, 8] literal payload \"e30\" was read as %v: %v", body, err)
			}
			if calls := s.calls.Load(); calls != 0 {
				t.Errorf("[RFC 7515 5.2 step 5] the key retriever ran %d time(s) for a header this library cannot process", calls)
			}
		})
	}

	t.Run("b64 true with crit b64 the caller lists is the default encoding", func(t *testing.T) {
		token := s.sign(t, []byte(`{"alg":"ES256","b64":true,"crit":["b64"]}`), []byte(`{"sub":"a"}`))
		if _, _, err := VerifyCompactSerialization(context.Background(), token, s.retriever, &model.JoseOptions{UnderstoodCriticalHeaders: []string{"b64"}}); err != nil {
			t.Fatalf("[RFC 7797 3] b64 true names the default encoding and was refused: %v", err)
		}
	})
}

func TestVerifyCompactSerialization_RefusesANestedJWTBeforeTouchingAKey(t *testing.T) {
	s := newSegmentSigner(t)
	inner := s.sign(t, []byte(`{"alg":"ES256","typ":"JWT"}`), []byte(`{"sub":"inner"}`))
	for _, cty := range []string{"JWT", "jwt", "application/jwt", "Application/JWT"} {
		t.Run(cty, func(t *testing.T) {
			s.calls.Store(0)
			header, _ := json.Marshal(map[string]any{"alg": "ES256", "cty": cty})
			token := s.sign(t, header, []byte(inner))
			_, _, err := VerifyCompactSerialization(context.Background(), token, s.retriever, nil)
			if !errors.Is(err, joseerror.ErrMalformedToken) || !strings.Contains(err.Error(), "nested JWTs are not supported") {
				t.Errorf("[RFC 7519 5.2, 7.2 step 8] cty %q was not refused as an unsupported nested JWT: %v", cty, err)
			}
			if calls := s.calls.Load(); calls != 0 {
				t.Errorf("[RFC 7519 7.2 step 8] the key retriever ran %d time(s) for a nested JWT this library refuses", calls)
			}
			if _, payload, err := Verify(context.Background(), token, s.retriever, nil); err != nil || string(payload) != inner {
				t.Errorf("[RFC 7515 4.1.10 'This parameter is ignored by JWS implementations'] Verify returned %q, %v", payload, err)
			}
		})
	}

	for _, cty := range []string{"example", "application/example+jwt", "x-jwt"} {
		t.Run("cty "+cty+" is not nesting", func(t *testing.T) {
			header, _ := json.Marshal(map[string]any{"alg": "ES256", "cty": cty})
			token := s.sign(t, header, []byte(`{"sub":"a"}`))
			if _, _, err := VerifyCompactSerialization(context.Background(), token, s.retriever, nil); err != nil {
				t.Errorf("[RFC 7515 4.1.10] cty %q names no nesting and was refused: %v", cty, err)
			}
		})
	}
}

func TestVerify_RefusesAnAlgorithmWithNoValidatorBeforeAnyFetch(t *testing.T) {
	var hits atomic.Int32
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		_, _ = w.Write([]byte(`{"keys":[]}`))
	}))
	defer server.Close()

	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	header, _ := json.Marshal(map[string]any{"alg": "EdDSA", "jku": server.URL + "/jwks", "jwk": map[string]any{"kty": "OKP", "crv": "Ed25519", "x": base64.RawURLEncoding.EncodeToString(public)}})
	input := base64.RawURLEncoding.EncodeToString(header) + "." + base64.RawURLEncoding.EncodeToString([]byte(`{"sub":"a"}`))
	token := input + "." + base64.RawURLEncoding.EncodeToString(ed25519.Sign(private, []byte(input)))

	var retrieverCalls atomic.Int32
	retriever := func() ([]crypto.PublicKey, error) {
		retrieverCalls.Add(1)
		return []crypto.PublicKey{public}, nil
	}
	opts := &model.JoseOptions{HttpClient: server.Client(), UseTokenProvidedKeys: true}

	for name, verify := range map[string]func() error{
		"Verify": func() error {
			_, _, err := Verify(context.Background(), token, retriever, opts)
			return err
		},
		"VerifyCompactSerialization": func() error {
			_, _, err := VerifyCompactSerialization(context.Background(), token, retriever, opts)
			return err
		},
	} {
		t.Run(name, func(t *testing.T) {
			err := verify()
			if !errors.Is(err, joseerror.ErrUnsupportedAlgorithm) {
				t.Errorf("[RFC 7515 4.1.1] an alg with no validator was reported as %v, not ErrUnsupportedAlgorithm", err)
			}
			if err != nil && !strings.Contains(err.Error(), strconv.Quote("EdDSA")+" has no validator") {
				t.Errorf("[RFC 7515 4.1.1] the refusal does not name the algorithm: %v", err)
			}
			if hits.Load() != 0 || retrieverCalls.Load() != 0 {
				t.Errorf("[RFC 7515 5.2 step 5] an alg with no validator still caused %d fetch(es) and %d retriever call(s)", hits.Load(), retrieverCalls.Load())
			}
		})
	}
}

func TestVerify_HeaderErrorsQuoteAndBoundThePeersValue(t *testing.T) {
	injected := "\r\nX-Injected: 1\r\n" + strings.Repeat("A", 4096)
	echoCap := 64
	tests := map[string]struct {
		header map[string]any
		opts   *model.JoseOptions
		echoed string
	}{
		"alg":      {map[string]any{"alg": injected}, nil, injected},
		"jku":      {map[string]any{"alg": "ES256", "jku": "http://" + injected}, nil, "http://" + injected},
		"x5u":      {map[string]any{"alg": "ES256", "x5u": "http://" + injected}, nil, "http://" + injected},
		"x5t":      {map[string]any{"alg": "ES256", "x5t": injected}, nil, injected},
		"x5t#S256": {map[string]any{"alg": "ES256", "x5t#S256": injected}, nil, injected},
		"typ":      {map[string]any{"alg": "ES256", "typ": injected}, &model.JoseOptions{AcceptedTypes: []string{"JWT"}}, injected},
		"crit":     {map[string]any{"alg": "ES256", "crit": []any{injected}, injected: true}, nil, injected},
	}
	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			header, err := json.Marshal(test.header)
			if err != nil {
				t.Fatal(err)
			}
			token := base64.RawURLEncoding.EncodeToString(header) + ".e30.AA"
			_, _, err = Verify(context.Background(), token, nil, test.opts)
			if err == nil {
				t.Fatal("[RFC 7515 5.2] the header was accepted")
			}
			message := err.Error()
			if strings.ContainsAny(message, "\r\n") {
				t.Errorf("[RFC 7515 5.2] the error carries the peer's raw CR or LF: %q", message)
			}
			if want := strconv.Quote(test.echoed[:echoCap]); !strings.Contains(message, want) {
				t.Errorf("[RFC 7515 5.2] the error does not quote the first %d characters of the value as %s: %q", echoCap, want, message)
			}
			if strings.Contains(message, strconv.Quote(test.echoed[:echoCap+1])) {
				t.Errorf("[RFC 7515 5.2] the error echoes more than %d characters of the peer's value: %d bytes", echoCap, len(message))
			}
		})
	}
}
