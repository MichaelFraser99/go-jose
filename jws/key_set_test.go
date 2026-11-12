package jws_test

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/MichaelFraser99/go-jose/joseerror"
	"github.com/MichaelFraser99/go-jose/jwa"
	"github.com/MichaelFraser99/go-jose/jws"
	"github.com/MichaelFraser99/go-jose/model"
)

func keySetSigner(t *testing.T) *ecdsa.PrivateKey {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return key
}

func keySetToken(t *testing.T, signer model.Signer, header map[string]any) string {
	t.Helper()
	header["alg"] = signer.Alg().String()
	head, err := json.Marshal(header)
	if err != nil {
		t.Fatal(err)
	}
	input := base64.RawURLEncoding.EncodeToString(head) + "." + base64.RawURLEncoding.EncodeToString([]byte(`{"sub":"alice"}`))
	signature, err := signer.Sign(rand.Reader, []byte(input), nil)
	if err != nil {
		t.Fatal(err)
	}
	return input + "." + base64.RawURLEncoding.EncodeToString(signature)
}

func es256Signer(t *testing.T, key *ecdsa.PrivateKey) model.Signer {
	t.Helper()
	signer, err := jws.GetSignerFromPrivateKey(jwa.ES256, key)
	if err != nil {
		t.Fatal(err)
	}
	return signer
}

func wrongMembers(t *testing.T, n int, extra func(i int) map[string]any) []map[string]any {
	t.Helper()
	members := make([]map[string]any, n)
	for i := range members {
		members[i] = selectionJwk(&keySetSigner(t).PublicKey, extra(i))
	}
	return members
}

func TestVerify_KeySetSelectsTheKeyForTheToken(t *testing.T) {
	right := keySetSigner(t)
	signer := es256Signer(t, right)
	public := &right.PublicKey
	hugeKid := strings.Repeat("ключ-🔑", 50_000)

	tests := map[string]struct {
		members  []map[string]any
		header   map[string]any
		opts     model.JoseOptions
		verifies bool
		clause   string
	}{
		"the token's kid selects one key among many, so the others cost no verification": {
			members:  append(wrongMembers(t, 20, func(i int) map[string]any { return map[string]any{"kid": fmt.Sprintf("wrong-%d", i)} }), selectionJwk(public, map[string]any{"kid": "right"})),
			header:   map[string]any{"kid": "right"},
			opts:     model.JoseOptions{MaxKeysTried: 1},
			verifies: true, clause: "RFC 7515 4.1.4",
		},
		"a member with no kid is tried for a token naming any kid": {
			members:  []map[string]any{selectionJwk(public, nil)},
			header:   map[string]any{"kid": "anything"},
			verifies: true, clause: "RFC 7515 4.1.4",
		},
		"a token with no kid is checked against every member": {
			members:  append(wrongMembers(t, 3, func(i int) map[string]any { return map[string]any{"kid": fmt.Sprintf("wrong-%d", i)} }), selectionJwk(public, map[string]any{"kid": "right"})),
			header:   map[string]any{},
			verifies: true, clause: "RFC 7515 4.1.4",
		},
		"a member whose kid differs from the token's is not used": {
			members: []map[string]any{selectionJwk(public, map[string]any{"kid": "a"})},
			header:  map[string]any{"kid": "b"},
			clause:  "RFC 7515 4.1.4",
		},
		"a kid is compared case-sensitively": {
			members: []map[string]any{selectionJwk(public, map[string]any{"kid": "KEY"})},
			header:  map[string]any{"kid": "key"},
			clause:  "RFC 7515 4.1.4",
		},
		"a member published for the token's alg is used": {
			members:  []map[string]any{selectionJwk(public, map[string]any{"alg": "ES256"})},
			header:   map[string]any{},
			verifies: true, clause: "RFC 8725 3.1",
		},
		"a member published for another alg is not used": {
			members: []map[string]any{selectionJwk(public, map[string]any{"alg": "ES384"})},
			header:  map[string]any{},
			clause:  "RFC 8725 3.1",
		},
		"a member whose use is enc is not used": {
			members: []map[string]any{selectionJwk(public, map[string]any{"use": "enc"})},
			header:  map[string]any{},
			clause:  "RFC 7517 4.2",
		},
		"a member whose use is enc is used with IgnoreKeyUse": {
			members:  []map[string]any{selectionJwk(public, map[string]any{"use": "enc"})},
			header:   map[string]any{},
			opts:     model.JoseOptions{IgnoreKeyUse: true},
			verifies: true, clause: "RFC 7517 4.2",
		},
		"a member whose key_ops lacks verify is not used": {
			members: []map[string]any{selectionJwk(public, map[string]any{"key_ops": []any{"sign"}})},
			header:  map[string]any{},
			clause:  "RFC 7517 4.3",
		},
		"a member carrying both use and key_ops is used by default": {
			members:  []map[string]any{selectionJwk(public, map[string]any{"use": "sig", "key_ops": []any{"verify"}})},
			header:   map[string]any{},
			verifies: true, clause: "RFC 7517 4.3",
		},
		"a member carrying both use and key_ops is not used with StrictKeyOperations": {
			members: []map[string]any{selectionJwk(public, map[string]any{"use": "sig", "key_ops": []any{"verify"}})},
			header:  map[string]any{},
			opts:    model.JoseOptions{StrictKeyOperations: true},
			clause:  "RFC 7517 4.3",
		},
		"an empty set selects no key": {
			members: []map[string]any{},
			header:  map[string]any{},
			clause:  "RFC 7517 5",
		},
		"a set with nil Keys selects no key": {
			members: nil,
			header:  map[string]any{},
			clause:  "RFC 7517 5",
		},
		"members this library cannot read are skipped and a readable one still verifies": {
			members: []map[string]any{
				{},
				{"kty": 5},
				{"kty": "unknown"},
				{"kty": "EC", "crv": "P-256", "x": "!!", "y": "!!"},
				{"kty": "EC", "crv": "P-256"},
				{"kty": "RSA", "n": []any{}, "e": map[string]any{}},
				selectionJwk(public, map[string]any{"kid": 7}),
				selectionJwk(public, map[string]any{"alg": nil}),
				selectionJwk(public, map[string]any{"use": []any{"sig"}}),
				selectionJwk(public, map[string]any{"key_ops": "verify"}),
				selectionJwk(public, nil),
			},
			header:   map[string]any{},
			verifies: true, clause: "RFC 7517 5",
		},
		"a set of members this library cannot read selects no key": {
			members: []map[string]any{{}, {"kty": nil}, {"kty": "unknown"}, {"kty": "EC", "crv": "P-256", "x": "!!", "y": "!!"}},
			header:  map[string]any{},
			clause:  "RFC 7517 5",
		},
		"a huge unicode kid selects the member carrying it": {
			members:  []map[string]any{selectionJwk(&keySetSigner(t).PublicKey, map[string]any{"kid": hugeKid + "x"}), selectionJwk(public, map[string]any{"kid": hugeKid})},
			header:   map[string]any{"kid": hugeKid},
			opts:     model.JoseOptions{MaxKeysTried: 1},
			verifies: true, clause: "RFC 7515 4.1.4",
		},
		"a huge unicode kid no member carries selects no key": {
			members: []map[string]any{selectionJwk(public, map[string]any{"kid": "right"})},
			header:  map[string]any{"kid": hugeKid},
			clause:  "RFC 7515 4.1.4",
		},
	}
	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			opts := tc.opts
			opts.KeySet = &model.Jwks{Keys: tc.members}
			token := keySetToken(t, signer, tc.header)
			_, body, err := jws.VerifyCompactSerialization(context.Background(), token, nil, &opts)
			if tc.verifies {
				if err != nil || body["sub"] != "alice" {
					t.Fatalf("[%s] the right member of the caller's key set must verify the token, got %v", tc.clause, err)
				}
				return
			}
			if !errors.Is(err, joseerror.ErrInvalidSignature) || !errors.Is(err, joseerror.ErrNoKeyIdentifierMatch) {
				t.Fatalf("[%s] a token no member of the key set is selected for is an invalid signature matching ErrNoKeyIdentifierMatch, got %v", tc.clause, err)
			}
			if len(err.Error()) > 1024 {
				t.Errorf("[%s] the refusal must not echo a peer-sized kid, got %d bytes", tc.clause, len(err.Error()))
			}
		})
	}
}

func TestVerify_KeySetNeverSelectsAnOctMember(t *testing.T) {
	secret := make([]byte, 32)
	if _, err := rand.Read(secret); err != nil {
		t.Fatal(err)
	}
	signer, err := jws.GetSigner(jwa.HS256, &model.Opts{SecretKey: &secret})
	if err != nil {
		t.Fatal(err)
	}
	token := keySetToken(t, signer, map[string]any{"kid": "hmac"})
	octMember := map[string]any{"kty": "oct", "kid": "hmac", "k": base64.RawURLEncoding.EncodeToString(secret)}
	opts := &model.JoseOptions{KeySet: &model.Jwks{Keys: []map[string]any{octMember}}}

	_, _, err = jws.VerifyCompactSerialization(context.Background(), token, nil, opts)
	if !errors.Is(err, joseerror.ErrInvalidSignature) || !errors.Is(err, joseerror.ErrNoKeyIdentifierMatch) {
		t.Errorf("[RFC 7518 6.4] an oct member is a secret with no public half, so it never verifies through the key set, got %v", err)
	}

	_, _, err = jws.VerifyCompactSerialization(context.Background(), token, func() ([]crypto.PublicKey, error) { return []crypto.PublicKey{signer.Public()}, nil }, opts)
	if err != nil {
		t.Errorf("[RFC 7518 3.2] an HMAC token still verifies with a retriever beside the key set, got %v", err)
	}
}

func TestVerify_KeySetAloneIsAKeySource(t *testing.T) {
	right := keySetSigner(t)
	token := keySetToken(t, es256Signer(t, right), map[string]any{"kid": "nobody"})
	for name, keys := range map[string][]map[string]any{"empty": {}, "nil": nil, "unmatched": {selectionJwk(&right.PublicKey, map[string]any{"kid": "other"})}} {
		t.Run(name, func(t *testing.T) {
			_, _, err := jws.Verify(context.Background(), token, nil, &model.JoseOptions{KeySet: &model.Jwks{Keys: keys}})
			if errors.Is(err, joseerror.ErrInvalidOptions) {
				t.Fatalf("[RFC 7517 5] a key set is a source of keys, so options holding only one are not wrong, got %v", err)
			}
			if !errors.Is(err, joseerror.ErrInvalidSignature) || !errors.Is(err, joseerror.ErrNoKeyIdentifierMatch) {
				t.Errorf("[RFC 7515 5.2] a token the key set holds no key for is the token's fault, got %v", err)
			}
		})
	}

	_, _, err := jws.Verify(context.Background(), token, nil, &model.JoseOptions{})
	if !errors.Is(err, joseerror.ErrInvalidOptions) {
		t.Errorf("[JoseOptions.KeySet] a nil key set adds no key, so options with no source are still refused, got %v", err)
	}
}

func TestVerify_KeySetIsTriedAfterTheRetrieverAndBeforeTheTokensKeys(t *testing.T) {
	right := keySetSigner(t)
	wrong := keySetSigner(t)
	rightRetriever := func() ([]crypto.PublicKey, error) { return []crypto.PublicKey{&right.PublicKey}, nil }
	wrongRetriever := func() ([]crypto.PublicKey, error) { return []crypto.PublicKey{&wrong.PublicKey}, nil }
	rightSet := &model.Jwks{Keys: []map[string]any{selectionJwk(&right.PublicKey, nil)}}
	wrongSet := &model.Jwks{Keys: []map[string]any{selectionJwk(&wrong.PublicKey, nil)}}
	plain := keySetToken(t, es256Signer(t, right), map[string]any{})
	carrying := keySetToken(t, es256Signer(t, right), map[string]any{"jwk": selectionJwk(&right.PublicKey, nil)})

	tests := map[string]struct {
		token     string
		retriever model.Retriever
		opts      model.JoseOptions
		verifies  bool
		clause    string
	}{
		"the key set verifies when the retriever's key does not": {
			token: plain, retriever: wrongRetriever, opts: model.JoseOptions{KeySet: rightSet}, verifies: true, clause: "JoseOptions.KeySet",
		},
		"the retriever verifies when the key set's key does not": {
			token: plain, retriever: rightRetriever, opts: model.JoseOptions{KeySet: wrongSet}, verifies: true, clause: "JoseOptions.KeySet",
		},
		"the retriever is tried before the key set": {
			token: plain, retriever: rightRetriever, opts: model.JoseOptions{KeySet: wrongSet, MaxKeysTried: 1}, verifies: true, clause: "JoseOptions.MaxKeysTried",
		},
		"the retriever's key and the key set's share one bound": {
			token: plain, retriever: wrongRetriever, opts: model.JoseOptions{KeySet: rightSet, MaxKeysTried: 1}, clause: "JoseOptions.MaxKeysTried",
		},
		"the key set is tried before a key the token carries": {
			token: carrying, opts: model.JoseOptions{KeySet: wrongSet, UseTokenProvidedKeys: true, MaxKeysTried: 1}, clause: "JoseOptions.MaxKeysTried",
		},
		"a key set selecting no key passes on to a key the token carries": {
			token: carrying, opts: model.JoseOptions{KeySet: &model.Jwks{}, UseTokenProvidedKeys: true}, verifies: true, clause: "RFC 7515 4.1.3",
		},
	}
	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			_, _, err := jws.Verify(context.Background(), tc.token, tc.retriever, &tc.opts)
			if tc.verifies {
				if err != nil {
					t.Fatalf("[%s] the right key from one source must verify the token, got %v", tc.clause, err)
				}
				return
			}
			if !errors.Is(err, joseerror.ErrTooManyKeys) {
				t.Errorf("[%s] a wrong key tried first exhausts a bound of one, got %v", tc.clause, err)
			}
		})
	}
}

func TestVerify_KeySetKeysCountTowardsMaxKeysTried(t *testing.T) {
	right := keySetSigner(t)
	token := keySetToken(t, es256Signer(t, right), map[string]any{"kid": "shared"})
	members := append(wrongMembers(t, 3, func(int) map[string]any { return map[string]any{"kid": "shared"} }), selectionJwk(&right.PublicKey, map[string]any{"kid": "shared"}))

	for limit, verifies := range map[int]bool{3: false, 4: true} {
		t.Run(fmt.Sprint(limit), func(t *testing.T) {
			_, _, err := jws.Verify(context.Background(), token, nil, &model.JoseOptions{KeySet: &model.Jwks{Keys: members}, MaxKeysTried: limit})
			if verifies && err != nil {
				t.Fatalf("[RFC 7517 4.5] the 4th key under a shared kid is within a bound of 4, got %v", err)
			}
			if !verifies && !errors.Is(err, joseerror.ErrTooManyKeys) {
				t.Fatalf("[RFC 7517 4.5] the 4th key under a shared kid is beyond a bound of 3, got %v", err)
			}
		})
	}
}

func TestVerify_KeySetIsReadOnEveryCall(t *testing.T) {
	right := keySetSigner(t)
	token := keySetToken(t, es256Signer(t, right), map[string]any{"kid": "rotated"})
	opts := &model.JoseOptions{KeySet: &model.Jwks{}}

	if _, _, err := jws.Verify(context.Background(), token, nil, opts); !errors.Is(err, joseerror.ErrNoKeyIdentifierMatch) {
		t.Fatalf("[RFC 7517 5] an empty key set selects no key, got %v", err)
	}
	opts.KeySet.Keys = append(opts.KeySet.Keys, selectionJwk(&right.PublicKey, map[string]any{"kid": "rotated"}))
	if _, _, err := jws.Verify(context.Background(), token, nil, opts); err != nil {
		t.Fatalf("[JoseOptions.KeySet] a member added between calls is selected on the next call, got %v", err)
	}
	opts.KeySet.Keys = nil
	if _, _, err := jws.Verify(context.Background(), token, nil, opts); !errors.Is(err, joseerror.ErrNoKeyIdentifierMatch) {
		t.Fatalf("[JoseOptions.KeySet] a member removed between calls is not selected on the next call, got %v", err)
	}
}

func TestVerify_KeySetDoesNotAdmitTheTokensOwnKeys(t *testing.T) {
	right := keySetSigner(t)
	var fetched atomic.Int32
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		fetched.Add(1)
		_ = json.NewEncoder(w).Encode(model.Jwks{Keys: []map[string]any{selectionJwk(&right.PublicKey, nil)}})
	}))
	t.Cleanup(server.Close)

	for name, header := range map[string]map[string]any{
		"jwk": {"jwk": selectionJwk(&right.PublicKey, nil)},
		"jku": {"jku": server.URL},
	} {
		t.Run(name, func(t *testing.T) {
			token := keySetToken(t, es256Signer(t, right), header)
			_, _, err := jws.Verify(context.Background(), token, nil, &model.JoseOptions{KeySet: &model.Jwks{}, HttpClient: server.Client()})
			if !errors.Is(err, joseerror.ErrInvalidSignature) || !errors.Is(err, joseerror.ErrNoKeyIdentifierMatch) {
				t.Errorf("[RFC 7515 10.3] a key set is not UseTokenProvidedKeys, so a key the token names must not verify it, got %v", err)
			}
		})
	}
	if fetched.Load() != 0 {
		t.Errorf("[RFC 7515 10.3] a key set must not cause a fetch of the jku a token names, got %d fetches", fetched.Load())
	}
}

func TestVerify_KeySetDoesNotLoosenTheKidShape(t *testing.T) {
	right := keySetSigner(t)
	opts := &model.JoseOptions{KeySet: &model.Jwks{Keys: []map[string]any{selectionJwk(&right.PublicKey, nil)}}}
	for name, kid := range map[string]any{"number": 7, "object": map[string]any{"a": "b"}, "array": []any{"k"}, "null": nil, "bool": true} {
		t.Run(name, func(t *testing.T) {
			token := keySetToken(t, es256Signer(t, right), map[string]any{"kid": kid})
			_, _, err := jws.Verify(context.Background(), token, nil, opts)
			if !errors.Is(err, joseerror.ErrMalformedToken) {
				t.Errorf("[RFC 7515 4.1.4] a kid MUST be a string, so the token is malformed whatever key set is given, got %v", err)
			}
		})
	}
}
