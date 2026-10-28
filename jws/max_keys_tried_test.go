package jws_test

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"

	"github.com/MichaelFraser99/go-jose/joseerror"
	"github.com/MichaelFraser99/go-jose/jwa"
	"github.com/MichaelFraser99/go-jose/jwk"
	"github.com/MichaelFraser99/go-jose/jws"
	"github.com/MichaelFraser99/go-jose/model"
)

func wrongEd25519Keys(t *testing.T, n int) []crypto.PublicKey {
	t.Helper()
	keys := make([]crypto.PublicKey, n)
	for i := range keys {
		keys[i] = newEd25519Key(t).Public()
	}
	return keys
}

func TestVerify_TheKeysATokenIsCheckedAgainstAreBounded(t *testing.T) {
	signingKey := newEd25519Key(t)
	token := signWithHeader(t, jwa.Ed25519, signingKey, map[string]any{})
	right := signingKey.Public()

	tests := map[string]struct {
		opts       *model.JoseOptions
		wrongFirst int
		verifies   bool
		limit      int
	}{
		"the 100th key with no options":       {opts: nil, wrongFirst: 99, verifies: true},
		"the 101st key with no options":       {opts: nil, wrongFirst: 100, limit: 100},
		"the 100th key with an unset limit":   {opts: &model.JoseOptions{}, wrongFirst: 99, verifies: true},
		"the 101st key with an unset limit":   {opts: &model.JoseOptions{}, wrongFirst: 100, limit: 100},
		"the 101st key with a negative limit": {opts: &model.JoseOptions{MaxKeysTried: -1}, wrongFirst: 100, limit: 100},
		"the 3rd key with a limit of 3":       {opts: &model.JoseOptions{MaxKeysTried: 3}, wrongFirst: 2, verifies: true},
		"the 4th key with a limit of 3":       {opts: &model.JoseOptions{MaxKeysTried: 3}, wrongFirst: 3, limit: 3},
		"the 150th key with a limit of 150":   {opts: &model.JoseOptions{MaxKeysTried: 150}, wrongFirst: 149, verifies: true},
		"the 1st key with a limit of 1":       {opts: &model.JoseOptions{MaxKeysTried: 1}, wrongFirst: 0, verifies: true},
		"the 2nd key with a limit of 1":       {opts: &model.JoseOptions{MaxKeysTried: 1}, wrongFirst: 1, limit: 1},
	}
	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			keys := append(wrongEd25519Keys(t, tc.wrongFirst), right)
			_, _, err := jws.Verify(context.Background(), token, retrieving(keys...), tc.opts)
			if tc.verifies {
				if err != nil {
					t.Errorf("[JoseOptions.MaxKeysTried] the right key within the limit must verify the token, got %v", err)
				}
				return
			}
			if !errors.Is(err, joseerror.ErrTooManyKeys) {
				t.Fatalf("[JoseOptions.MaxKeysTried] a token needing more keys than the limit must be refused with ErrTooManyKeys, got %v", err)
			}
			if errors.Is(err, joseerror.ErrInvalidSignature) || errors.Is(err, joseerror.ErrApplicationError) {
				t.Errorf("[JoseOptions.MaxKeysTried] a limit refusing a peer's key set is neither a bad signature nor a fault of this side, got %v", err)
			}
			if !strings.Contains(err.Error(), "MaxKeysTried") || !strings.Contains(err.Error(), strconv.Itoa(tc.limit)) {
				t.Errorf("[JoseOptions.MaxKeysTried] the refusal must name the limit and its value %d, got %v", tc.limit, err)
			}
		})
	}
}

func TestVerify_AsManyWrongKeysAsTheLimitIsABadSignature(t *testing.T) {
	token := signWithHeader(t, jwa.Ed25519, newEd25519Key(t), map[string]any{})
	_, _, err := jws.Verify(context.Background(), token, retrieving(wrongEd25519Keys(t, 3)...), &model.JoseOptions{MaxKeysTried: 3})
	if !errors.Is(err, joseerror.ErrInvalidSignature) || errors.Is(err, joseerror.ErrTooManyKeys) {
		t.Errorf("[RFC 7515 5.2 step 8] three wrong keys within a limit of three is a signature that does not verify, got %v", err)
	}
}

func TestVerify_AKeyThatCannotBeUsedWithTheAlgDoesNotCountTowardTheLimit(t *testing.T) {
	signingKey := newEd25519Key(t)
	token := signWithHeader(t, jwa.Ed25519, signingKey, map[string]any{})
	var keys []crypto.PublicKey
	for range 10 {
		ecdsaKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		keys = append(keys, &ecdsaKey.PublicKey)
	}
	keys = append(keys, signingKey.Public())
	if _, _, err := jws.Verify(context.Background(), token, retrieving(keys...), &model.JoseOptions{MaxKeysTried: 1}); err != nil {
		t.Errorf("[JoseOptions.MaxKeysTried] a key no validator can be built from for the alg costs no verification, so it must not count, got %v", err)
	}
}

func TestVerify_TheLimitSpansEveryKeySource(t *testing.T) {
	signingKey := newEd25519Key(t)
	publicJwk, err := jwk.PublicJwk(signingKey.Public())
	if err != nil {
		t.Fatal(err)
	}
	token := signWithHeader(t, jwa.Ed25519, signingKey, map[string]any{"jwk": *publicJwk})
	opts := &model.JoseOptions{UseTokenProvidedKeys: true, MaxKeysTried: 3}

	if _, _, err := jws.Verify(context.Background(), token, retrieving(wrongEd25519Keys(t, 2)...), opts); err != nil {
		t.Errorf("[JoseOptions.MaxKeysTried] two keys from the retriever and the header's key make three, within the limit, got %v", err)
	}
	if _, _, err := jws.Verify(context.Background(), token, retrieving(wrongEd25519Keys(t, 3)...), opts); !errors.Is(err, joseerror.ErrTooManyKeys) {
		t.Errorf("[JoseOptions.MaxKeysTried] three keys from the retriever exhaust the limit before the header's key, got %v", err)
	}
}

func TestVerify_AJkuSetOfManyKeysUnderOneKidIsRefusedAtTheLimit(t *testing.T) {
	var members []map[string]any
	for _, key := range wrongEd25519Keys(t, 150) {
		member, err := jwk.PublicJwk(key.(ed25519.PublicKey))
		if err != nil {
			t.Fatal(err)
		}
		(*member)["kid"] = "shared"
		members = append(members, *member)
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

	head, err := json.Marshal(map[string]any{"alg": "Ed25519", "kid": "shared", "jku": server.URL})
	if err != nil {
		t.Fatal(err)
	}
	input := base64.RawURLEncoding.EncodeToString(head) + "." + base64.RawURLEncoding.EncodeToString([]byte(`{"sub":"test"}`))
	token := input + "." + base64.RawURLEncoding.EncodeToString(ed25519.Sign(newEd25519Key(t), []byte(input)))

	_, _, err = jws.Verify(context.Background(), token, nil, &model.JoseOptions{UseTokenProvidedKeys: true, HttpClient: server.Client()})
	if !errors.Is(err, joseerror.ErrTooManyKeys) {
		t.Errorf("[RFC 7517 4.5] a peer may publish many keys under one kid, so a set of 150 must stop at the default limit of 100, got %v", err)
	}
}
