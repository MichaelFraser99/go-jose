package jwk

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/MichaelFraser99/go-jose/internal/httputils"
	"github.com/MichaelFraser99/go-jose/joseerror"
	"github.com/MichaelFraser99/go-jose/model"
)

type member map[string]any

func p256Jwk(t *testing.T, extra member) (map[string]any, *ecdsa.PublicKey) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate a key: %v", err)
	}
	jwk := map[string]any{
		"kty": "EC",
		"crv": "P-256",
		"x":   base64.RawURLEncoding.EncodeToString(key.X.FillBytes(make([]byte, 32))),
		"y":   base64.RawURLEncoding.EncodeToString(key.Y.FillBytes(make([]byte, 32))),
	}
	for name, value := range extra {
		jwk[name] = value
	}
	return jwk, &key.PublicKey
}

func unreadable(extra member) member {
	m := member{"kty": "nonsense"}
	for name, value := range extra {
		m[name] = value
	}
	return m
}

type selectionCase struct {
	members      []member
	kid          *string
	ignoreKeyUse bool
	want         []int
	clause       string
}

func selectionCases() map[string]selectionCase {
	a := model.Pointer("a")
	return map[string]selectionCase{
		"a member whose alg differs is not used when no member names the header alg": {
			members: []member{{"kid": "a", "alg": "ES384"}}, kid: a, want: nil, clause: "RFC 8725 3.1",
		},
		"a member whose alg differs is dropped beside one whose alg matches": {
			members: []member{{"alg": "ES256"}, {"alg": "ES384"}}, want: []int{0}, clause: "RFC 8725 3.1",
		},
		"a member with no alg is kept beside one whose alg matches": {
			members: []member{{"kid": "old", "alg": "ES256"}, {"kid": "new"}}, want: []int{0, 1}, clause: "RFC 7517 4.4",
		},
		"a member whose alg is not a string is not used": {
			members: []member{{"alg": []any{"ES256"}}}, want: nil, clause: "RFC 7517 4.4",
		},
		"a header kid that matches no member selects no member": {
			members: []member{{"kid": "issued"}}, kid: model.Pointer("some-other-key"), want: nil, clause: "RFC 7515 4.1.4",
		},
		"a member whose kid differs is dropped beside one whose kid matches": {
			members: []member{{"kid": "a"}, {"kid": "b"}}, kid: a, want: []int{0}, clause: "RFC 7515 4.1.4",
		},
		"a member with no kid is kept when the header names a kid": {
			members: []member{{"kid": "a"}, {}}, kid: a, want: []int{0, 1}, clause: "RFC 7517 4.5",
		},
		"every member is kept when the header names no kid": {
			members: []member{{"kid": "a"}, {"kid": "b"}}, want: []int{0, 1}, clause: "RFC 7515 4.1.4",
		},
		"a member whose kid is not a string is not used": {
			members: []member{{"kid": 7}}, kid: model.Pointer("7"), want: nil, clause: "RFC 7517 4.5",
		},
		"an unreadable member naming the alg does not drop a readable member with no alg": {
			members: []member{unreadable(member{"kid": "a", "alg": "ES256"}), {"kid": "a"}}, kid: a, want: []int{1}, clause: "RFC 7517 5",
		},
		"an unreadable member naming the kid does not admit a readable member with another kid": {
			members: []member{unreadable(member{"kid": "z"}), {"kid": "b"}}, kid: a, want: nil, clause: "RFC 7515 4.1.4",
		},
		"an unreadable member naming the kid does not admit a readable member with another alg": {
			members: []member{unreadable(member{"kid": "a", "alg": "ES384"}), {"kid": "a", "alg": "ES384"}}, kid: a, want: nil, clause: "RFC 8725 3.1",
		},
		"a member marked use sig is used": {
			members: []member{{"use": "sig"}}, want: []int{0}, clause: "RFC 7517 4.2",
		},
		"a member marked use enc is not used": {
			members: []member{{"use": "enc"}}, want: nil, clause: "RFC 7517 4.2",
		},
		"a member marked use Sig is not used, since use is case-sensitive": {
			members: []member{{"use": "Sig"}}, want: nil, clause: "RFC 7517 4.2",
		},
		"a member whose use is not a string is not used": {
			members: []member{{"use": []any{"sig"}}}, want: nil, clause: "RFC 7517 4.2",
		},
		"a member whose key_ops include verify is used": {
			members: []member{{"key_ops": []any{"sign", "verify"}}}, want: []int{0}, clause: "RFC 7517 4.3",
		},
		"a member whose key_ops lack verify is not used": {
			members: []member{{"key_ops": []any{"encrypt"}}}, want: nil, clause: "RFC 7517 4.3",
		},
		"a member whose key_ops are empty is not used": {
			members: []member{{"key_ops": []any{}}}, want: nil, clause: "RFC 7517 4.3",
		},
		"a member whose key_ops is a string rather than an array is not used": {
			members: []member{{"key_ops": "verify"}}, want: nil, clause: "RFC 7517 4.3",
		},
		"a member whose key_ops hold a value that is not a string is not used": {
			members: []member{{"key_ops": []any{7, "verify"}}}, want: nil, clause: "RFC 7517 4.3",
		},
		"a member marked use sig whose key_ops lack verify is not used": {
			members: []member{{"use": "sig", "key_ops": []any{"encrypt"}}}, want: nil, clause: "RFC 7517 4.3",
		},
		"a member marked use enc whose key_ops include verify is not used": {
			members: []member{{"use": "enc", "key_ops": []any{"verify"}}}, want: nil, clause: "RFC 7517 4.3",
		},
		"a member marked use enc is used when key use is ignored": {
			members: []member{{"use": "enc", "key_ops": []any{"encrypt"}}}, ignoreKeyUse: true, want: []int{0}, clause: "RFC 7517 4.3",
		},
		"a member with a malformed use is used when key use is ignored": {
			members: []member{{"use": 7, "key_ops": "encrypt"}}, ignoreKeyUse: true, want: []int{0}, clause: "RFC 7517 4.3",
		},
		"a member whose alg differs is not used when key use is ignored": {
			members: []member{{"use": "enc", "alg": "ES384"}}, ignoreKeyUse: true, want: nil, clause: "RFC 8725 3.1",
		},
	}
}

func TestSelectKeys(t *testing.T) {
	for name, tc := range selectionCases() {
		t.Run(name, func(t *testing.T) {
			var set model.Jwks
			var publics []*ecdsa.PublicKey
			for _, m := range tc.members {
				if m["kty"] == "nonsense" {
					set.Keys = append(set.Keys, m)
					publics = append(publics, nil)
					continue
				}
				jwk, public := p256Jwk(t, m)
				set.Keys = append(set.Keys, jwk)
				publics = append(publics, public)
			}

			got := SelectKeys(set, tc.kid, "ES256", tc.ignoreKeyUse)

			if len(got) != len(tc.want) {
				t.Fatalf("[%s] expected %d keys, got %d", tc.clause, len(tc.want), len(got))
			}
			for i, index := range tc.want {
				if !publics[index].Equal(got[i]) {
					t.Errorf("[%s] key %d must be member %d of the set", tc.clause, i, index)
				}
			}
		})
	}
}

func TestRetrieveJKU_ASelectionOfNoMemberReportsNoKeyIdentifierMatch(t *testing.T) {
	tests := map[string]struct {
		member member
		kid    *string
		clause string
	}{
		"a kid that matches no member":   {member: member{"kid": "issued"}, kid: model.Pointer("some-other-key"), clause: "RFC 7515 4.1.4"},
		"an alg that matches no member":  {member: member{"alg": "ES384"}, clause: "RFC 8725 3.1"},
		"a member marked for encryption": {member: member{"use": "enc"}, clause: "RFC 7517 4.2"},
		"a member without verify in ops": {member: member{"key_ops": []any{"encrypt"}}, clause: "RFC 7517 4.3"},
	}
	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			jwk, _ := p256Jwk(t, tc.member)
			server := serveKeySet(t, jwk)

			keys, err := RetrieveJKU(server.URL, httputils.Fetcher(context.Background(), server.Client(), 0), tc.kid, "ES256", false)()
			if err == nil {
				t.Fatalf("[%s] no member may be selected, got %d keys", tc.clause, len(keys))
			}
			if !errors.Is(err, joseerror.ErrNoKeyIdentifierMatch) {
				t.Errorf("[%s] an empty selection must report that no key matched, so the next key source is tried, got %v", tc.clause, err)
			}
		})
	}
}

func TestRetrieveJKU_ADocumentThatIsNotAJwkSetIsRefused(t *testing.T) {
	for _, body := range []string{`{"foo":[]}`, `{"keys":null}`, `{"KEYS":[]}`, `null`} {
		t.Run(body, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				if _, err := w.Write([]byte(body)); err != nil {
					return
				}
			}))
			defer server.Close()

			keys, err := RetrieveJKU(server.URL, httputils.Fetcher(context.Background(), server.Client(), 0), nil, "ES256", false)()
			if err == nil {
				t.Fatalf("[RFC 7517 5] a JWK Set MUST have a \"keys\" member holding an array, got %d keys", len(keys))
			}
			if !errors.Is(err, joseerror.ErrKeystoreError) {
				t.Errorf("[RFC 7517 5] a document that is not a JWK Set must report a keystore error, got %v", err)
			}
			if errors.Is(err, joseerror.ErrNoKeyIdentifierMatch) {
				t.Errorf("[RFC 7517 5] a document that is not a JWK Set must not be reported as a set with no matching key, got %v", err)
			}
		})
	}
}

func TestInlineJWK_KeyUse(t *testing.T) {
	tests := map[string]struct {
		member       member
		ignoreKeyUse bool
		wantErr      error
		clause       string
	}{
		"use sig is used":                     {member: member{"use": "sig"}, clause: "RFC 7517 4.2"},
		"key_ops with verify is used":         {member: member{"key_ops": []any{"verify"}}, clause: "RFC 7517 4.3"},
		"use enc is not used":                 {member: member{"use": "enc"}, wantErr: joseerror.ErrNoKeyIdentifierMatch, clause: "RFC 7517 4.2"},
		"key_ops without verify is not used":  {member: member{"key_ops": []any{"encrypt"}}, wantErr: joseerror.ErrNoKeyIdentifierMatch, clause: "RFC 7517 4.3"},
		"use sig with key_ops lacking verify": {member: member{"use": "sig", "key_ops": []any{"encrypt"}}, wantErr: joseerror.ErrNoKeyIdentifierMatch, clause: "RFC 7517 4.3"},
		"use that is not a string":            {member: member{"use": 7}, wantErr: joseerror.ErrMalformedClaim, clause: "RFC 7517 4.2"},
		"key_ops that is not an array":        {member: member{"key_ops": "verify"}, wantErr: joseerror.ErrMalformedClaim, clause: "RFC 7517 4.3"},
		"key_ops holding a non-string":        {member: member{"key_ops": []any{true, "verify"}}, wantErr: joseerror.ErrMalformedClaim, clause: "RFC 7517 4.3"},
		"use enc when key use is ignored":     {member: member{"use": "enc", "key_ops": []any{"encrypt"}}, ignoreKeyUse: true, clause: "RFC 7517 4.3"},
		"malformed use when key use ignored":  {member: member{"use": 7, "key_ops": "x"}, ignoreKeyUse: true, clause: "RFC 7517 4.3"},
	}
	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			jwk, public := p256Jwk(t, tc.member)

			keys, err := InlineJWK(jwk, nil, "ES256", tc.ignoreKeyUse)()
			if tc.wantErr != nil {
				if !errors.Is(err, tc.wantErr) {
					t.Errorf("[%s] expected %v, got %d keys and %v", tc.clause, tc.wantErr, len(keys), err)
				}
				return
			}
			if err != nil {
				t.Fatalf("[%s] expected the key, got %v", tc.clause, err)
			}
			if len(keys) != 1 || !public.Equal(keys[0]) {
				t.Errorf("[%s] expected exactly the jwk's key, got %d keys", tc.clause, len(keys))
			}
		})
	}
}
