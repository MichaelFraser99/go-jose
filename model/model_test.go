package model

import (
	"fmt"
	"github.com/MichaelFraser99/go-jose/joseerror"
	"testing"
)

func TestJwks_Add(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name         string
		initialJwks  Jwks
		keyToAdd     map[string]any
		expectErr    bool
		expectedErr  error
		expectedKeys []map[string]any
	}{
		{
			name:        "Add valid key",
			initialJwks: Jwks{},
			keyToAdd:    map[string]any{"kid": "key1", "alg": "RS256"},
			expectErr:   false,
			expectedKeys: []map[string]any{
				{"kid": "key1", "alg": "RS256"},
			},
		},
		{
			name: "Add duplicate key with unique KIDs enforced",
			initialJwks: Jwks{
				Opts: struct {
					EnforceUniqueKIDs bool
				}{EnforceUniqueKIDs: true},
				Keys: []map[string]any{
					{"kid": "key1", "alg": "RS256"},
				},
			},
			keyToAdd:    map[string]any{"kid": "key1", "alg": "RS256"},
			expectErr:   true,
			expectedErr: fmt.Errorf("%wprovided jwk has kid value matching a value already present in the keyset", joseerror.ErrKeystoreError),
		},
		{
			name: "Add duplicate key with unique KIDs not enforced",
			initialJwks: Jwks{
				Opts: struct {
					EnforceUniqueKIDs bool
				}{EnforceUniqueKIDs: false},
				Keys: []map[string]any{
					{"kid": "key1", "alg": "RS256"},
				},
			},
			keyToAdd:  map[string]any{"kid": "key1", "alg": "RS256"},
			expectErr: false,
			expectedKeys: []map[string]any{
				{"kid": "key1", "alg": "RS256"},
				{"kid": "key1", "alg": "RS256"},
			},
		},
		{
			name:        "Add malformed key",
			initialJwks: Jwks{},
			keyToAdd:    map[string]any{"invalidKey": "value"},
			expectErr:   false,
			expectedKeys: []map[string]any{
				{"invalidKey": "value"},
			},
		},
		{
			name: "Add key with non-string kid and unique KIDs enforced",
			initialJwks: Jwks{
				Opts: struct {
					EnforceUniqueKIDs bool
				}{EnforceUniqueKIDs: true},
			},
			keyToAdd:    map[string]any{"kid": 12345, "alg": "RS256"},
			expectErr:   true,
			expectedErr: fmt.Errorf("%wmalformed key ID found for JWK", joseerror.ErrKeystoreError),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.initialJwks.Add(tt.keyToAdd)
			if tt.expectErr {
				if err == nil {
					t.Errorf("expected an error but got nil")
				}
				if err != nil && err.Error() != tt.expectedErr.Error() {
					t.Errorf("expected error: %v, got: %v", tt.expectedErr, err)
				}
			} else {
				if err != nil {
					t.Errorf("did not expect an error but got: %v", err)
				}
				if len(tt.initialJwks.Keys) != len(tt.expectedKeys) {
					t.Errorf("expected keys: %v, got: %v", tt.expectedKeys, tt.initialJwks.Keys)
					return
				}
				for i, key := range tt.initialJwks.Keys {
					if fmt.Sprintf("%v", key) != fmt.Sprintf("%v", tt.expectedKeys[i]) {
						t.Errorf("expected key: %v, got: %v", tt.expectedKeys[i], key)
					}
				}
			}
		})
	}
}

func TestRetrieveByKeyID(t *testing.T) {
	t.Parallel()
	tests := map[string]struct {
		reference string
		jwks      Jwks
		kid       string
		expect    []map[string]any
		expectErr error
	}{
		"no key carries the kid": {
			reference: "RFC 7517 4.5",
			jwks:      Jwks{Keys: []map[string]any{}},
			kid:       "non-existent-kid",
			expectErr: fmt.Errorf("%wno matching key found for provided key ID", joseerror.ErrKeystoreError),
		},
		"one key carries the kid": {
			reference: "RFC 7517 4.5",
			jwks:      Jwks{Keys: []map[string]any{{"kid": "key1", "alg": "RS256"}}},
			kid:       "key1",
			expect:    []map[string]any{{"kid": "key1", "alg": "RS256"}},
		},
		"two keys carry the kid": {
			reference: "RFC 7517 4.5",
			jwks: Jwks{Keys: []map[string]any{
				{"kid": "key1", "alg": "RS256"},
				{"kid": "key1", "alg": "RS384"},
			}},
			kid: "key1",
			expect: []map[string]any{
				{"kid": "key1", "alg": "RS256"},
				{"kid": "key1", "alg": "RS384"},
			},
		},
		"the matching keys keep the order of the set": {
			reference: "RFC 7517 4.5",
			jwks: Jwks{Keys: []map[string]any{
				{"kid": "key1", "alg": "RS384"},
				{"kid": "other", "alg": "RS256"},
				{"kid": "key1", "alg": "RS256"},
			}},
			kid: "key1",
			expect: []map[string]any{
				{"kid": "key1", "alg": "RS384"},
				{"kid": "key1", "alg": "RS256"},
			},
		},
		"a key with no kid is skipped": {
			reference: "RFC 7517 4.5",
			jwks: Jwks{Keys: []map[string]any{
				{"alg": "RS256"},
				{"kid": "key1", "alg": "RS384"},
			}},
			kid:    "key1",
			expect: []map[string]any{{"kid": "key1", "alg": "RS384"}},
		},
		"a key whose kid is not a string is skipped": {
			reference: "RFC 7517 4.5",
			jwks: Jwks{Keys: []map[string]any{
				{"kid": 7, "alg": "RS256"},
				{"kid": "key1", "alg": "RS384"},
			}},
			kid:    "key1",
			expect: []map[string]any{{"kid": "key1", "alg": "RS384"}},
		},
		"an empty kid does not match a key whose kid is not a string": {
			reference: "RFC 7517 4.5",
			jwks: Jwks{Keys: []map[string]any{
				{"kid": 7, "alg": "RS256"},
				{"kid": nil, "alg": "RS384"},
				{"kid": map[string]any{}, "alg": "RS512"},
			}},
			kid:       "",
			expectErr: fmt.Errorf("%wno matching key found for provided key ID", joseerror.ErrKeystoreError),
		},
		"an empty kid matches a key published with one": {
			reference: "RFC 7517 4.5",
			jwks: Jwks{Keys: []map[string]any{
				{"kid": 7, "alg": "RS256"},
				{"kid": "", "alg": "RS384"},
			}},
			kid:    "",
			expect: []map[string]any{{"kid": "", "alg": "RS384"}},
		},
		"only keys with no usable kid": {
			reference: "RFC 7517 4.5",
			jwks:      Jwks{Keys: []map[string]any{{"invalid_key": "RS256"}}},
			kid:       "key1",
			expectErr: fmt.Errorf("%wno matching key found for provided key ID", joseerror.ErrKeystoreError),
		},
	}

	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			keys, err := tt.jwks.RetrieveByKeyID(tt.kid)

			if tt.expectErr != nil {
				if err == nil {
					t.Fatalf("[%s] expected an error, got %d keys", tt.reference, len(keys))
				}
				if err.Error() != tt.expectErr.Error() {
					t.Errorf("[%s] expected error %v, got %v", tt.reference, tt.expectErr, err)
				}
				if keys != nil {
					t.Errorf("[%s] no keys may be returned alongside an error, got %d", tt.reference, len(keys))
				}
				return
			}

			if err != nil {
				t.Fatalf("[%s] did not expect an error, got %v", tt.reference, err)
			}
			if len(keys) != len(tt.expect) {
				t.Fatalf("[%s] a kid is not required to be unique, so every key carrying it must be returned: expected %d keys, got %d", tt.reference, len(tt.expect), len(keys))
			}
			for i, want := range tt.expect {
				if keys[i]["kid"] != want["kid"] || keys[i]["alg"] != want["alg"] {
					t.Errorf("[%s] key %d: expected %v, got %v", tt.reference, i, want, keys[i])
				}
			}
		})
	}
}
