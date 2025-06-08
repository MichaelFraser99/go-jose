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
			expectedErr: fmt.Errorf("%w provided jwk has kid value matching a value already present in the keyset", joseerror.ErrKeystoreError),
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
			expectedErr: fmt.Errorf("%w malformed key ID found for JWK", joseerror.ErrKeystoreError),
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
	tests := []struct {
		name        string
		jwks        Jwks
		kid         string
		expectedKey map[string]any
		expectErr   bool
		expectedErr error
	}{
		{
			name:        "No matching key",
			jwks:        Jwks{Keys: []map[string]any{}},
			kid:         "non-existent-kid",
			expectErr:   true,
			expectedErr: fmt.Errorf("%wno matching key found for provided key ID", joseerror.ErrKeystoreError),
		},
		{
			name: "Single matching key",
			jwks: Jwks{Keys: []map[string]any{
				{"kid": "key1", "alg": "RS256"},
			}},
			kid:         "key1",
			expectedKey: map[string]any{"kid": "key1", "alg": "RS256"},
			expectErr:   false,
		},
		{
			name: "Multiple matching keys",
			jwks: Jwks{
				Opts: struct {
					EnforceUniqueKIDs bool
				}{EnforceUniqueKIDs: false},
				Keys: []map[string]any{
					{"kid": "key1", "alg": "RS256"},
					{"kid": "key1", "alg": "RS384"},
				},
			},
			kid:         "key1",
			expectErr:   true,
			expectedErr: fmt.Errorf("%wmultiple keys found for provided key ID", joseerror.ErrKeystoreError),
		},
		{
			name: "Invalid key format",
			jwks: Jwks{Keys: []map[string]any{
				{"invalid_key": "RS256"},
			}},
			kid:         "key1",
			expectErr:   true,
			expectedErr: fmt.Errorf("%wno matching key found for provided key ID", joseerror.ErrKeystoreError),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			key, err := tt.jwks.RetrieveByKeyID(tt.kid)
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
				if key["kid"] != tt.expectedKey["kid"] || key["alg"] != tt.expectedKey["alg"] {
					t.Errorf("expected key: %v, got: %v", tt.expectedKey, key)
				}
			}
		})
	}
}
