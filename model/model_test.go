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
			expectedErr: fmt.Errorf("%w provided jwk has kid value matching a value already present in the keyset", joseerror.KeystoreError),
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
			expectedErr: fmt.Errorf("%w malformed key ID found for JWK", joseerror.KeystoreError),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
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
			expectedErr: fmt.Errorf("%wno matching key found for provided key ID", joseerror.KeystoreError),
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
			expectedErr: fmt.Errorf("%wmultiple keys found for provided key ID", joseerror.KeystoreError),
		},
		{
			name: "Invalid key format",
			jwks: Jwks{Keys: []map[string]any{
				{"invalid_key": "RS256"},
			}},
			kid:         "key1",
			expectErr:   true,
			expectedErr: fmt.Errorf("%wno matching key found for provided key ID", joseerror.KeystoreError),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
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

func TestAlgorithm_String(t *testing.T) {
	t.Parallel()
	tests := []struct {
		algorithm Algorithm
		expected  string
	}{
		{
			algorithm: ES256,
			expected:  "ES256",
		},
		{
			algorithm: ES384,
			expected:  "ES384",
		},
		{
			algorithm: ES512,
			expected:  "ES512",
		},
		{
			algorithm: RS256,
			expected:  "RS256",
		},
		{
			algorithm: RS384,
			expected:  "RS384",
		},
		{
			algorithm: RS512,
			expected:  "RS512",
		},
		{
			algorithm: PS256,
			expected:  "PS256",
		},
		{
			algorithm: PS384,
			expected:  "PS384",
		},
		{
			algorithm: PS512,
			expected:  "PS512",
		},
		{
			algorithm: HS256,
			expected:  "HS256",
		},
		{
			algorithm: HS384,
			expected:  "HS384",
		},
		{
			algorithm: HS512,
			expected:  "HS512",
		},
		{
			algorithm: EdDSA,
			expected:  "EdDSA",
		},
	}

	for _, tt := range tests {
		t.Run(tt.expected, func(t *testing.T) {
			t.Parallel()
			if tt.algorithm.String() != tt.expected {
				t.Errorf("Expected: %s got: %s", tt.expected, tt.algorithm.String())
			}
		})
	}
}

func TestGetAlgorithm(t *testing.T) {
	t.Parallel()
	tests := []struct {
		algString string
		expected  Algorithm
	}{
		{
			algString: "ES256",
			expected:  ES256,
		},
		{
			algString: "ES384",
			expected:  ES384,
		},
		{
			algString: "ES512",
			expected:  ES512,
		},
		{
			algString: "RS256",
			expected:  RS256,
		},
		{
			algString: "RS384",
			expected:  RS384,
		},
		{
			algString: "RS512",
			expected:  RS512,
		},
		{
			algString: "PS256",
			expected:  PS256,
		},
		{
			algString: "PS384",
			expected:  PS384,
		},
		{
			algString: "PS512",
			expected:  PS512,
		},
		{
			algString: "HS256",
			expected:  HS256,
		},
		{
			algString: "HS384",
			expected:  HS384,
		},
		{
			algString: "HS512",
			expected:  HS512,
		},
		{
			algString: "EdDSA",
			expected:  EdDSA,
		},
		{
			algString: "rubbish",
			expected:  Unknown,
		},
	}

	for _, tt := range tests {
		t.Run(tt.algString, func(t *testing.T) {
			t.Parallel()
			alg := GetAlgorithm(tt.algString)
			if alg != tt.expected {
				t.Errorf("wrong algorithm returned, expected %s got: %s", tt.expected.String(), alg.String())
			}
		})
	}
}
