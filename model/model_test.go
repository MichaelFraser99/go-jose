package model

import "testing"

func TestAlgorithm_String(t *testing.T) {
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
	}

	for _, tt := range tests {
		t.Run(tt.expected, func(t *testing.T) {
			if tt.algorithm.String() != tt.expected {
				t.Errorf("Expected: %s got: %s", tt.expected, tt.algorithm.String())
			}
		})
	}
}
