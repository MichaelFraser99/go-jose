package model

import "testing"

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
