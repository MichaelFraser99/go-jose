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

func TestGetAlgorithm(t *testing.T) {
	tests := []struct {
		algString string
		validate  func(t *testing.T, alg *Algorithm)
	}{
		{
			algString: "ES256",
			validate: func(t *testing.T, alg *Algorithm) {
				if alg == nil {
					t.Fatal("algorithm should not be nil")
				}
				if *alg != ES256 {
					t.Errorf("wrong algorithm returned, expected ES256 got: %s", alg.String())
				}
			},
		},
		{
			algString: "ES384",
			validate: func(t *testing.T, alg *Algorithm) {
				if alg == nil {
					t.Fatal("algorithm should not be nil")
				}
				if *alg != ES384 {
					t.Errorf("wrong algorithm returned, expected ES384 got: %s", alg.String())
				}
			},
		},
		{
			algString: "ES512",
			validate: func(t *testing.T, alg *Algorithm) {
				if alg == nil {
					t.Fatal("algorithm should not be nil")
				}
				if *alg != ES512 {
					t.Errorf("wrong algorithm returned, expected ES512 got: %s", alg.String())
				}
			},
		},
		{
			algString: "RS256",
			validate: func(t *testing.T, alg *Algorithm) {
				if alg == nil {
					t.Fatal("algorithm should not be nil")
				}
				if *alg != RS256 {
					t.Errorf("wrong algorithm returned, expected RS256 got: %s", alg.String())
				}
			},
		},
		{
			algString: "RS384",
			validate: func(t *testing.T, alg *Algorithm) {
				if alg == nil {
					t.Fatal("algorithm should not be nil")
				}
				if *alg != RS384 {
					t.Errorf("wrong algorithm returned, expected RS384 got: %s", alg.String())
				}
			},
		},
		{
			algString: "RS512",
			validate: func(t *testing.T, alg *Algorithm) {
				if alg == nil {
					t.Fatal("algorithm should not be nil")
				}
				if *alg != RS512 {
					t.Errorf("wrong algorithm returned, expected RS512 got: %s", alg.String())
				}
			},
		},
		{
			algString: "PS256",
			validate: func(t *testing.T, alg *Algorithm) {
				if alg == nil {
					t.Fatal("algorithm should not be nil")
				}
				if *alg != PS256 {
					t.Errorf("wrong algorithm returned, expected PS256 got: %s", alg.String())
				}
			},
		},
		{
			algString: "PS384",
			validate: func(t *testing.T, alg *Algorithm) {
				if alg == nil {
					t.Fatal("algorithm should not be nil")
				}
				if *alg != PS384 {
					t.Errorf("wrong algorithm returned, expected PS384 got: %s", alg.String())
				}
			},
		},
		{
			algString: "PS512",
			validate: func(t *testing.T, alg *Algorithm) {
				if alg == nil {
					t.Fatal("algorithm should not be nil")
				}
				if *alg != PS512 {
					t.Errorf("wrong algorithm returned, expected PS512 got: %s", alg.String())
				}
			},
		},
		{
			algString: "HS256",
			validate: func(t *testing.T, alg *Algorithm) {
				if alg == nil {
					t.Fatal("algorithm should not be nil")
				}
				if *alg != HS256 {
					t.Errorf("wrong algorithm returned, expected HS256 got: %s", alg.String())
				}
			},
		},
		{
			algString: "HS384",
			validate: func(t *testing.T, alg *Algorithm) {
				if alg == nil {
					t.Fatal("algorithm should not be nil")
				}
				if *alg != HS384 {
					t.Errorf("wrong algorithm returned, expected HS384 got: %s", alg.String())
				}
			},
		},
		{
			algString: "HS512",
			validate: func(t *testing.T, alg *Algorithm) {
				if alg == nil {
					t.Fatal("algorithm should not be nil")
				}
				if *alg != HS512 {
					t.Errorf("wrong algorithm returned, expected HS512 got: %s", alg.String())
				}
			},
		},
		{
			algString: "rubbish",
			validate: func(t *testing.T, alg *Algorithm) {
				if alg != nil {
					t.Errorf("algorithm should be nil: %s", alg.String())
				}
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.algString, func(t *testing.T) {
			alg := GetAlgorithm(tt.algString)
			tt.validate(t, alg)
		})
	}
}
