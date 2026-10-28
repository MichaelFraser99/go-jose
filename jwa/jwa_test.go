package jwa

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
		{
			algorithm: Ed25519,
			expected:  "Ed25519",
		},
		{
			algorithm: MLDSA44,
			expected:  "ML-DSA-44",
		},
		{
			algorithm: MLDSA65,
			expected:  "ML-DSA-65",
		},
		{
			algorithm: MLDSA87,
			expected:  "ML-DSA-87",
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
			algString: "Ed25519",
			expected:  Ed25519,
		},
		{
			algString: "ML-DSA-44",
			expected:  MLDSA44,
		},
		{
			algString: "ML-DSA-65",
			expected:  MLDSA65,
		},
		{
			algString: "ML-DSA-87",
			expected:  MLDSA87,
		},
		{
			algString: "rubbish",
			expected:  Unknown,
		},
	}

	for _, tt := range tests {
		t.Run(tt.algString, func(t *testing.T) {
			alg := GetAlgorithm(tt.algString)
			if alg != tt.expected {
				t.Errorf("wrong algorithm returned, expected %s got: %s", tt.expected.String(), alg.String())
			}
		})
	}
}

func TestAlgorithm_UnknownIsTheZeroValue(t *testing.T) {
	if Algorithm(0) != Unknown {
		t.Errorf("the zero value of Algorithm must be Unknown, so a caller who leaves it unset is refused rather than silently given a real algorithm, got %q", Algorithm(0).String())
	}

	var unset Algorithm
	if unset != Unknown {
		t.Errorf("a declared but unassigned Algorithm must be Unknown, got %q", unset.String())
	}
}

func TestAlgorithm_EveryNamedAlgorithmRoundTripsAndNoneIsTheZeroValue(t *testing.T) {
	named := []Algorithm{ES256, ES384, ES512, RS256, RS384, RS512, PS256, PS384, PS512, HS256, HS384, HS512, EdDSA, Ed25519, MLDSA44, MLDSA65, MLDSA87}

	for _, alg := range named {
		t.Run(alg.String(), func(t *testing.T) {
			if alg == Unknown {
				t.Fatalf("%q must not equal Unknown", alg.String())
			}
			if alg == 0 {
				t.Errorf("%q must not be the zero value, or an unset Algorithm would mean this algorithm", alg.String())
			}
			if got := GetAlgorithm(alg.String()); got != alg {
				t.Errorf("GetAlgorithm(%q) must round trip, got %q", alg.String(), got.String())
			}
		})
	}
}

func TestGetAlgorithm_AnUnrecognisedNameIsUnknown(t *testing.T) {
	tests := map[string]string{
		"an empty name":          "",
		"a lowercase name":       "es256",
		"a name with whitespace": " ES256",
		"an algorithm of none":   "none",
		"an unregistered name":   "ES999",
		"a lowercase Ed25519":    "ed25519",
		"Ed448, not supported":   "Ed448",
		"a lowercase ML-DSA":     "ml-dsa-44",
		"HashML-DSA":             "HashML-DSA-44",
		"ML-DSA with no set":     "ML-DSA",
	}

	for name, alg := range tests {
		t.Run(name, func(t *testing.T) {
			if got := GetAlgorithm(alg); got != Unknown {
				t.Errorf("%q names no algorithm this library supports, so it must map to Unknown, got %q", alg, got.String())
			}
		})
	}
}
