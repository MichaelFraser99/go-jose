package joseerror

import (
	"errors"
	"fmt"
	"strings"
	"testing"
)

func sentinels() map[string]error {
	return map[string]error{
		"ErrInvalidPublicKey":     ErrInvalidPublicKey,
		"ErrInvalidPrivateKey":    ErrInvalidPrivateKey,
		"ErrInvalidSignature":     ErrInvalidSignature,
		"ErrDecryptionFailed":     ErrDecryptionFailed,
		"ErrUnsupportedAlgorithm": ErrUnsupportedAlgorithm,
		"ErrSigningError":         ErrSigningError,
		"ErrMalformedClaim":       ErrMalformedClaim,
		"ErrMissingCriticalClaim": ErrMissingCriticalClaim,
		"ErrMissingClaim":         ErrMissingClaim,
		"ErrKeystoreError":        ErrKeystoreError,
		"ErrApplicationError":     ErrApplicationError,
		"ErrNoKeyIdentifierMatch": ErrNoKeyIdentifierMatch,
		"ErrMalformedToken":       ErrMalformedToken,
		"ErrExpired":              ErrExpired,
		"ErrNotYetValid":          ErrNotYetValid,
		"ErrAudienceMismatch":     ErrAudienceMismatch,
		"ErrInvalidOptions":       ErrInvalidOptions,
	}
}

func TestSentinels_EachNamesItsOwnCategory(t *testing.T) {
	for name, err := range sentinels() {
		t.Run(name, func(t *testing.T) {
			if err.Error() == "" {
				t.Fatalf("%s has an empty message, so returned on its own it prints nothing and wrapped it contributes nothing", name)
			}
			if !strings.HasSuffix(err.Error(), ": ") {
				t.Errorf("%s must end in %q so that a wrapped suffix composes into one sentence, got %q", name, ": ", err.Error())
			}
			if strings.TrimSpace(err.Error()) != strings.ToLower(strings.TrimSpace(err.Error())) {
				t.Errorf("%s should read as lower case prose, got %q", name, err.Error())
			}
		})
	}
}

func TestSentinels_AreDistinctFromOneAnother(t *testing.T) {
	seen := map[string]string{}
	for name, err := range sentinels() {
		if previous, clash := seen[err.Error()]; clash {
			t.Errorf("%s and %s share the message %q, so neither names a distinguishable category", name, previous, err.Error())
		}
		seen[err.Error()] = name
	}

	for name, err := range sentinels() {
		for otherName, other := range sentinels() {
			if name == otherName {
				continue
			}
			if errors.Is(err, other) {
				t.Errorf("%s must not match %s under errors.Is", name, otherName)
			}
		}
	}
}

func TestSentinels_WrapComposesIntoOneSentence(t *testing.T) {
	wrapped := fmt.Errorf("%wshould be an instance of *ecdsa.PrivateKey", ErrInvalidPrivateKey)

	const want = "invalid private key: should be an instance of *ecdsa.PrivateKey"
	if wrapped.Error() != want {
		t.Errorf("a sentinel wrapped with a discriminating suffix must read as one sentence, want %q, got %q", want, wrapped.Error())
	}
	if !errors.Is(wrapped, ErrInvalidPrivateKey) {
		t.Error("wrapping must preserve the sentinel for errors.Is")
	}
}
