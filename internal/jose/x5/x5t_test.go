package x5

import (
	"bytes"
	"crypto/sha1"
	"crypto/sha256"
	"encoding/base64"
	"strings"
	"testing"
)

func TestCalculateX5t_IsTheBase64urlDigestOfTheCertificate(t *testing.T) {
	certs, err := generateCertificateChain(t, 3)
	if err != nil {
		t.Fatalf("failed to generate certificate chain: %v", err)
	}

	tests := map[string]struct {
		reference string
		calculate func(cert []byte) string
		digest    func(cert []byte) []byte
		length    int
	}{
		"x5t is the SHA-1 thumbprint": {
			reference: "RFC 7515 4.1.7",
			calculate: CalculateX5t,
			digest:    func(cert []byte) []byte { sum := sha1.Sum(cert); return sum[:] },
			length:    27,
		},
		"x5t#S256 is the SHA-256 thumbprint": {
			reference: "RFC 7515 4.1.8",
			calculate: CalculateX5tS256,
			digest:    func(cert []byte) []byte { sum := sha256.Sum256(cert); return sum[:] },
			length:    43,
		},
	}

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			for i, cert := range certs {
				want := base64.RawURLEncoding.EncodeToString(tc.digest(cert))
				got := tc.calculate(cert)
				if got != want {
					t.Errorf("[%s] certificate %d: the thumbprint is the base64url encoded digest of the DER encoding, want %q, got %q", tc.reference, i, want, got)
				}
				if len(got) != tc.length {
					t.Errorf("[%s] certificate %d: a %d byte digest encodes to %d base64url characters, got %d", tc.reference, i, len(tc.digest(cert)), tc.length, len(got))
				}
			}
		})
	}
}

func TestCalculateX5t_DoesNotCarryTheCertificate(t *testing.T) {
	certs, err := generateCertificateChain(t, 1)
	if err != nil {
		t.Fatalf("failed to generate certificate chain: %v", err)
	}
	cert := certs[0]

	tests := map[string]struct {
		reference string
		calculate func(cert []byte) string
	}{
		"x5t":      {reference: "RFC 7515 4.1.7", calculate: CalculateX5t},
		"x5t#S256": {reference: "RFC 7515 4.1.8", calculate: CalculateX5tS256},
	}

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			decoded, err := base64.RawURLEncoding.DecodeString(tc.calculate(cert))
			if err != nil {
				t.Fatalf("[%s] the thumbprint must be base64url: %v", tc.reference, err)
			}
			if bytes.Contains(decoded, cert) {
				t.Errorf("[%s] a digest of a %d byte certificate cannot contain it, so the certificate is being returned rather than hashed", tc.reference, len(cert))
			}
		})
	}
}

func TestCalculateX5t_DependsOnEveryByteOfTheCertificate(t *testing.T) {
	certs, err := generateCertificateChain(t, 1)
	if err != nil {
		t.Fatalf("failed to generate certificate chain: %v", err)
	}
	cert := certs[0]

	tests := map[string]struct {
		reference string
		calculate func(cert []byte) string
	}{
		"x5t":      {reference: "RFC 7515 4.1.7", calculate: CalculateX5t},
		"x5t#S256": {reference: "RFC 7515 4.1.8", calculate: CalculateX5tS256},
	}

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			base := tc.calculate(cert)
			for _, at := range []int{0, len(cert) / 2, len(cert) - 1} {
				flipped := make([]byte, len(cert))
				copy(flipped, cert)
				flipped[at] ^= 0x01
				if tc.calculate(flipped) == base {
					t.Errorf("[%s] flipping a bit at offset %d did not change the thumbprint, so that byte is not hashed", tc.reference, at)
				}
			}
		})
	}
}

func TestInlineCertificate_AcceptsTheThumbprintTheRFCDefines(t *testing.T) {
	certs, err := generateCertificateChain(t, 1)
	if err != nil {
		t.Fatalf("failed to generate certificate chain: %v", err)
	}
	cert := certs[0]
	encoded := base64.StdEncoding.EncodeToString(cert)

	sha1Sum := sha1.Sum(cert)
	sha256Sum := sha256.Sum256(cert)
	x5t := base64.RawURLEncoding.EncodeToString(sha1Sum[:])
	x5ts256 := base64.RawURLEncoding.EncodeToString(sha256Sum[:])

	tests := map[string]struct {
		reference string
		x5t       *string
		x5ts256   *string
	}{
		"the SHA-1 thumbprint alone":   {reference: "RFC 7515 4.1.7", x5t: &x5t},
		"the SHA-256 thumbprint alone": {reference: "RFC 7515 4.1.8", x5ts256: &x5ts256},
		"both thumbprints":             {reference: "RFC 7515 4.1.7, 4.1.8", x5t: &x5t, x5ts256: &x5ts256},
	}

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			_, err := InlineCertificate([]string{encoded}, tc.x5t, tc.x5ts256, "RS256")()
			if err != nil && strings.Contains(err.Error(), "does not match value from jose header") {
				t.Errorf("[%s] a header carrying the thumbprint this RFC defines must be accepted, got %v", tc.reference, err)
			}
		})
	}
}
