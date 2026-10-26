package x5

import (
	"bytes"
	"crypto/sha1"
	"crypto/sha256"
	"encoding/base64"
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
			flipped := make([]byte, len(cert))
			for at := range cert {
				copy(flipped, cert)
				flipped[at] ^= 0x01
				if tc.calculate(flipped) == base {
					t.Fatalf("[%s] flipping a bit at offset %d of %d did not change the thumbprint, so that byte is not hashed", tc.reference, at, len(cert))
				}
			}
		})
	}
}

const x5tVectorCertificate = "MIIDFDCCAfygAwIBAgIBATANBgkqhkiG9w0BAQsFADAiMSAwHgYDVQQDDBdnby1qb3NlIHg1dCB0ZXN0IHZlY3RvcjAgFw0yNjEwMjYyMjU2MTNaGA8yMTI2MTAwMjIyNTYxM1owIjEgMB4GA1UEAwwXZ28tam9zZSB4NXQgdGVzdCB2ZWN0b3IwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQCmt6lbndhDssFjH6pFbw0Jp6MfZ+VsRwBS8oOGttGiSLFPy+FzgwbQpBHhC0poJlu3UbkBFwuOnhbPt09lsJCljr+M6T77YWX7Roc+SrNYX0dbgxys+8e5R0jhTCz8nVt+WUJY5bfcNDPQ7muQNGMwYjQH2oaiKBgVvwz5Us5Y7NdDDawvmIEbRr1rzfHcgMsa+PheoZodZM/bh+Gwo0tqUANKcO5MHFsDJeS1a/L+/EBD6MeAiD+fuBWDpVnS1LSdMggfUKHHZhPcq2YZgf51ozhwIoLr6NBuJdEcnt+1WbFd8tV4UAV2YOkfmISwZLzKDNEQoa+8jqKOxfrqUIw7AgMBAAGjUzBRMB0GA1UdDgQWBBRI5AEpAtGUUvn8EfMB4T7lhJmKajAfBgNVHSMEGDAWgBRI5AEpAtGUUvn8EfMB4T7lhJmKajAPBgNVHRMBAf8EBTADAQH/MA0GCSqGSIb3DQEBCwUAA4IBAQCcGU6VFIgCihdOjKWBhVQJRk225sD5naYkJ3/pf2azj0cfUoPEBlgUkicBE742vX/Wa3rAZXqQbgtdphMpfKTqe4ZBn+DxPvmWu83hns4yWe4SUYjMBqBI/+RIOf9LdfptE5cdWF4j5pq7DkzGYr9HPNQj+CTuQqFBh3vKaBil3DUu74uoM+YnTPYbW3KNj3rNq5SPxyvxcOBj7GrT1S7iTaSon7Sirdo/NNevc0YMYk2b8PA1xeo4hBKC4XrcJZiG9VwyMZ4v466GvB3fWswqorXR0oX3SsB4mQjky0C5aL+rfxzyaNSrM+SSyxzZdSOS8dSybTV9YfbaWqpl+Aoe"

func TestCalculateX5t_MatchesAVectorFromOutsideThisLibrary(t *testing.T) {
	cert, err := base64.StdEncoding.DecodeString(x5tVectorCertificate)
	if err != nil {
		t.Fatalf("failed to decode the test vector: %v", err)
	}

	tests := map[string]struct {
		reference string
		calculate func(cert []byte) string
		want      string
	}{
		"x5t":      {reference: "RFC 7515 4.1.7", calculate: CalculateX5t, want: "CxZDJJ0hdNH_RoG2SbPKVq5_xdI"},
		"x5t#S256": {reference: "RFC 7515 4.1.8", calculate: CalculateX5tS256, want: "6vPAUxDJQntONHQG1m9EOzppP7O_oqUR1gk3H-Bczn4"},
	}

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			if got := tc.calculate(cert); got != tc.want {
				t.Errorf("[%s] openssl dgst over this certificate's DER encodes to %q, got %q", tc.reference, tc.want, got)
			}
		})
	}
}
