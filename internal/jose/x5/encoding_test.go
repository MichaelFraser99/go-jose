package x5

import (
	"crypto/x509"
	"encoding/base64"
	"errors"
	"strings"
	"testing"

	"github.com/MichaelFraser99/go-jose/joseerror"
)

func paddedCertificate(t *testing.T, root *issued) *issued {
	t.Helper()
	for {
		leaf := issueCertificate(t, leafTemplate(x509.KeyUsageDigitalSignature), root)
		if len(leaf.cert.Raw)%3 != 0 {
			return leaf
		}
	}
}

func withNonZeroPadBits(t *testing.T, encoded string) string {
	t.Helper()
	const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
	trimmed := strings.TrimRight(encoded, "=")
	last := strings.IndexByte(alphabet, trimmed[len(trimmed)-1])
	if last%2 != 0 {
		t.Fatalf("a canonical encoding leaves its pad bits zero, got %q", encoded)
	}
	return trimmed[:len(trimmed)-1] + string(alphabet[last+1]) + encoded[len(trimmed):]
}

func TestParseCertificateChain_AnEntryIsTheBase64AlphabetAlone(t *testing.T) {
	root := issueCertificate(t, caTemplate("root", x509.KeyUsageCertSign|x509.KeyUsageDigitalSignature), nil)
	leaf := paddedCertificate(t, root)
	encoded := base64.StdEncoding.EncodeToString(leaf.cert.Raw)

	tests := map[string]struct {
		reference string
		entry     string
		lenient   bool
		accept    bool
	}{
		"the canonical encoding": {
			reference: "RFC 7515 4.1.6", entry: encoded, accept: true,
		},
		"a CRLF in the middle": {
			reference: "RFC 4648 3.3", entry: encoded[:40] + "\r\n" + encoded[40:], lenient: true,
		},
		"a LF in the middle": {
			reference: "RFC 4648 3.3", entry: encoded[:40] + "\n" + encoded[40:], lenient: true,
		},
		"a CR in the middle": {
			reference: "RFC 4648 3.3", entry: encoded[:40] + "\r" + encoded[40:], lenient: true,
		},
		"a line break every 64 characters, as PEM wraps": {
			reference: "RFC 4648 3.3", entry: wrap(encoded, 64), lenient: true,
		},
		"a trailing LF": {
			reference: "RFC 4648 3.3", entry: encoded + "\n", lenient: true,
		},
		"a leading CRLF": {
			reference: "RFC 4648 3.3", entry: "\r\n" + encoded, lenient: true,
		},
		"a space in the middle": {
			reference: "RFC 4648 3.3", entry: encoded[:40] + " " + encoded[40:],
		},
		"pad bits that are not zero": {
			reference: "RFC 4648 3.5", entry: withNonZeroPadBits(t, encoded), lenient: true,
		},
	}

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			if tc.lenient {
				if der, err := base64.StdEncoding.DecodeString(tc.entry); err != nil || string(der) != string(leaf.cert.Raw) {
					t.Fatalf("the fixture must decode to the certificate under encoding/base64's lenient decoder, or this row asserts nothing: %v", err)
				}
			}

			chain := []string{tc.entry}
			validateErr := ValidateCertificateChain(map[string]any{}, chain)
			keys, inlineErr := InlineCertificate(chain, nil, nil, poolOfIssued(root), nil)()

			if tc.accept {
				if validateErr != nil || inlineErr != nil {
					t.Fatalf("[%s] %s must be read, got %v and %v", tc.reference, name, validateErr, inlineErr)
				}
				return
			}
			for stage, err := range map[string]error{"header validation": validateErr, "key retrieval": inlineErr} {
				if err == nil {
					t.Errorf("[%s] %s is not the base64 RFC 7515 4.1.6 names, so %s must refuse it", tc.reference, name, stage)
					continue
				}
				if !errors.Is(err, joseerror.ErrMalformedClaim) {
					t.Errorf("[%s] %s must refuse it as ErrMalformedClaim, got %v", tc.reference, stage, err)
				}
			}
			if len(keys) != 0 {
				t.Errorf("[%s] no key may be returned, got %d", tc.reference, len(keys))
			}
		})
	}
}

func wrap(text string, width int) string {
	var lines []string
	for len(text) > width {
		lines = append(lines, text[:width])
		text = text[width:]
	}
	return strings.Join(append(lines, text), "\r\n")
}
