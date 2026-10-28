package x5

import (
	"crypto/x509"
	"encoding/base64"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/MichaelFraser99/go-jose/joseerror"
)

func TestValidateCertificateChain_AnEmptyParseResultIsRefusedNotPanicked(t *testing.T) {
	tests := map[string]struct {
		reference string
		chain     []string
	}{
		"one entry that decodes to nothing":  {reference: "RFC 7515 4.1.6", chain: []string{""}},
		"two entries that decode to nothing": {reference: "RFC 7515 4.1.6", chain: []string{"", ""}},
		"an entry of base64 padding only":    {reference: "RFC 7515 4.1.6", chain: []string{"===="}},
		"a valid entry beside an empty one":  {reference: "RFC 7515 4.1.6", chain: []string{"", ""}},
	}

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			defer func() {
				if r := recover(); r != nil {
					t.Fatalf("[%s] x5c is written by the peer, so a chain that parses to no certificate must be refused rather than panicking, got %v", tc.reference, r)
				}
			}()

			err := ValidateCertificateChain(map[string]any{}, tc.chain)
			if err == nil {
				t.Fatalf("[%s] a chain carrying no certificate is malformed and must be refused", tc.reference)
			}
			if !errors.Is(err, joseerror.ErrMalformedClaim) {
				t.Errorf("[%s] a malformed chain is the peer's fault, so the refusal must carry ErrMalformedClaim, got %v", tc.reference, err)
			}
		})
	}
}

func TestInlineCertificate_AnEmptyChainIsRefusedNotPanicked(t *testing.T) {
	tests := map[string]struct {
		reference string
		chain     []string
	}{
		"a nil chain":    {reference: "RFC 7515 4.1.6", chain: nil},
		"an empty slice": {reference: "RFC 7515 4.1.6", chain: []string{}},
	}

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			defer func() {
				if r := recover(); r != nil {
					t.Fatalf("[%s] an empty chain reaches this retriever because validation accepts one, so it must be refused rather than panicking, got %v", tc.reference, r)
				}
			}()

			keys, err := InlineCertificate(tc.chain, nil, nil, "RS256", x509.NewCertPool())()
			if err == nil {
				t.Fatalf("[%s] a chain carrying no certificate cannot name a signing key, got %d keys", tc.reference, len(keys))
			}
			if len(keys) != 0 {
				t.Errorf("[%s] no key may be returned, got %d", tc.reference, len(keys))
			}
		})
	}
}

func TestRetrieveX5U_AnEmptyBodyIsRefusedNotPanicked(t *testing.T) {
	tests := map[string]struct {
		reference string
		body      string
	}{
		"a 200 with no body at all": {reference: "RFC 7515 4.1.5", body: ""},
		"a 200 carrying whitespace": {reference: "RFC 7515 4.1.5", body: "   \n"},
	}

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			defer func() {
				if r := recover(); r != nil {
					t.Fatalf("[%s] the x5u URL is written by the peer, so a response carrying no certificate must be refused rather than panicking, got %v", tc.reference, r)
				}
			}()

			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				w.WriteHeader(http.StatusOK)
				if _, err := w.Write([]byte(tc.body)); err != nil {
					return
				}
			}))
			defer server.Close()

			keys, err := RetrieveX5U(server.URL, server.Client(), nil, nil, "RS256", x509.NewCertPool())()
			if err == nil && len(keys) != 0 {
				t.Fatalf("[%s] a response carrying no certificate must not yield a key, got %d", tc.reference, len(keys))
			}
		})
	}
}

func TestValidateCertificateChain_AnEntryThatIsNotBase64IsStillRefused(t *testing.T) {
	err := ValidateCertificateChain(map[string]any{}, []string{"!!!not base64!!!"})
	if err == nil {
		t.Fatal("[RFC 7515 4.1.6] each entry is base64-encoded DER, so an entry that is not base64 must be refused")
	}
	if !errors.Is(err, joseerror.ErrMalformedClaim) {
		t.Errorf("expected ErrMalformedClaim, got %v", err)
	}
	if _, decodeErr := base64.StdEncoding.DecodeString("!!!not base64!!!"); decodeErr == nil {
		t.Fatal("the fixture must not be valid base64, or this row asserts nothing")
	}
}
