package httputils

import (
	"context"
	"errors"
	"net/http"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/MichaelFraser99/go-jose/joseerror"
)

func TestRetrieveResource_ARefusedRedirectHopIsNotEchoedUnbounded(t *testing.T) {
	long := strings.Repeat("a", 1<<20)
	tests := map[string]struct {
		location func(httpsURL, plainURL string) string
		allowed  func(startURL string) []string
		sentinel error
	}{
		"a hop that is not https": {
			location: func(_, plainURL string) string { return plainURL + "/" + long },
			allowed:  func(string) []string { return nil },
			sentinel: errNotTLS,
		},
		"a hop not in AllowedKeyURLs": {
			location: func(httpsURL, _ string) string { return httpsURL + "/" + long },
			allowed:  func(startURL string) []string { return []string{startURL} },
			sentinel: errNotAllowed,
		},
	}
	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			var targetHits, plainHits, startHits atomic.Int64
			target := countingServer(t, true, &targetHits, serveKeySet)
			plain := countingServer(t, false, &plainHits, serveKeySet)
			start := countingServer(t, true, &startHits, redirectTo(tc.location(target.URL, plain.URL)))

			response, err := Fetcher(context.Background(), start.Client(), 0, tc.allowed(start.URL))(start.URL, "jku")
			if err == nil {
				_ = response.Body.Close()
				t.Fatalf("[draft-ietf-oauth-rfc8725bis 3.10] %s must be refused", name)
			}
			if startHits.Load() != 1 {
				t.Fatalf("the redirect carrying the long URL must have been served, or this case proves nothing, got %d requests", startHits.Load())
			}
			if !errors.Is(err, joseerror.ErrApplicationError) || !errors.Is(err, tc.sentinel) {
				t.Errorf("[README Errors] %s must still match ErrApplicationError and its refusal, got %v", name, err)
			}
			if strings.Contains(err.Error(), strings.Repeat("a", 65)) || len(err.Error()) > 512 {
				t.Errorf("[README Errors] an echoed value is cut to 64 characters, so the error must not carry the %d-byte URL the peer's server chose, got %d bytes", len(long), len(err.Error()))
			}
			if targetHits.Load() != 0 || plainHits.Load() != 0 {
				t.Errorf("[draft-ietf-oauth-rfc8725bis 3.10] the refused hop must not be sent, got %d and %d requests", targetHits.Load(), plainHits.Load())
			}
		})
	}
}

func TestRetrieveResource_AFailedFetchOfALongURLIsNotEchoedUnbounded(t *testing.T) {
	tests := map[string]string{
		"a long path on a closed port":    "https://127.0.0.1:1/" + strings.Repeat("a", 1<<20),
		"a long host that cannot resolve": "https://" + strings.Repeat("a", 1<<16) + ".invalid/jwks",
	}
	for name, long := range tests {
		t.Run(name, func(t *testing.T) {
			response, err := RetrieveResource(context.Background(), &http.Client{}, 0, long, "jku")
			if err == nil {
				_ = response.Body.Close()
				t.Fatalf("%s must fail to fetch", name)
			}
			if !errors.Is(err, joseerror.ErrApplicationError) {
				t.Errorf("[README Errors] a failed fetch must match ErrApplicationError, got %v", err)
			}
			if strings.Contains(err.Error(), strings.Repeat("a", MaxCauseRunes+1)) || len(err.Error()) > 512 {
				t.Errorf("[README Errors] the URL is cut to 64 characters and the cause to %d, so the error must not carry the %d-byte URL a token chose, got %d bytes", MaxCauseRunes, len(long), len(err.Error()))
			}
		})
	}
}
