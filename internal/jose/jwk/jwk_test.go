package jwk

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/MichaelFraser99/go-jose/internal/httputils"
	"github.com/MichaelFraser99/go-jose/joseerror"
)

func TestRetrieveJKU_RefusesAKeySetLargerThanTheCap(t *testing.T) {
	tests := map[string]struct {
		size   int64
		refuse bool
	}{
		"a key set one byte over the cap": {size: httputils.MaxBodyBytes + 1, refuse: true},
		"a key set far over the cap":      {size: httputils.MaxBodyBytes * 2, refuse: true},
	}

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				if _, err := io.WriteString(w, `{"keys":[`); err != nil {
					return
				}
				written := int64(len(`{"keys":[`))
				filler := strings.Repeat(" ", 4096)
				for written < tc.size {
					n, err := io.WriteString(w, filler)
					if err != nil {
						return
					}
					written += int64(n)
				}
			}))
			defer server.Close()

			keys, err := RetrieveJKU(server.URL, httputils.Fetcher(context.Background(), server.Client(), 0), nil, "RS256")()
			if !tc.refuse {
				return
			}
			if err == nil {
				t.Fatalf("a key set beyond the cap must be refused, got %d keys", len(keys))
			}
			if !strings.Contains(err.Error(), "exceeded the") {
				t.Errorf("the refusal must name the size limit rather than blaming the content, got %v", err)
			}
			if !errors.Is(err, joseerror.ErrApplicationError) {
				t.Errorf("expected ErrApplicationError, got %v", err)
			}
		})
	}
}
