package httputils

import (
	"context"
	"errors"
	"net"
	"net/http"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
)

func TestRetrieveResource_AFailedFetchPutsNoRawLineBreakIntoItsError(t *testing.T) {
	breaks := []string{" ", " ", "\u0085", "\r"}
	tests := map[string]struct {
		fetch          func(t *testing.T) error
		causeCarriesIt bool
	}{
		"a host carrying U+2028, U+2029 and U+0085 that cannot resolve": {
			fetch: func(t *testing.T) error {
				_, err := RetrieveResource(context.Background(), &http.Client{}, 0, "https://a b c\u0085d.invalid/jwks", "jku")
				return err
			},
			causeCarriesIt: true,
		},
		"a redirect hop whose path carries U+2028, U+2029 and U+0085": {
			fetch: func(t *testing.T) error {
				var hits atomic.Int64
				plain := countingServer(t, false, &hits, serveKeySet)
				start := countingServer(t, true, &hits, redirectTo(plain.URL+"/  \u0085"))
				_, err := RetrieveResource(context.Background(), start.Client(), 0, start.URL, "jku")
				return err
			},
		},
		"a host carrying a lone carriage return": {
			fetch: func(t *testing.T) error {
				_, err := RetrieveResource(context.Background(), &http.Client{}, 0, "https://a\rb.invalid/jwks", "jku")
				return err
			},
		},
	}
	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			err := tc.fetch(t)
			if err == nil {
				t.Fatalf("%s must fail to fetch", name)
			}
			if tc.causeCarriesIt {
				var dnsErr *net.DNSError
				if !errors.As(err, &dnsErr) || !strings.Contains(dnsErr.Name, " ") {
					t.Fatalf("the cause must repeat the host with its line breaks, or this case proves nothing, got %s", strconv.Quote(err.Error()))
				}
			}
			for _, lineBreak := range breaks {
				if strings.Contains(err.Error(), lineBreak) {
					t.Errorf("[README Errors] a peer cannot put a raw line break into your logs, but the error carries %q raw: %s", lineBreak, strconv.Quote(err.Error()))
				}
			}
		})
	}
}
