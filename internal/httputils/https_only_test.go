package httputils

import (
	"context"
	"crypto/x509"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/MichaelFraser99/go-jose/joseerror"
)

func countingServer(t *testing.T, tls bool, hits *atomic.Int64, handler http.HandlerFunc) *httptest.Server {
	t.Helper()
	counted := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		handler(w, r)
	})
	var server *httptest.Server
	if tls {
		server = httptest.NewTLSServer(counted)
	} else {
		server = httptest.NewServer(counted)
	}
	t.Cleanup(server.Close)
	return server
}

func redirectTo(location string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, location, http.StatusFound)
	}
}

func serveKeySet(w http.ResponseWriter, _ *http.Request) {
	if _, err := io.WriteString(w, `{"keys":[]}`); err != nil {
		return
	}
}

func TestRetrieveResource_EveryHopMustUseTLS(t *testing.T) {
	tests := map[string]struct {
		reference string
		start     func(t *testing.T, plainURL string) *httptest.Server
		fromPlain bool
	}{
		"a redirect from https to plain http": {
			reference: "RFC 7515 4.1.2, 4.1.5",
			start: func(t *testing.T, plainURL string) *httptest.Server {
				var hits atomic.Int64
				return countingServer(t, true, &hits, redirectTo(plainURL))
			},
		},
		"a redirect to plain http after an https hop": {
			reference: "RFC 7515 4.1.2, 4.1.5",
			start: func(t *testing.T, plainURL string) *httptest.Server {
				var hits atomic.Int64
				second := countingServer(t, true, &hits, redirectTo(plainURL))
				return countingServer(t, true, &hits, redirectTo(second.URL))
			},
		},
		"a redirect to plain http spelt in upper case": {
			reference: "RFC 7515 4.1.2, 4.1.5",
			start: func(t *testing.T, plainURL string) *httptest.Server {
				var hits atomic.Int64
				return countingServer(t, true, &hits, redirectTo("HTTP"+strings.TrimPrefix(plainURL, "http")))
			},
		},
		"a plain http URL to begin with": {
			reference: "RFC 7515 4.1.2, 4.1.5",
			fromPlain: true,
		},
	}

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			var plainHits atomic.Int64
			plain := countingServer(t, false, &plainHits, serveKeySet)

			client := plain.Client()
			url := plain.URL
			if !tc.fromPlain {
				start := tc.start(t, plain.URL)
				client = start.Client()
				url = start.URL
			}

			response, err := RetrieveResource(context.Background(), client, 0, url, "jku")
			if err == nil {
				_ = response.Body.Close()
				t.Fatalf("[%s] an HTTP GET to retrieve the resource MUST use TLS, so %s must not yield the resource", tc.reference, name)
			}
			if !errors.Is(err, joseerror.ErrApplicationError) {
				t.Errorf("[%s] a refused fetch must match ErrApplicationError, got %v", tc.reference, err)
			}
			if !errors.Is(err, errNotTLS) {
				t.Errorf("[%s] the fetch must be refused for not using TLS, got %v", tc.reference, err)
			}
			if got := plainHits.Load(); got != 0 {
				t.Errorf("[%s] the request must be refused before it is sent in clear, but the plain http server saw %d", tc.reference, got)
			}
		})
	}
}

type countingRoundTripper struct {
	hits *atomic.Int64
}

func (c countingRoundTripper) RoundTrip(*http.Request) (*http.Response, error) {
	c.hits.Add(1)
	return &http.Response{StatusCode: http.StatusOK, Body: io.NopCloser(strings.NewReader(`{"keys":[]}`)), Header: http.Header{}}, nil
}

func TestRetrieveResource_ARedirectToASchemeTheCallersTransportServesIsRefused(t *testing.T) {
	var hits, protocolHits atomic.Int64
	start := countingServer(t, true, &hits, redirectTo("cleartext://example.com/jwks"))

	client := start.Client()
	transport := client.Transport.(*http.Transport).Clone()
	transport.RegisterProtocol("cleartext", countingRoundTripper{hits: &protocolHits})
	client.Transport = transport

	response, err := RetrieveResource(context.Background(), client, 0, start.URL, "jku")
	if err == nil {
		_ = response.Body.Close()
		t.Fatal("[RFC 7515 4.1.2, 4.1.5] a hop that is not https must not yield the resource, whatever schemes the caller's transport serves")
	}
	if !errors.Is(err, errNotTLS) {
		t.Errorf("[RFC 7515 4.1.2, 4.1.5] the fetch must be refused for not using TLS, got %v", err)
	}
	if got := protocolHits.Load(); got != 0 {
		t.Errorf("[RFC 7515 4.1.2, 4.1.5] the request must be refused before it is sent, but the caller's protocol saw %d", got)
	}
}

func TestRetrieveResource_AnHttpsRedirectIsStillFollowed(t *testing.T) {
	var hits atomic.Int64
	target := countingServer(t, true, &hits, serveKeySet)
	start := countingServer(t, true, &hits, redirectTo(target.URL+"/jwks"))

	body, err := ReadBody(mustRetrieve(t, start.Client(), start.URL), "jku")
	if err != nil {
		t.Fatalf("[RFC 7515 4.1.2] a redirect that stays on https must be followed, got %v", err)
	}
	if string(body) != `{"keys":[]}` {
		t.Errorf("[RFC 7515 4.1.2] expected the redirected resource, got %q", body)
	}
	if got := hits.Load(); got != 2 {
		t.Errorf("[RFC 7515 4.1.2] expected one request to each server, got %d", got)
	}
}

func mustRetrieve(t *testing.T, client *http.Client, url string) *http.Response {
	t.Helper()
	response, err := RetrieveResource(context.Background(), client, 0, url, "jku")
	if err != nil {
		t.Fatalf("[RFC 7515 4.1.2] unexpected error: %v", err)
	}
	return response
}

func TestRetrieveResource_TheCallersRedirectPolicyStillApplies(t *testing.T) {
	var hits atomic.Int64
	target := countingServer(t, true, &hits, serveKeySet)
	start := countingServer(t, true, &hits, redirectTo(target.URL))

	consulted := 0
	client := start.Client()
	client.CheckRedirect = func(*http.Request, []*http.Request) error {
		consulted++
		return http.ErrUseLastResponse
	}

	response, err := RetrieveResource(context.Background(), client, 0, start.URL, "jku")
	if err == nil {
		_ = response.Body.Close()
		t.Fatal("[JoseOptions.HttpClient] a caller whose redirect policy declines to follow must not be handed the redirected resource")
	}
	if consulted != 1 {
		t.Errorf("[JoseOptions.HttpClient] the caller's CheckRedirect must be consulted for the redirect, consulted %d times", consulted)
	}
	if got := hits.Load(); got != 1 {
		t.Errorf("[JoseOptions.HttpClient] the redirect target must not be fetched, got %d requests", got)
	}
}

func TestRetrieveResource_AnEndlessRedirectStopsAtTheDefaultLimit(t *testing.T) {
	var hits atomic.Int64
	var server *httptest.Server
	server = countingServer(t, true, &hits, func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, server.URL, http.StatusFound)
	})

	response, err := RetrieveResource(context.Background(), server.Client(), 0, server.URL, "jku")
	if err == nil {
		_ = response.Body.Close()
		t.Fatal("[net/http Client.CheckRedirect] a redirect loop must not yield a resource")
	}
	if got := hits.Load(); got != 10 {
		t.Errorf("[net/http Client.CheckRedirect] with no CheckRedirect the client stops after 10 consecutive requests, got %d", got)
	}
}

func TestRetrieveResource_TheCallersClientTimeoutStillApplies(t *testing.T) {
	stalling := stallingServer(t, true)
	client := stalling.Client()
	client.Timeout = 100 * time.Millisecond

	begin := time.Now()
	err := fetchAll(context.Background(), client, time.Hour, stalling.URL)
	elapsed := time.Since(begin)

	if err == nil {
		t.Fatal("[net/http Client.Timeout] a fetch that outlives the caller's client Timeout must fail")
	}
	if elapsed > bound {
		t.Errorf("[net/http Client.Timeout] the caller's client Timeout must survive the https-only wrapping, so 100ms must not take %v", elapsed)
	}
}

func TestRetrieveResource_TheTimeoutCoversEveryHop(t *testing.T) {
	stalling := stallingServer(t, true)
	var hits atomic.Int64
	start := countingServer(t, true, &hits, redirectTo(stalling.URL))

	begin := time.Now()
	err := fetchAll(context.Background(), start.Client(), 100*time.Millisecond, start.URL)
	elapsed := time.Since(begin)

	if err == nil {
		t.Fatal("[JoseOptions.FetchTimeout] a fetch whose redirect target stalls must fail")
	}
	if elapsed > bound {
		t.Errorf("[JoseOptions.FetchTimeout] the timeout bounds every hop of a fetch, so a 100ms timeout must not take %v", elapsed)
	}
}

func TestRetrieveResource_AClientWithNoTransportUsesTheDefaultOne(t *testing.T) {
	var hits atomic.Int64
	server := countingServer(t, true, &hits, serveKeySet)

	response, err := RetrieveResource(context.Background(), &http.Client{}, 0, server.URL, "jku")
	if err == nil {
		_ = response.Body.Close()
		t.Fatal("[net/http Client.Transport] the default transport does not trust the test server's certificate, so the fetch must fail")
	}
	var unknownAuthority x509.UnknownAuthorityError
	if !errors.As(err, &unknownAuthority) {
		t.Errorf("[net/http Client.Transport] a nil Transport means http.DefaultTransport, which must refuse the untrusted certificate, got %v", err)
	}
}
