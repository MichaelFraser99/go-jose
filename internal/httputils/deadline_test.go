package httputils

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/MichaelFraser99/go-jose/joseerror"
)

const bound = 2 * time.Second

func stallingServer(t *testing.T, sendHeaders bool) *httptest.Server {
	t.Helper()
	release := make(chan struct{})
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if sendHeaders {
			w.WriteHeader(http.StatusOK)
			if _, err := w.Write([]byte(`{"keys":[`)); err != nil {
				return
			}
			w.(http.Flusher).Flush()
		}
		select {
		case <-r.Context().Done():
		case <-release:
		}
	}))
	t.Cleanup(func() {
		close(release)
		server.Close()
	})
	return server
}

func fetchAll(ctx context.Context, client *http.Client, timeout time.Duration, url string) error {
	response, err := RetrieveResource(ctx, client, timeout, url, "jku")
	if err != nil {
		return err
	}
	defer func() { _ = response.Body.Close() }()
	_, err = io.ReadAll(response.Body)
	return err
}

func TestRetrieveResource_AStallingPeerIsCutOffByTheTimeout(t *testing.T) {
	tests := map[string]bool{
		"a peer that never sends headers":                    false,
		"a peer that sends headers and then stalls the body": true,
	}

	for name, sendHeaders := range tests {
		t.Run(name, func(t *testing.T) {
			server := stallingServer(t, sendHeaders)
			client := &http.Client{}

			start := time.Now()
			err := fetchAll(context.Background(), client, 100*time.Millisecond, server.URL)
			elapsed := time.Since(start)

			if err == nil {
				t.Fatal("[JoseOptions.FetchTimeout] a fetch that outlives its timeout must fail")
			}
			if elapsed > bound {
				t.Errorf("[JoseOptions.FetchTimeout] the timeout bounds the whole fetch, headers and body, so a 100ms timeout must not take %v, even with a client that sets no Timeout", elapsed)
			}
		})
	}
}

func TestRetrieveResource_TheCallersContextCutsAFetchShort(t *testing.T) {
	server := stallingServer(t, true)
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()

	start := time.Now()
	err := fetchAll(ctx, &http.Client{}, time.Hour, server.URL)
	elapsed := time.Since(start)

	if err == nil {
		t.Fatal("a fetch must fail once the caller's context is done")
	}
	if elapsed > bound {
		t.Errorf("the caller's own deadline must cut a fetch short however long FetchTimeout allows, took %v", elapsed)
	}
}

func TestRetrieveResource_AFetchStoppedBeforeHeadersKeepsItsContextErrorClass(t *testing.T) {
	tests := map[string]struct {
		fetchTimeout time.Duration
		cancelAfter  time.Duration
		want         error
		reference    string
	}{
		"FetchTimeout expires": {
			fetchTimeout: 100 * time.Millisecond, want: context.DeadlineExceeded,
			reference: "JoseOptions.FetchTimeout",
		},
		"the caller cancels ctx": {
			fetchTimeout: time.Hour, cancelAfter: 100 * time.Millisecond, want: context.Canceled,
			reference: "the ctx passed to VerifyCompactSerialization",
		},
	}

	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			server := stallingServer(t, false)
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			if test.cancelAfter > 0 {
				time.AfterFunc(test.cancelAfter, cancel)
			}

			response, err := RetrieveResource(ctx, &http.Client{}, test.fetchTimeout, server.URL, "jku")
			if err == nil {
				_ = response.Body.Close()
				t.Fatalf("[%s] a peer that never sends headers yields no resource", test.reference)
			}
			if !errors.Is(err, test.want) {
				t.Errorf("[%s] a fetch stopped before headers arrive must match %v, got %v", test.reference, test.want, err)
			}
			if !errors.Is(err, joseerror.ErrApplicationError) {
				t.Errorf("[%s] a failed fetch must match ErrApplicationError, got %v", test.reference, err)
			}
		})
	}
}

func TestTimeoutOrDefault_NeverMeansNoTimeout(t *testing.T) {
	tests := map[string]struct {
		given, want time.Duration
	}{
		"unset":    {given: 0, want: DefaultFetchTimeout},
		"negative": {given: -time.Second, want: DefaultFetchTimeout},
		"set":      {given: 3 * time.Second, want: 3 * time.Second},
	}

	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			if got := timeoutOrDefault(test.given); got != test.want {
				t.Errorf("[JoseOptions.FetchTimeout] %v must resolve to %v, got %v", test.given, test.want, got)
			}
		})
	}
	if DefaultFetchTimeout <= 0 {
		t.Errorf("the default must be a real bound, got %v", DefaultFetchTimeout)
	}
}
