package httputils

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"time"

	"github.com/MichaelFraser99/go-jose/joseerror"
)

// MaxBodyBytes caps how much of a retrieved resource a caller can read. The URLs
// this fetches come from the JOSE header of the token being verified, so a peer
// chooses both the address and the size of the answer.
//
// A caller reading the returned Body sees at most MaxBodyBytes+1 bytes, so it can
// tell an oversize body from one that exactly fills the cap, and report the former
// rather than parsing a truncated resource.
const MaxBodyBytes int64 = 4 << 20

// DefaultFetchTimeout bounds a fetch when JoseOptions.FetchTimeout is zero or less.
const DefaultFetchTimeout = 10 * time.Second

// Fetch retrieves a resource a token's header names, under the deadline the caller
// configured.
type Fetch func(url, alias string) (*http.Response, error)

// Fetcher binds a context, client and timeout into a Fetch.
func Fetcher(ctx context.Context, client *http.Client, timeout time.Duration) Fetch {
	return func(url, alias string) (*http.Response, error) {
		return RetrieveResource(ctx, client, timeout, url, alias)
	}
}

type limitedReadCloser struct {
	io.Reader
	closer io.Closer
	cancel context.CancelFunc
}

func (l limitedReadCloser) Close() error {
	defer l.cancel()
	return l.closer.Close()
}

func timeoutOrDefault(timeout time.Duration) time.Duration {
	if timeout <= 0 {
		return DefaultFetchTimeout
	}
	return timeout
}

func RetrieveResource(ctx context.Context, client *http.Client, timeout time.Duration, url, alias string) (*http.Response, error) {
	if client == nil {
		return nil, fmt.Errorf("%w%s is specified but no client exists", joseerror.ErrApplicationError, alias)
	}

	ctx, cancel := context.WithTimeout(ctx, timeoutOrDefault(timeout))

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		cancel()
		return nil, fmt.Errorf("%wfailed to create request to specified %s: %w", joseerror.ErrApplicationError, alias, err)
	}

	response, err := client.Do(req)
	if err != nil {
		cancel()
		return nil, fmt.Errorf("%wfailed to retrieve %s: %w", joseerror.ErrApplicationError, alias, err)
	}

	if response.StatusCode != http.StatusOK {
		cancel()
		_ = response.Body.Close()
		return nil, fmt.Errorf("%wfailed to retrieve %s: received status code %d", joseerror.ErrApplicationError, alias, response.StatusCode)
	}

	if response.Body == nil {
		cancel()
		return response, nil
	}
	response.Body = limitedReadCloser{
		Reader: io.LimitReader(response.Body, MaxBodyBytes+1),
		closer: response.Body,
		cancel: cancel,
	}
	return response, nil
}
