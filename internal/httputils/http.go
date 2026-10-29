package httputils

import (
	"context"
	"errors"
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
	ctx    context.Context
	cancel context.CancelFunc
}

func (l limitedReadCloser) Read(p []byte) (int, error) {
	n, err := l.Reader.Read(p)
	if errors.Is(err, io.EOF) {
		if cause := l.ctx.Err(); cause != nil {
			return n, cause
		}
	}
	return n, err
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

var errNotTLS = errors.New("refusing a request that does not use TLS")

type httpsOnly struct {
	next http.RoundTripper
}

func (h httpsOnly) RoundTrip(request *http.Request) (*http.Response, error) {
	if request.URL.Scheme != "https" {
		return nil, errNotTLS
	}
	next := h.next
	if next == nil {
		next = http.DefaultTransport
	}
	return next.RoundTrip(request)
}

// RetrieveResource fetches url through a copy of client whose transport refuses any
// hop that is not https, keeping the client's own transport and redirect policy.
// The copy has no cookie jar, so the fetch sends no cookies and keeps none, as RFC
// 8725 section 3.10 asks of a jku or x5u request.
// The fetch is bounded by the earlier of timeout and the client's own Timeout, so a
// body that either limit cuts short is never taken as complete.
func RetrieveResource(ctx context.Context, client *http.Client, timeout time.Duration, url, alias string) (*http.Response, error) {
	if client == nil {
		return nil, fmt.Errorf("%w%s is specified but no client exists", joseerror.ErrApplicationError, alias)
	}
	tlsOnly := *client
	tlsOnly.Transport = httpsOnly{next: client.Transport}
	tlsOnly.Jar = nil
	limit := timeoutOrDefault(timeout)
	if client.Timeout > 0 && client.Timeout < limit {
		limit = client.Timeout
	}

	ctx, cancel := context.WithTimeout(ctx, limit)

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		cancel()
		return nil, fmt.Errorf("%wfailed to create request to specified %s: %w", joseerror.ErrApplicationError, alias, err)
	}

	response, err := tlsOnly.Do(req)
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
		ctx:    ctx,
		cancel: cancel,
	}
	return response, nil
}

// ReadBody reads a fetched resource up to MaxBodyBytes and closes the body on every
// path, releasing the connection and the fetch deadline.
func ReadBody(response *http.Response, alias string) ([]byte, error) {
	if response.Body == nil {
		return nil, fmt.Errorf("%wfailed to retrieve %s: response body is nil", joseerror.ErrApplicationError, alias)
	}
	defer func() { _ = response.Body.Close() }()

	body, err := io.ReadAll(response.Body)
	if err != nil {
		return nil, fmt.Errorf("%wfailed to read %s response: %w", joseerror.ErrApplicationError, alias, err)
	}
	if int64(len(body)) > MaxBodyBytes {
		return nil, fmt.Errorf("%w%s response exceeded the %d byte limit", joseerror.ErrApplicationError, alias, MaxBodyBytes)
	}
	return body, nil
}
