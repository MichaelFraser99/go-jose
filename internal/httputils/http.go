package httputils

import (
	"fmt"
	"io"
	"net/http"

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

type limitedReadCloser struct {
	io.Reader
	closer io.Closer
}

func (l limitedReadCloser) Close() error { return l.closer.Close() }

func RetrieveResource(client *http.Client, url, alias string) (*http.Response, error) {
	if client == nil {
		return nil, fmt.Errorf("%w%s is specified but no client exists", joseerror.ErrApplicationError, alias)
	}

	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return nil, fmt.Errorf("%wfailed to create request to specified %s: %w", joseerror.ErrApplicationError, alias, err)
	}

	response, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("%wfailed to retrieve %s: %w", joseerror.ErrApplicationError, alias, err)
	}

	if response.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("%wfailed to retrieve %s: received status code %d", joseerror.ErrApplicationError, alias, response.StatusCode)
	}

	if response.Body != nil {
		response.Body = limitedReadCloser{
			Reader: io.LimitReader(response.Body, MaxBodyBytes+1),
			closer: response.Body,
		}
	}

	return response, nil
}
