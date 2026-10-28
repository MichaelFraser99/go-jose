package httputils

import (
	"context"
	"errors"
	"io"
	"net/http"
	"strings"
	"testing"

	"github.com/MichaelFraser99/go-jose/joseerror"
)

type statusTransport struct {
	status int
	body   io.ReadCloser
}

func (s statusTransport) RoundTrip(*http.Request) (*http.Response, error) {
	return &http.Response{StatusCode: s.status, Body: s.body, Header: http.Header{}}, nil
}

type failingBody struct {
	closed *bool
}

func (failingBody) Read([]byte) (int, error) { return 0, io.ErrUnexpectedEOF }

func (f failingBody) Close() error {
	*f.closed = true
	return nil
}

func TestRetrieveResource_ARefusedResponseHasItsBodyClosed(t *testing.T) {
	closed := false
	client := &http.Client{Transport: statusTransport{
		status: http.StatusNotFound,
		body:   closeRecordingBody{Reader: strings.NewReader("not here"), closed: &closed},
	}}

	if _, err := RetrieveResource(context.Background(), client, 0, "https://example.com/jwks", "jku"); err == nil {
		t.Fatal("a 404 must be refused")
	}
	if !closed {
		t.Error("a refused response's body must be closed, or its connection is never released")
	}
}

func TestReadBody_ClosesTheBodyWhateverHappens(t *testing.T) {
	tests := map[string]struct {
		body    func(closed *bool) io.ReadCloser
		refused bool
	}{
		"a body that reads cleanly": {
			body: func(closed *bool) io.ReadCloser {
				return closeRecordingBody{Reader: strings.NewReader("a key set"), closed: closed}
			},
		},
		"a body whose read fails": {
			body:    func(closed *bool) io.ReadCloser { return failingBody{closed: closed} },
			refused: true,
		},
		"a body over the cap": {
			body: func(closed *bool) io.ReadCloser {
				return closeRecordingBody{Reader: io.LimitReader(endlessReader{}, MaxBodyBytes+1), closed: closed}
			},
			refused: true,
		},
	}

	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			closed := false
			_, err := ReadBody(&http.Response{Body: test.body(&closed)}, "jku")
			if test.refused && err == nil {
				t.Error("expected the body to be refused")
			}
			if !test.refused && err != nil {
				t.Errorf("expected the body to be read, got %v", err)
			}
			if !closed {
				t.Error("the body must be closed on every path, or the connection and the fetch deadline are held until the timeout fires")
			}
		})
	}
}

func TestReadBody_ABodyThatExactlyFillsTheCapIsReadAndOneByteMoreIsRefused(t *testing.T) {
	tests := map[string]struct {
		size    int64
		refused bool
	}{
		"exactly MaxBodyBytes":  {size: MaxBodyBytes},
		"one byte past the cap": {size: MaxBodyBytes + 1, refused: true},
	}

	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			closed := false
			body := closeRecordingBody{Reader: io.LimitReader(endlessReader{}, test.size), closed: &closed}
			read, err := ReadBody(&http.Response{Body: body}, "jku")
			if test.refused {
				if !errors.Is(err, joseerror.ErrApplicationError) {
					t.Errorf("[MaxBodyBytes] a body past the cap must be refused with ErrApplicationError, got %v", err)
				}
				return
			}
			if err != nil {
				t.Fatalf("[MaxBodyBytes] a body that exactly fills the cap is within it, got %v", err)
			}
			if int64(len(read)) != test.size {
				t.Errorf("[MaxBodyBytes] expected all %d bytes, got %d", test.size, len(read))
			}
		})
	}
}

func TestReadBody_RefusesAResponseWithNoBody(t *testing.T) {
	_, err := ReadBody(&http.Response{}, "jku")
	if err == nil {
		t.Fatal("a response with no body carries no resource")
	}
	if !errors.Is(err, joseerror.ErrApplicationError) {
		t.Errorf("expected ErrApplicationError, got %v", err)
	}
}
