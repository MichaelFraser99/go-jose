package httputils

import (
	"bytes"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/MichaelFraser99/go-jose/joseerror"
)

type closeRecordingBody struct {
	io.Reader
	closed *bool
}

func (c closeRecordingBody) Close() error {
	*c.closed = true
	return nil
}

type endlessReader struct{}

func (endlessReader) Read(p []byte) (int, error) {
	for i := range p {
		p[i] = 'a'
	}
	return len(p), nil
}

type stubTransport struct {
	body io.ReadCloser
}

func (s stubTransport) RoundTrip(*http.Request) (*http.Response, error) {
	return &http.Response{StatusCode: http.StatusOK, Body: s.body, Header: http.Header{}}, nil
}

func TestRetrieveResource_ReadsNoMoreThanTheCapPlusOneByte(t *testing.T) {
	tests := map[string]int64{
		"a body well under the cap": 1024,
		"a body one byte under":     MaxBodyBytes - 1,
		"a body exactly at the cap": MaxBodyBytes,
		"a body one byte over":      MaxBodyBytes + 1,
		"a body far over the cap":   MaxBodyBytes * 3,
	}

	for name, size := range tests {
		t.Run(name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				if _, err := io.CopyN(w, endlessReader{}, size); err != nil {
					return
				}
			}))
			defer server.Close()

			response, err := RetrieveResource(server.Client(), server.URL, "test")
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			read, err := io.ReadAll(response.Body)
			if err != nil {
				t.Fatalf("failed to read the body: %v", err)
			}
			if err := response.Body.Close(); err != nil {
				t.Fatalf("failed to close the body: %v", err)
			}

			if int64(len(read)) > MaxBodyBytes+1 {
				t.Errorf("a caller must not be able to read more than the cap plus one byte, so an oversize body can be detected but not held: read %d of a %d byte body, cap is %d", len(read), size, MaxBodyBytes)
			}
			if size <= MaxBodyBytes && int64(len(read)) != size {
				t.Errorf("a body within the cap must be readable in full: read %d of %d", len(read), size)
			}
			if size > MaxBodyBytes && int64(len(read)) != MaxBodyBytes+1 {
				t.Errorf("a body over the cap must read as exactly the cap plus one byte, so the caller can tell it was truncated: read %d, want %d", len(read), MaxBodyBytes+1)
			}
		})
	}
}

func TestRetrieveResource_ClosingTheWrappedBodyClosesTheUnderlyingOne(t *testing.T) {
	closed := false
	client := &http.Client{Transport: stubTransport{
		body: closeRecordingBody{Reader: bytes.NewReader([]byte("a key set")), closed: &closed},
	}}

	response, err := RetrieveResource(client, "https://example.com/jwks", "test")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if _, err := io.ReadAll(response.Body); err != nil {
		t.Fatalf("failed to read the body: %v", err)
	}
	if err := response.Body.Close(); err != nil {
		t.Fatalf("failed to close the body: %v", err)
	}

	if !closed {
		t.Error("closing the capped body must close the body underneath it, or the connection is never released")
	}
}

func TestRetrieveResource_AResponseWithNoBodyIsStillUsable(t *testing.T) {
	client := &http.Client{Transport: stubTransport{body: nil}}

	response, err := RetrieveResource(client, "https://example.com/jwks", "test")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if response.Body == nil {
		return
	}
	read, err := io.ReadAll(response.Body)
	if err != nil {
		t.Fatalf("a response carrying no body must still read cleanly: %v", err)
	}
	if len(read) != 0 {
		t.Errorf("expected no bytes, got %d", len(read))
	}
	if err := response.Body.Close(); err != nil {
		t.Errorf("a response carrying no body must still close cleanly: %v", err)
	}
}

func TestRetrieveResource_RefusesWithoutAClient(t *testing.T) {
	_, err := RetrieveResource(nil, "https://example.com/jwks", "jku")
	if err == nil {
		t.Fatal("expected an error with no client")
	}
	if !errors.Is(err, joseerror.ErrApplicationError) {
		t.Errorf("expected ErrApplicationError, got %v", err)
	}
}
