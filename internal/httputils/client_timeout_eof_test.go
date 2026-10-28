package httputils

import (
	"context"
	"errors"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"
)

type cutOffBody struct {
	ctx  context.Context
	sent bool
}

func (c *cutOffBody) Read(p []byte) (int, error) {
	if !c.sent {
		c.sent = true
		return copy(p, `{"keys":[`), nil
	}
	<-c.ctx.Done()
	return 0, io.EOF
}

func (c *cutOffBody) Close() error { return nil }

type cutOffTransport struct{}

func (cutOffTransport) RoundTrip(request *http.Request) (*http.Response, error) {
	return &http.Response{StatusCode: http.StatusOK, Body: &cutOffBody{ctx: request.Context()}, Header: http.Header{}, Request: request}, nil
}

func TestRetrieveResource_ABodyThatEndsCleanlyAfterTheCallersClientTimeoutIsNotComplete(t *testing.T) {
	client := &http.Client{Transport: cutOffTransport{}, Timeout: 50 * time.Millisecond}

	response, err := RetrieveResource(context.Background(), client, time.Hour, "https://keys.example/jwks", "jku")
	if err != nil {
		t.Fatal(err)
	}
	body, err := ReadBody(response, "jku")
	if err == nil {
		t.Fatalf("[net/http Client.Timeout] a body cut off by the caller's client Timeout must not be taken as complete, got %q", body)
	}
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Errorf("[JoseOptions.HttpClient] a fetch stopped by the client's Timeout must match context.DeadlineExceeded, as one stopped by FetchTimeout does, got %v", err)
	}
	if !strings.Contains(err.Error(), "jku") {
		t.Errorf("the error must name the header whose fetch failed, got %v", err)
	}
}

func TestRetrieveResource_TheEarlierOfFetchTimeoutAndTheClientTimeoutApplies(t *testing.T) {
	tests := map[string]struct {
		clientTimeout, fetchTimeout, within time.Duration
	}{
		"the client's Timeout is earlier": {clientTimeout: 50 * time.Millisecond, fetchTimeout: time.Hour, within: 50 * time.Millisecond},
		"FetchTimeout is earlier":         {clientTimeout: time.Hour, fetchTimeout: 50 * time.Millisecond, within: 50 * time.Millisecond},
		"the client sets no Timeout":      {clientTimeout: 0, fetchTimeout: 50 * time.Millisecond, within: 50 * time.Millisecond},
	}
	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			var deadline time.Time
			var hasDeadline bool
			client := &http.Client{Timeout: tc.clientTimeout, Transport: roundTripFunc(func(request *http.Request) (*http.Response, error) {
				deadline, hasDeadline = request.Context().Deadline()
				return &http.Response{StatusCode: http.StatusOK, Body: io.NopCloser(strings.NewReader(`{}`)), Header: http.Header{}, Request: request}, nil
			})}
			begin := time.Now()
			response, err := RetrieveResource(context.Background(), client, tc.fetchTimeout, "https://keys.example/jwks", "jku")
			if err != nil {
				t.Fatal(err)
			}
			if _, err := ReadBody(response, "jku"); err != nil {
				t.Fatal(err)
			}
			if !hasDeadline || deadline.Sub(begin) > tc.within+time.Second {
				t.Errorf("[JoseOptions.FetchTimeout] the fetch must be bounded by the earlier limit, %v, got a deadline %v away", tc.within, deadline.Sub(begin))
			}
		})
	}
}

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(request *http.Request) (*http.Response, error) { return f(request) }
