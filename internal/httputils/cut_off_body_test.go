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

type endsCleanlyWhenCancelled struct {
	ctx     context.Context
	partial io.Reader
}

func (b *endsCleanlyWhenCancelled) Read(p []byte) (int, error) {
	if n, err := b.partial.Read(p); n > 0 || err == nil {
		return n, nil
	}
	<-b.ctx.Done()
	return 0, io.EOF
}

func (b *endsCleanlyWhenCancelled) Close() error { return nil }

type cleanEOFTransport struct{}

func (cleanEOFTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	return &http.Response{
		StatusCode: http.StatusOK,
		Header:     http.Header{},
		Body:       &endsCleanlyWhenCancelled{ctx: r.Context(), partial: strings.NewReader(`{"keys":[`)},
	}, nil
}

func TestReadBody_ABodyCutOffByItsDeadlineIsNotTakenAsComplete(t *testing.T) {
	tests := map[string]struct {
		ctx     func() (context.Context, context.CancelFunc)
		timeout time.Duration
		want    error
	}{
		"FetchTimeout expires": {
			ctx:     func() (context.Context, context.CancelFunc) { return context.WithCancel(context.Background()) },
			timeout: 50 * time.Millisecond,
			want:    context.DeadlineExceeded,
		},
		"the caller's deadline expires": {
			ctx: func() (context.Context, context.CancelFunc) {
				return context.WithTimeout(context.Background(), 50*time.Millisecond)
			},
			timeout: time.Hour,
			want:    context.DeadlineExceeded,
		},
		"the caller cancels": {
			ctx: func() (context.Context, context.CancelFunc) {
				ctx, cancel := context.WithCancel(context.Background())
				time.AfterFunc(50*time.Millisecond, cancel)
				return ctx, cancel
			},
			timeout: time.Hour,
			want:    context.Canceled,
		},
	}

	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			ctx, cancel := test.ctx()
			defer cancel()

			response, err := RetrieveResource(ctx, &http.Client{Transport: cleanEOFTransport{}}, test.timeout, "https://example.com/jwks", "jku")
			if err != nil {
				t.Fatalf("the response arrives before the bound, got %v", err)
			}
			body, err := ReadBody(response, "jku")
			if err == nil {
				t.Fatalf("[JoseOptions.FetchTimeout] a body still arriving when its fetch's context ended is incomplete, however its read ends, but %q was returned as whole", body)
			}
			if !errors.Is(err, test.want) {
				t.Errorf("[JoseOptions.FetchTimeout] expected the cut-off to match %v, got %v", test.want, err)
			}
		})
	}
}
