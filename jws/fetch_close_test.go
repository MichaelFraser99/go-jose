package jws

import (
	"context"
	"crypto/x509"
	"errors"
	"io"
	"net/http"
	"testing"

	"github.com/MichaelFraser99/go-jose/joseerror"
	"github.com/MichaelFraser99/go-jose/model"
)

type unreadableBody struct {
	closed *bool
}

func (unreadableBody) Read([]byte) (int, error) { return 0, io.ErrUnexpectedEOF }

func (u unreadableBody) Close() error {
	*u.closed = true
	return nil
}

type unreadableBodyTransport struct {
	body unreadableBody
}

func (u unreadableBodyTransport) RoundTrip(*http.Request) (*http.Response, error) {
	return &http.Response{StatusCode: http.StatusOK, Body: u.body, Header: http.Header{}}, nil
}

func TestVerifyCompactSerialization_ARemoteBodyThatFailsToReadIsStillClosed(t *testing.T) {
	for _, header := range []string{"jku", "x5u"} {
		t.Run(header, func(t *testing.T) {
			closed := false
			token := es256Token(t, p256(t), map[string]any{header: "https://example.com/" + header})

			_, _, err := VerifyCompactSerialization(context.Background(), token, nil, &model.JoseOptions{
				UseTokenProvidedKeys: true,
				X509Roots:            x509.NewCertPool(),
				HttpClient:           &http.Client{Transport: unreadableBodyTransport{body: unreadableBody{closed: &closed}}},
			})
			if !errors.Is(err, joseerror.ErrApplicationError) {
				t.Errorf("[JoseOptions.HttpClient] a %s body that cannot be read yields no key, so the refusal is an application error, got %v", header, err)
			}
			if !closed {
				t.Errorf("[JoseOptions.FetchTimeout] a %s body must be closed when its read fails, or the connection and the fetch deadline are held until the timeout fires", header)
			}
		})
	}
}
