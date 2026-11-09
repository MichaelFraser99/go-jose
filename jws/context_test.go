package jws

import (
	"context"
	"crypto"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"testing"
	"time"

	"github.com/MichaelFraser99/go-jose/jwa"
	"github.com/MichaelFraser99/go-jose/model"
)

func contextTestToken(t *testing.T, signer model.Signer) string {
	t.Helper()
	input := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"ES256"}`)) + "." + base64.RawURLEncoding.EncodeToString([]byte(`{"sub":"a"}`))
	signature, err := signer.Sign(rand.Reader, []byte(input), nil)
	if err != nil {
		t.Fatal(err)
	}
	return input + "." + base64.RawURLEncoding.EncodeToString(signature)
}

func TestVerify_StopsOnceTheContextHasEnded(t *testing.T) {
	signer, err := GetSigner(jwa.ES256, nil)
	if err != nil {
		t.Fatal(err)
	}
	token := contextTestToken(t, signer)
	retriever := func() ([]crypto.PublicKey, error) { return []crypto.PublicKey{signer.Public()}, nil }

	cancelled, cancel := context.WithCancel(context.Background())
	cancel()
	expired, stop := context.WithDeadline(context.Background(), time.Now().Add(-time.Second))
	defer stop()
	for name, c := range map[string]struct {
		ctx  context.Context
		want error
	}{
		"a cancelled context": {ctx: cancelled, want: context.Canceled},
		"an expired deadline": {ctx: expired, want: context.DeadlineExceeded},
	} {
		t.Run(name, func(t *testing.T) {
			head, payload, err := Verify(c.ctx, token, retriever, nil)
			if !errors.Is(err, c.want) || head != nil || payload != nil {
				t.Errorf("the context has ended, so Verify must return its error and no token, got %v", err)
			}
			if _, body, err := VerifyCompactSerialization(c.ctx, token, retriever, nil); !errors.Is(err, c.want) || body != nil {
				t.Errorf("the context has ended, so VerifyCompactSerialization must return its error and no token, got %v", err)
			}
		})
	}

	ctx, cancelDuring := context.WithCancel(context.Background())
	defer cancelDuring()
	tried := 0
	first := func() ([]crypto.PublicKey, error) {
		tried++
		cancelDuring()
		return nil, nil
	}
	if _, _, err := Verify(ctx, token, first, nil); !errors.Is(err, context.Canceled) || tried != 1 {
		t.Errorf("a context cancelled while a source runs must stop verification before the next source, got %v after %d sources", err, tried)
	}
	if _, _, err := Verify(context.Background(), token, retriever, nil); err != nil {
		t.Errorf("a live context must not stop verification, got %v", err)
	}
}
