package jws_test

import (
	"context"
	"errors"
	"net/http"
	"strings"
	"testing"

	"github.com/MichaelFraser99/go-jose/joseerror"
	"github.com/MichaelFraser99/go-jose/jws"
	"github.com/MichaelFraser99/go-jose/model"
)

func TestVerifyCompactSerialization_AnX5uBodyThatDoesNotDecodeKeepsTheEarlierFailures(t *testing.T) {
	keys := newRemoteKeys(t)
	jku := serving(t, func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusNotFound) })
	x5u := servingBody(t, []byte("<html>not a certificate</html>"))
	token := es256Token(t, keys.signingKey, map[string]any{"jku": jku.URL, "x5u": x5u.URL})
	opts := &model.JoseOptions{UseTokenProvidedKeys: true, X509Roots: roots(keys.root), HttpClient: jku.Client()}

	_, _, err := jws.VerifyCompactSerialization(context.Background(), token, nil, opts)
	if !errors.Is(err, joseerror.ErrApplicationError) {
		t.Fatalf("[README Errors] a body that does not decode is a failed decode of what a fetch returned, got %v", err)
	}
	if !strings.Contains(err.Error(), "jku") || !strings.Contains(err.Error(), "x5u") {
		t.Errorf("[RFC 7515 6] a body that does not decode is a source that failed, so the earlier jku failure must still be reported beside it, got %v", err)
	}
}

func TestVerifyCompactSerialization_AKeyThatIsNotSelectedMatchesErrNoKeyIdentifierMatch(t *testing.T) {
	keys := newRemoteKeys(t)
	unrelated := leaf(t, p256Key(t), rootCA(t, p256Key(t)))
	token := es256Token(t, keys.signingKey, map[string]any{"x5c": []string{der64(unrelated)}})

	_, _, err := jws.VerifyCompactSerialization(context.Background(), token, nil, &model.JoseOptions{X509Roots: roots(keys.root)})
	if !errors.Is(err, joseerror.ErrInvalidSignature) || !errors.Is(err, joseerror.ErrNoKeyIdentifierMatch) {
		t.Errorf("[README Errors] a chain that does not reach a configured root selects no key, so the refusal must match ErrInvalidSignature and ErrNoKeyIdentifierMatch, got %v", err)
	}
}
