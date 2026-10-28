package jws_test

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"math/big"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/MichaelFraser99/go-jose/internal/httputils"
	"github.com/MichaelFraser99/go-jose/joseerror"
	"github.com/MichaelFraser99/go-jose/jwa"
	"github.com/MichaelFraser99/go-jose/jwk"
	"github.com/MichaelFraser99/go-jose/jws"
	"github.com/MichaelFraser99/go-jose/model"
)

type remoteKeys struct {
	signingKey *ecdsa.PrivateKey
	root       *issuedCertificate
	jwks       []byte
	pem        []byte
}

func newRemoteKeys(t *testing.T) remoteKeys {
	t.Helper()
	signingKey := p256Key(t)
	root := rootCA(t, p256Key(t))
	signer := leaf(t, signingKey, root)
	member, err := jwk.PublicJwk(&signingKey.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	jwks, err := json.Marshal(map[string]any{"keys": []any{*member}})
	if err != nil {
		t.Fatal(err)
	}
	return remoteKeys{
		signingKey: signingKey,
		root:       root,
		jwks:       jwks,
		pem:        pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: signer.cert.Raw}),
	}
}

func serving(t *testing.T, handler http.HandlerFunc) *httptest.Server {
	t.Helper()
	server := httptest.NewTLSServer(handler)
	t.Cleanup(server.Close)
	return server
}

func servingBody(t *testing.T, body []byte) *httptest.Server {
	t.Helper()
	return serving(t, func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write(body)
	})
}

func countingServer(t *testing.T, requests *atomic.Int32) *httptest.Server {
	t.Helper()
	return serving(t, func(w http.ResponseWriter, _ *http.Request) {
		requests.Add(1)
		w.WriteHeader(http.StatusNotFound)
	})
}

func TestVerifyCompactSerialization_ARemoteKeyFetchSendsAndKeepsNoCookies(t *testing.T) {
	keys := newRemoteKeys(t)
	bodies := map[string][]byte{"jku": keys.jwks, "x5u": keys.pem}

	for source, body := range bodies {
		t.Run(source, func(t *testing.T) {
			var cookieSent atomic.Value
			cookieSent.Store("")
			server := serving(t, func(w http.ResponseWriter, r *http.Request) {
				cookieSent.Store(r.Header.Get("Cookie"))
				http.SetCookie(w, &http.Cookie{Name: "planted", Value: "by-the-key-server"})
				_, _ = w.Write(body)
			})
			serverURL, err := url.Parse(server.URL)
			if err != nil {
				t.Fatal(err)
			}
			jar, err := cookiejar.New(nil)
			if err != nil {
				t.Fatal(err)
			}
			jar.SetCookies(serverURL, []*http.Cookie{{Name: "session", Value: "callers-secret"}})
			client := server.Client()
			client.Jar = jar

			token := es256Token(t, keys.signingKey, map[string]any{source: server.URL})
			opts := &model.JoseOptions{UseTokenProvidedKeys: true, X509Roots: roots(keys.root), HttpClient: client}
			if _, _, err := jws.VerifyCompactSerialization(context.Background(), token, nil, opts); err != nil {
				t.Fatalf("[RFC 7515 4.1.2, 4.1.5] the %s resource holds the signing key, so the token must verify, got %v", source, err)
			}
			if sent := cookieSent.Load().(string); sent != "" {
				t.Errorf("[RFC 8725 3.10] a fetch of a URL the token names must send no cookies, sent %q", sent)
			}
			kept := jar.Cookies(serverURL)
			if len(kept) != 1 || kept[0].Name != "session" {
				t.Errorf("[RFC 8725 3.10] a reply to a fetch the token caused must not reach the caller's cookie jar, jar holds %v", kept)
			}
		})
	}
}

func es256Token(t *testing.T, key *ecdsa.PrivateKey, head map[string]any) string {
	t.Helper()
	return signWithHeader(t, jwa.ES256, key, head)
}

func TestVerifyCompactSerialization_AKeySourceThatFailsGivesWayToTheNext(t *testing.T) {
	keys := newRemoteKeys(t)
	failures := map[string][]byte{
		"a jku that is not found":      nil,
		"a jku body over the size cap": []byte(strings.Repeat(" ", int(httputils.MaxBodyBytes)+1)),
		"a jku body that is not JSON":  []byte("not json"),
	}
	for name, body := range failures {
		t.Run(name, func(t *testing.T) {
			jku := serving(t, func(w http.ResponseWriter, _ *http.Request) {
				if body == nil {
					w.WriteHeader(http.StatusNotFound)
					return
				}
				_, _ = w.Write(body)
			})
			x5u := servingBody(t, keys.pem)
			client := jku.Client()
			token := es256Token(t, keys.signingKey, map[string]any{"jku": jku.URL, "x5u": x5u.URL})
			opts := &model.JoseOptions{UseTokenProvidedKeys: true, X509Roots: roots(keys.root), HttpClient: client}

			if _, _, err := jws.VerifyCompactSerialization(context.Background(), token, nil, opts); err != nil {
				t.Errorf("[RFC 7515 5.2 step 8, 6] %s yields no key, and the x5u chain to a trusted root holds the signing key, so the token must verify, got %v", name, err)
			}

			jkuOnly := es256Token(t, keys.signingKey, map[string]any{"jku": jku.URL})
			_, _, err := jws.VerifyCompactSerialization(context.Background(), jkuOnly, nil, opts)
			if !errors.Is(err, joseerror.ErrApplicationError) {
				t.Errorf("[README Errors] with no other source, %s must still be reported as ErrApplicationError, got %v", name, err)
			}
			if errors.Is(err, joseerror.ErrInvalidSignature) {
				t.Errorf("[README Errors] a key the token named could not be obtained, so the signature was not shown to be invalid, got %v", err)
			}
		})
	}
}

func retrieverFailingWith(err error) model.Retriever {
	return func() ([]crypto.PublicKey, error) { return nil, err }
}

func TestVerifyCompactSerialization_ACallersRetrieverThatFailsGivesWayToTheTokensKey(t *testing.T) {
	signingKey := p256Key(t)
	member, err := jwk.PublicJwk(&signingKey.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	opts := &model.JoseOptions{UseTokenProvidedKeys: true}
	unavailable := errors.New("the caller's key store is unavailable")

	token := es256Token(t, signingKey, map[string]any{"jwk": *member})
	if _, _, err := jws.VerifyCompactSerialization(context.Background(), token, retrieverFailingWith(unavailable), opts); err != nil {
		t.Errorf("[RFC 7515 5.2 step 8, 6] once opted in, the token's own key verifies it whatever the caller's retriever returned, got %v", err)
	}

	forged := es256Token(t, p256Key(t), map[string]any{"jwk": *member})
	_, _, err = jws.VerifyCompactSerialization(context.Background(), forged, retrieverFailingWith(unavailable), opts)
	if !errors.Is(err, unavailable) {
		t.Errorf("[README Errors] when no key verifies, the retriever's failure must still be matchable, got %v", err)
	}
}

func TestVerifyCompactSerialization_EveryFailedSourceIsReportedWhenNothingVerifies(t *testing.T) {
	keys := newRemoteKeys(t)
	var requests atomic.Int32
	jku, x5u := countingServer(t, &requests), countingServer(t, &requests)
	token := es256Token(t, keys.signingKey, map[string]any{"jku": jku.URL, "x5u": x5u.URL})
	opts := &model.JoseOptions{UseTokenProvidedKeys: true, X509Roots: roots(keys.root), HttpClient: jku.Client()}

	_, _, err := jws.VerifyCompactSerialization(context.Background(), token, nil, opts)
	if !errors.Is(err, joseerror.ErrApplicationError) {
		t.Fatalf("[README Errors] two failed fetches must be reported as ErrApplicationError, got %v", err)
	}
	if !strings.Contains(err.Error(), "jku") || !strings.Contains(err.Error(), "x5u") {
		t.Errorf("[README Errors] the error must name both sources that failed, got %v", err)
	}
	if got := requests.Load(); got != 2 {
		t.Errorf("[RFC 7515 6] a failed jku must not stop the x5u being fetched, got %d requests", got)
	}
}

func TestVerifyCompactSerialization_AFetchThatTimesOutGivesWayToTheNextSource(t *testing.T) {
	keys := newRemoteKeys(t)
	release := make(chan struct{})
	stalling := serving(t, func(w http.ResponseWriter, r *http.Request) {
		select {
		case <-r.Context().Done():
		case <-release:
		}
	})
	t.Cleanup(func() { close(release) })
	x5u := servingBody(t, keys.pem)
	client := stalling.Client()
	opts := &model.JoseOptions{UseTokenProvidedKeys: true, X509Roots: roots(keys.root), HttpClient: client, FetchTimeout: 100 * time.Millisecond}

	both := es256Token(t, keys.signingKey, map[string]any{"jku": stalling.URL, "x5u": x5u.URL})
	if _, _, err := jws.VerifyCompactSerialization(context.Background(), both, nil, opts); err != nil {
		t.Errorf("[RFC 7515 5.2 step 8, 6] a jku that runs out of time yields no key, and the x5u holds the signing key, got %v", err)
	}

	jkuOnly := es256Token(t, keys.signingKey, map[string]any{"jku": stalling.URL})
	_, _, err := jws.VerifyCompactSerialization(context.Background(), jkuOnly, nil, opts)
	if !errors.Is(err, joseerror.ErrApplicationError) || !errors.Is(err, context.DeadlineExceeded) {
		t.Errorf("[README Errors] a fetch that ran out of time must match ErrApplicationError and context.DeadlineExceeded, got %v", err)
	}
}

func TestVerify_NoSourceIsFetchedOnceTheKeyBudgetIsSpent(t *testing.T) {
	keys := newRemoteKeys(t)
	var requests atomic.Int32
	jku, x5u := countingServer(t, &requests), countingServer(t, &requests)
	token := es256Token(t, keys.signingKey, map[string]any{"jku": jku.URL, "x5u": x5u.URL})
	var wrong []crypto.PublicKey
	for range 3 {
		wrong = append(wrong, &p256Key(t).PublicKey)
	}
	opts := &model.JoseOptions{UseTokenProvidedKeys: true, X509Roots: roots(keys.root), HttpClient: jku.Client(), MaxKeysTried: 3}

	_, _, err := jws.Verify(context.Background(), token, retrieving(wrong...), opts)
	if !errors.Is(err, joseerror.ErrTooManyKeys) {
		t.Errorf("[JoseOptions.MaxKeysTried] three wrong keys spend a budget of three while sources remain, so the token must be refused with ErrTooManyKeys, got %v", err)
	}
	if got := requests.Load(); got != 0 {
		t.Errorf("[JoseOptions.MaxKeysTried] no source may be fetched once the budget is spent, got %d requests", got)
	}
}

func TestVerify_ASpentBudgetStillReportsTheSourcesThatFailed(t *testing.T) {
	keys := newRemoteKeys(t)
	var requests atomic.Int32
	jku := countingServer(t, &requests)
	member, err := jwk.PublicJwk(&p256Key(t).PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	token := es256Token(t, keys.signingKey, map[string]any{"jwk": *member, "jku": jku.URL})
	unavailable := errors.New("the caller's key store is unavailable")
	opts := &model.JoseOptions{UseTokenProvidedKeys: true, HttpClient: jku.Client(), MaxKeysTried: 1}

	_, _, err = jws.Verify(context.Background(), token, retrieverFailingWith(unavailable), opts)
	if !errors.Is(err, joseerror.ErrTooManyKeys) || !errors.Is(err, unavailable) {
		t.Errorf("[JoseOptions.MaxKeysTried] the wrong jwk spends the budget of one before the jku, and the retriever's failure must still be matchable, got %v", err)
	}
	if got := requests.Load(); got != 0 {
		t.Errorf("[JoseOptions.MaxKeysTried] no source may be fetched once the budget is spent, got %d requests", got)
	}
}

func TestVerify_ANilContextIsRefusedWhateverTheToken(t *testing.T) {
	keys := newRemoteKeys(t)
	var requests atomic.Int32
	jku := countingServer(t, &requests)
	opts := &model.JoseOptions{UseTokenProvidedKeys: true, HttpClient: jku.Client()}
	tokens := map[string]string{
		"a token naming a jku":     es256Token(t, keys.signingKey, map[string]any{"jku": jku.URL}),
		"a token naming no key":    es256Token(t, keys.signingKey, map[string]any{}),
		"text that is not a token": "not-a-token",
	}
	var noContext context.Context
	verifiers := map[string]func(token string) error{
		"Verify": func(token string) error {
			_, _, err := jws.Verify(noContext, token, nil, opts)
			return err
		},
		"VerifyCompactSerialization": func(token string) error {
			_, _, err := jws.VerifyCompactSerialization(noContext, token, nil, opts)
			return err
		},
	}
	for verifier, verify := range verifiers {
		for name, token := range tokens {
			t.Run(verifier+" "+name, func(t *testing.T) {
				if err := verify(token); !errors.Is(err, joseerror.ErrInvalidOptions) {
					t.Errorf("[README Errors] a nil context is wrong whatever the token, so it must be refused with ErrInvalidOptions, got %v", err)
				}
			})
		}
	}
	if got := requests.Load(); got != 0 {
		t.Errorf("[README Errors] a refused call must fetch nothing, got %d requests", got)
	}
}

func certificateQuotingALongURI(t *testing.T, issuer *issuedCertificate, uri string) []byte {
	t.Helper()
	names, err := asn1.Marshal([]asn1.RawValue{{Class: asn1.ClassContextSpecific, Tag: 6, Bytes: []byte(uri)}})
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{
		SerialNumber:    big.NewInt(1),
		Subject:         pkix.Name{CommonName: "leaf"},
		NotBefore:       time.Now().Add(-time.Hour),
		NotAfter:        time.Now().Add(time.Hour),
		ExtraExtensions: []pkix.Extension{{Id: asn1.ObjectIdentifier{2, 5, 29, 17}, Value: names}},
	}
	der, err := x509.CreateCertificate(rand.Reader, template, issuer.cert, issuer.key.Public(), issuer.key)
	if err != nil {
		t.Fatal(err)
	}
	return der
}

func TestVerifyCompactSerialization_AnUnparsableX5cIsNotEchoedUnbounded(t *testing.T) {
	root := rootCA(t, p256Key(t))
	long := strings.Repeat("a", 50_000)
	der := certificateQuotingALongURI(t, root, "https://"+long+"/%zz")
	if _, err := x509.ParseCertificate(der); err == nil || !strings.Contains(err.Error(), long) {
		t.Fatalf("the fixture must be a certificate crypto/x509 refuses while quoting its SAN in full, got %v", err)
	}
	token := signWithX5c(t, jwa.ES256, p256Key(t), []string{base64.StdEncoding.EncodeToString(der)})

	_, _, err := jws.VerifyCompactSerialization(context.Background(), token, nil, nil)
	if !errors.Is(err, joseerror.ErrMalformedClaim) {
		t.Fatalf("[RFC 7515 4.1.6] an x5c entry that is not a certificate must be refused with ErrMalformedClaim, got %v", err)
	}
	if strings.Contains(err.Error(), strings.Repeat("a", 65)) || len(err.Error()) > 512 {
		t.Errorf("[README Errors] an echoed value is cut to 64 characters, so the error must not carry the %d-byte SAN, got %d bytes", len(long), len(err.Error()))
	}
}
