package jws_test

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/MichaelFraser99/go-jose/joseerror"
	"github.com/MichaelFraser99/go-jose/jws"
	"github.com/MichaelFraser99/go-jose/model"
)

type remoteSource struct {
	header string
	body   func(keys remoteKeys) []byte
	opts   func(keys remoteKeys, client *http.Client, allowed []string) *model.JoseOptions
}

var remoteSources = map[string]remoteSource{
	"jku": {
		header: "jku",
		body:   func(keys remoteKeys) []byte { return keys.jwks },
		opts: func(_ remoteKeys, client *http.Client, allowed []string) *model.JoseOptions {
			return &model.JoseOptions{UseTokenProvidedKeys: true, HttpClient: client, AllowedKeyURLs: allowed}
		},
	},
	"x5u": {
		header: "x5u",
		body:   func(keys remoteKeys) []byte { return keys.pem },
		opts: func(keys remoteKeys, client *http.Client, allowed []string) *model.JoseOptions {
			return &model.JoseOptions{X509Roots: roots(keys.root), HttpClient: client, AllowedKeyURLs: allowed}
		},
	},
}

func countingBody(t *testing.T, hits *atomic.Int64, body []byte) *httptest.Server {
	t.Helper()
	return serving(t, func(w http.ResponseWriter, _ *http.Request) {
		hits.Add(1)
		_, _ = w.Write(body)
	})
}

func TestVerifyCompactSerialization_AllowedKeyURLsFetchesOnlyAListedURL(t *testing.T) {
	keys := newRemoteKeys(t)
	for name, source := range remoteSources {
		t.Run(name+" listed", func(t *testing.T) {
			var hits atomic.Int64
			server := countingBody(t, &hits, source.body(keys))
			token := es256Token(t, keys.signingKey, map[string]any{source.header: server.URL})
			opts := source.opts(keys, server.Client(), []string{"https://other.example/keys", server.URL})

			if _, _, err := jws.VerifyCompactSerialization(context.Background(), token, nil, opts); err != nil {
				t.Errorf("[draft-ietf-oauth-rfc8725bis 3.10] the %s equals an AllowedKeyURLs entry and holds the signing key, so the token must verify, got %v", name, err)
			}
			if got := hits.Load(); got != 1 {
				t.Errorf("[draft-ietf-oauth-rfc8725bis 3.10] a listed %s must be fetched once, got %d requests", name, got)
			}
		})

		t.Run(name+" not listed", func(t *testing.T) {
			var hits atomic.Int64
			server := countingBody(t, &hits, source.body(keys))
			token := es256Token(t, keys.signingKey, map[string]any{source.header: server.URL})
			opts := source.opts(keys, server.Client(), []string{"https://other.example/keys"})

			_, _, err := jws.VerifyCompactSerialization(context.Background(), token, nil, opts)
			if !errors.Is(err, joseerror.ErrInvalidSignature) || !errors.Is(err, joseerror.ErrNoKeyIdentifierMatch) {
				t.Errorf("[draft-ietf-oauth-rfc8725bis 3.10] an unlisted %s contributes no key, so the token must be refused with ErrInvalidSignature matching ErrNoKeyIdentifierMatch, got %v", name, err)
			}
			if errors.Is(err, joseerror.ErrApplicationError) {
				t.Errorf("[draft-ietf-oauth-rfc8725bis 3.10] an unlisted %s is not fetched, so no fetch failed and the error must not match ErrApplicationError, got %v", name, err)
			}
			if err != nil && (!strings.Contains(err.Error(), "AllowedKeyURLs") || !strings.Contains(err.Error(), server.URL)) {
				t.Errorf("[README Errors] the error must name the unlisted URL and AllowedKeyURLs, got %v", err)
			}
			if got := hits.Load(); got != 0 {
				t.Errorf("[draft-ietf-oauth-rfc8725bis 3.10] no request may be sent for an unlisted %s, got %d", name, got)
			}
		})

		t.Run(name+" not listed, the caller's retriever verifies", func(t *testing.T) {
			var hits atomic.Int64
			server := countingBody(t, &hits, source.body(keys))
			token := es256Token(t, keys.signingKey, map[string]any{source.header: server.URL})
			opts := source.opts(keys, server.Client(), []string{"https://other.example/keys"})

			if _, _, err := jws.VerifyCompactSerialization(context.Background(), token, retrieving(&keys.signingKey.PublicKey), opts); err != nil {
				t.Errorf("[draft-ietf-oauth-rfc8725bis 3.10] an unlisted %s only contributes no key, so the caller's own key must still verify the token, got %v", name, err)
			}
			if got := hits.Load(); got != 0 {
				t.Errorf("[draft-ietf-oauth-rfc8725bis 3.10] no request may be sent for an unlisted %s, got %d", name, got)
			}
		})
	}
}

type recordingTransport struct {
	mu   sync.Mutex
	seen []string
}

func (r *recordingTransport) RoundTrip(request *http.Request) (*http.Response, error) {
	r.mu.Lock()
	r.seen = append(r.seen, request.URL.String())
	r.mu.Unlock()
	return &http.Response{StatusCode: http.StatusNotFound, Body: io.NopCloser(strings.NewReader("")), Request: request}, nil
}

func (r *recordingTransport) requests() []string {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]string(nil), r.seen...)
}

func TestVerifyCompactSerialization_AllowedKeyURLsMatchesAURLExactly(t *testing.T) {
	keys := newRemoteKeys(t)
	const entry = "https://keys.example/jwks"
	nearMisses := map[string]string{
		"a trailing slash":              "https://keys.example/jwks/",
		"a host in another case":        "https://KEYS.example/jwks",
		"a path in another case":        "https://keys.example/JWKS",
		"a scheme in another case":      "HTTPS://keys.example/jwks",
		"an added query":                "https://keys.example/jwks?v=1",
		"an empty query":                "https://keys.example/jwks?",
		"an added fragment":             "https://keys.example/jwks#keys",
		"the default port written":      "https://keys.example:443/jwks",
		"a percent-encoded path":        "https://keys.example/%6Awks",
		"the listed host as userinfo":   "https://keys.example@evil.example/jwks",
		"a listed prefix":               "https://keys.example/jwks/../evil",
		"a longer host":                 "https://keys.example.evil.example/jwks",
		"a Cyrillic homoglyph host":     "https://kеys.example/jwks",
		"a fullwidth homoglyph host":    "https://ｋeys.example/jwks",
		"an entry followed by a dot":    "https://keys.example./jwks",
		"an entry that is a substring":  "https://keys.example/jwk",
		"an entry followed by a NUL":    "https://keys.example/jwks%00",
		"a path with a doubled slash":   "https://keys.example//jwks",
		"an IPv6 literal for localhost": "https://[::1]/jwks",
	}

	for sourceName, source := range remoteSources {
		for _, listed := range []string{entry, "HTTPS://keys.example/jwks", "https://keys.example/jwks?", "https://keys.example/a%2Fb"} {
			t.Run(sourceName+" equal to the entry "+listed, func(t *testing.T) {
				transport := &recordingTransport{}
				token := es256Token(t, keys.signingKey, map[string]any{source.header: listed})
				opts := source.opts(keys, &http.Client{Transport: transport}, []string{listed})
				_, _, _ = jws.VerifyCompactSerialization(context.Background(), token, nil, opts)
				if got := transport.requests(); len(got) != 1 {
					t.Errorf("[RFC 3986 6.2.1] a %s equal to the entry %q must be fetched, got requests %q", sourceName, listed, got)
				}
			})
		}

		for name, location := range nearMisses {
			t.Run(sourceName+" "+name, func(t *testing.T) {
				token := es256Token(t, keys.signingKey, map[string]any{source.header: location})

				unrestricted := &recordingTransport{}
				_, _, _ = jws.VerifyCompactSerialization(context.Background(), token, nil, source.opts(keys, &http.Client{Transport: unrestricted}, nil))
				if len(unrestricted.requests()) != 1 {
					t.Fatalf("with no AllowedKeyURLs the %s %q must be fetched, or this case proves nothing, got requests %q", sourceName, location, unrestricted.requests())
				}

				transport := &recordingTransport{}
				_, _, err := jws.VerifyCompactSerialization(context.Background(), token, nil, source.opts(keys, &http.Client{Transport: transport}, []string{entry}))
				if got := transport.requests(); len(got) != 0 {
					t.Errorf("[RFC 3986 6.2.1] %q is not the string %q, so no request may be sent, got %q", location, entry, got)
				}
				if !errors.Is(err, joseerror.ErrInvalidSignature) || !errors.Is(err, joseerror.ErrNoKeyIdentifierMatch) {
					t.Errorf("[draft-ietf-oauth-rfc8725bis 3.10] an unlisted %s contributes no key, so the error must match ErrInvalidSignature and ErrNoKeyIdentifierMatch, got %v", sourceName, err)
				}
			})
		}
	}
}

func TestVerifyCompactSerialization_AllowedKeyURLsQuotesAnUnlistedURLBounded(t *testing.T) {
	keys := newRemoteKeys(t)
	token := es256Token(t, keys.signingKey, map[string]any{"jku": "https://keys.example/" + strings.Repeat("a", 10_000)})
	opts := &model.JoseOptions{UseTokenProvidedKeys: true, HttpClient: &http.Client{Transport: &recordingTransport{}}, AllowedKeyURLs: []string{"https://keys.example/jwks"}}

	_, _, err := jws.VerifyCompactSerialization(context.Background(), token, nil, opts)
	if !errors.Is(err, joseerror.ErrNoKeyIdentifierMatch) {
		t.Fatalf("[draft-ietf-oauth-rfc8725bis 3.10] an unlisted jku must be reported as ErrNoKeyIdentifierMatch, got %v", err)
	}
	if strings.Contains(err.Error(), strings.Repeat("a", 65)) || len(err.Error()) > 512 {
		t.Errorf("[README Errors] an echoed value is cut to 64 characters, so the error must not carry the whole URL, got %d bytes", len(err.Error()))
	}
}

func TestVerifyCompactSerialization_AllowedKeyURLsAppliesToEveryRedirectHop(t *testing.T) {
	keys := newRemoteKeys(t)
	for sourceName, source := range remoteSources {
		body := source.body(keys)

		t.Run(sourceName+" to an unlisted server", func(t *testing.T) {
			var targetHits, startHits atomic.Int64
			target := countingBody(t, &targetHits, body)
			start := serving(t, func(w http.ResponseWriter, r *http.Request) {
				startHits.Add(1)
				http.Redirect(w, r, target.URL, http.StatusFound)
			})
			token := es256Token(t, keys.signingKey, map[string]any{source.header: start.URL})

			_, _, err := jws.VerifyCompactSerialization(context.Background(), token, nil, source.opts(keys, start.Client(), []string{start.URL}))
			if !errors.Is(err, joseerror.ErrApplicationError) {
				t.Errorf("[draft-ietf-oauth-rfc8725bis 3.10] a refused redirect hop fails the fetch, as a hop that is not https does, so the error must match ErrApplicationError, got %v", err)
			}
			if startHits.Load() != 1 || targetHits.Load() != 0 {
				t.Errorf("[draft-ietf-oauth-rfc8725bis 3.10] the listed URL is fetched and the unlisted hop is never sent, got %d and %d requests", startHits.Load(), targetHits.Load())
			}
		})

		t.Run(sourceName+" to an unlisted path on the listed server", func(t *testing.T) {
			var hits atomic.Int64
			server := serving(t, func(w http.ResponseWriter, r *http.Request) {
				hits.Add(1)
				if r.URL.Path == "/listed" {
					http.Redirect(w, r, "/unlisted", http.StatusFound)
					return
				}
				_, _ = w.Write(body)
			})
			listed := server.URL + "/listed"
			token := es256Token(t, keys.signingKey, map[string]any{source.header: listed})

			_, _, err := jws.VerifyCompactSerialization(context.Background(), token, nil, source.opts(keys, server.Client(), []string{listed}))
			if !errors.Is(err, joseerror.ErrApplicationError) {
				t.Errorf("[draft-ietf-oauth-rfc8725bis 3.10] a relative redirect to an unlisted path must fail the fetch with ErrApplicationError, got %v", err)
			}
			if got := hits.Load(); got != 1 {
				t.Errorf("[draft-ietf-oauth-rfc8725bis 3.10] only the listed URL may be requested, got %d requests", got)
			}
		})

		t.Run(sourceName+" to another listed server", func(t *testing.T) {
			var targetHits atomic.Int64
			target := countingBody(t, &targetHits, body)
			start := serving(t, func(w http.ResponseWriter, r *http.Request) {
				http.Redirect(w, r, target.URL, http.StatusFound)
			})
			token := es256Token(t, keys.signingKey, map[string]any{source.header: start.URL})

			if _, _, err := jws.VerifyCompactSerialization(context.Background(), token, nil, source.opts(keys, start.Client(), []string{start.URL, target.URL})); err != nil {
				t.Errorf("[draft-ietf-oauth-rfc8725bis 3.10] each hop is listed and the target holds the signing key, so the token must verify, got %v", err)
			}
			if got := targetHits.Load(); got != 1 {
				t.Errorf("[draft-ietf-oauth-rfc8725bis 3.10] a redirect to a listed URL must be followed, got %d requests", got)
			}
		})

		t.Run(sourceName+" keeps the caller's redirect policy", func(t *testing.T) {
			var targetHits atomic.Int64
			target := countingBody(t, &targetHits, body)
			start := serving(t, func(w http.ResponseWriter, r *http.Request) {
				http.Redirect(w, r, target.URL, http.StatusFound)
			})
			client := start.Client()
			refused := errors.New("the caller follows no redirect")
			client.CheckRedirect = func(*http.Request, []*http.Request) error { return refused }
			token := es256Token(t, keys.signingKey, map[string]any{source.header: start.URL})

			_, _, err := jws.VerifyCompactSerialization(context.Background(), token, nil, source.opts(keys, client, []string{start.URL, target.URL}))
			if !errors.Is(err, refused) {
				t.Errorf("[JoseOptions.HttpClient] the caller's CheckRedirect must still apply with AllowedKeyURLs set, got %v", err)
			}
			if got := targetHits.Load(); got != 0 {
				t.Errorf("[JoseOptions.HttpClient] a redirect the caller's policy refuses must not be followed, got %d requests", got)
			}
		})
	}
}

func TestVerifyCompactSerialization_AllowedKeyURLsAdmitsNoSource(t *testing.T) {
	keys := newRemoteKeys(t)
	var hits atomic.Int64
	jku := countingBody(t, &hits, keys.jwks)
	x5u := countingBody(t, &hits, keys.pem)
	allowed := []string{jku.URL, x5u.URL}

	tests := map[string]struct {
		header map[string]any
		opts   *model.JoseOptions
	}{
		"a listed jku without UseTokenProvidedKeys": {
			header: map[string]any{"jku": jku.URL},
			opts:   &model.JoseOptions{X509Roots: roots(keys.root), HttpClient: jku.Client(), AllowedKeyURLs: allowed},
		},
		"a listed x5u without X509Roots": {
			header: map[string]any{"x5u": x5u.URL},
			opts:   &model.JoseOptions{UseTokenProvidedKeys: true, HttpClient: x5u.Client(), AllowedKeyURLs: allowed},
		},
		"a listed jku without HttpClient": {
			header: map[string]any{"jku": jku.URL},
			opts:   &model.JoseOptions{UseTokenProvidedKeys: true, AllowedKeyURLs: allowed},
		},
	}
	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			token := es256Token(t, keys.signingKey, tc.header)
			_, _, err := jws.VerifyCompactSerialization(context.Background(), token, nil, tc.opts)
			if !errors.Is(err, joseerror.ErrNoKeyIdentifierMatch) {
				t.Errorf("[RFC 7515 10.3] AllowedKeyURLs only restricts, so %s contributes no key and the token names none this verifier may use, got %v", name, err)
			}
		})
	}
	if got := hits.Load(); got != 0 {
		t.Errorf("[RFC 7515 10.3] a source AllowedKeyURLs lists but no switch admits must not be fetched, got %d requests", got)
	}
}

func TestCheckOptions_AllowedKeyURLsEntryThatNoHeaderCanMatch(t *testing.T) {
	refused := map[string]string{
		"an empty entry":               "",
		"a relative reference":         "/jwks",
		"a scheme-relative reference":  "//keys.example/jwks",
		"plain http":                   "http://keys.example/jwks",
		"text that is not a URL":       "not a url",
		"a URL that does not parse":    "https://keys.example/%zz",
		"a host with no scheme":        "keys.example/jwks",
		"another scheme":               "file:///etc/passwd",
		"https after a leading space":  " https://keys.example/jwks",
		"a bad entry after a good one": "http://after.example/jwks",
		"https with an empty host":     "https:///jwks",
		"https with only a port":       "https://:443/jwks",
		"https with userinfo only":     "https://user@/jwks",
		"https opaque":                 "https:opaque",
	}
	for name, entry := range refused {
		t.Run(name, func(t *testing.T) {
			allowed := []string{entry}
			if name == "a bad entry after a good one" {
				allowed = []string{"https://keys.example/jwks", entry}
			}
			opts := &model.JoseOptions{UseTokenProvidedKeys: true, AllowedKeyURLs: allowed}
			if err := jws.CheckOptions(opts); !errors.Is(err, joseerror.ErrInvalidOptions) {
				t.Errorf("[RFC 7515 4.1.2, 4.1.5] a jku or x5u must be https, so the entry %q can match none and must be refused with ErrInvalidOptions, got %v", entry, err)
			}
			if _, _, err := jws.VerifyCompactSerialization(context.Background(), "not-a-token", nil, opts); !errors.Is(err, joseerror.ErrInvalidOptions) {
				t.Errorf("[README Errors] options no token can meet are refused whatever the token, got %v", err)
			}
		})
	}

	accepted := map[string][]string{
		"none":                 nil,
		"an empty list":        {},
		"an https URL":         {"https://keys.example/jwks"},
		"a unicode host":       {"https://kеys.example/jwks"},
		"duplicate entries":    {"https://keys.example/jwks", "https://keys.example/jwks"},
		"an uppercase scheme":  {"HTTPS://keys.example/jwks"},
		"a query and fragment": {"https://keys.example/jwks?v=1#keys"},
	}
	for name, allowed := range accepted {
		t.Run(name, func(t *testing.T) {
			if err := jws.CheckOptions(&model.JoseOptions{AllowedKeyURLs: allowed}); err != nil {
				t.Errorf("[RFC 7515 4.1.2, 4.1.5] %v holds only https URLs a jku or x5u can equal, so the options must be accepted, got %v", allowed, err)
			}
		})
	}

	long := "http://" + strings.Repeat("a", 10_000)
	err := jws.CheckOptions(&model.JoseOptions{AllowedKeyURLs: []string{long}})
	if !errors.Is(err, joseerror.ErrInvalidOptions) || strings.Contains(err.Error(), strings.Repeat("a", 65)) {
		t.Errorf("[README Errors] a refused entry is quoted and cut to 64 characters, got %v", err)
	}
}

func TestVerifyCompactSerialization_AllowedKeyURLsRefusalFetchesNothing(t *testing.T) {
	keys := newRemoteKeys(t)
	var hits atomic.Int64
	server := countingBody(t, &hits, keys.jwks)
	token := es256Token(t, keys.signingKey, map[string]any{"jku": server.URL})
	opts := &model.JoseOptions{UseTokenProvidedKeys: true, HttpClient: server.Client(), AllowedKeyURLs: []string{server.URL, "http://keys.example/jwks"}}

	if _, _, err := jws.VerifyCompactSerialization(context.Background(), token, nil, opts); !errors.Is(err, joseerror.ErrInvalidOptions) {
		t.Errorf("[README Errors] an entry no header can match fails every call with ErrInvalidOptions, even for a listed jku, got %v", err)
	}
	if got := hits.Load(); got != 0 {
		t.Errorf("[README Errors] options refused before the token is read fetch nothing, got %d requests", got)
	}
}

func TestVerifyCompactSerialization_AJkuOrX5uWithAnEmptyHostIsMalformed(t *testing.T) {
	keys := newRemoteKeys(t)
	emptyHosts := []string{"https://", "https:opaque", "https:///jwks", "https://:443/", "https://user@/"}
	options := map[string]*model.JoseOptions{
		"no options":           nil,
		"every source enabled": {UseTokenProvidedKeys: true, X509Roots: roots(keys.root), HttpClient: &http.Client{Transport: &recordingTransport{}}},
	}
	for _, header := range []string{"jku", "x5u"} {
		for _, value := range emptyHosts {
			for optsName, opts := range options {
				t.Run(header+" "+value+" "+optsName, func(t *testing.T) {
					token := es256Token(t, keys.signingKey, map[string]any{header: value})
					_, _, err := jws.VerifyCompactSerialization(context.Background(), token, retrieving(&keys.signingKey.PublicKey), opts)
					if !errors.Is(err, joseerror.ErrMalformedToken) || !errors.Is(err, joseerror.ErrMalformedClaim) {
						t.Errorf("[RFC 9110 4.2.2] a recipient MUST reject an https URI with an empty host identifier, so a %s of %q must be refused with ErrMalformedToken and ErrMalformedClaim, got %v", header, value, err)
					}
				})
			}
		}
	}
}
