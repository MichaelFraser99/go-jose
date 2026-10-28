package header

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"

	"github.com/MichaelFraser99/go-jose/internal/jose/jsonutils"
	"github.com/MichaelFraser99/go-jose/joseerror"
	"github.com/MichaelFraser99/go-jose/jwa"
	"github.com/MichaelFraser99/go-jose/model"
)

func decodedHeader(t *testing.T, head map[string]any) map[string]any {
	t.Helper()
	raw, err := json.Marshal(head)
	if err != nil {
		t.Fatalf("failed to encode the header: %v", err)
	}
	decoded, err := jsonutils.DecodeBase64urlMap(base64.RawURLEncoding.EncodeToString(raw))
	if err != nil {
		t.Fatalf("failed to decode the header: %v", err)
	}
	return decoded
}

func TestValidateHeader_TheExpectedTypeIsComparedAsAMediaType(t *testing.T) {
	tests := map[string]struct {
		reference string
		accepted  []string
		typ       any
		accept    bool
	}{
		"nothing expected, so typ is not checked":    {reference: "RFC 7515 4.1.9", typ: "anything-at-all", accept: true},
		"nothing expected and no typ at all":         {reference: "RFC 7515 4.1.9", accept: true},
		"the bare form":                              {reference: "RFC 7515 4.1.9", accepted: []string{"example+jwt"}, typ: "example+jwt", accept: true},
		"the application/ form":                      {reference: "RFC 7515 4.1.9", accepted: []string{"example+jwt"}, typ: "application/example+jwt", accept: true},
		"a different case":                           {reference: "RFC 7515 4.1.9", accepted: []string{"example+jwt"}, typ: "Example+JWT", accept: true},
		"the application/ form in a different case":  {reference: "RFC 7515 4.1.9", accepted: []string{"example+jwt"}, typ: "APPLICATION/EXAMPLE+JWT", accept: true},
		"an accepted type named with application/":   {reference: "RFC 7515 4.1.9", accepted: []string{"application/example+jwt"}, typ: "example+jwt", accept: true},
		"one of several accepted types":              {reference: "RFC 7515 4.1.9", accepted: []string{"other+jwt", "example+jwt"}, typ: "example+jwt", accept: true},
		"a type that is not accepted":                {reference: "RFC 7515 4.1.9", accepted: []string{"example+jwt"}, typ: "JWT"},
		"a type that is a suffix of an accepted one": {reference: "RFC 7515 4.1.9", accepted: []string{"example+jwt"}, typ: "x-example+jwt"},
		"a type with a trailing suffix":              {reference: "RFC 7515 4.1.9", accepted: []string{"example+jwt"}, typ: "example+jwt-x"},
		"application/ prepended twice":               {reference: "RFC 7515 4.1.9", accepted: []string{"example+jwt"}, typ: "application/application/example+jwt"},
		"no typ when one is expected":                {reference: "RFC 7515 4.1.9", accepted: []string{"example+jwt"}},
		"a typ that is not a string":                 {reference: "RFC 7515 4.1.9", accepted: []string{"example+jwt"}, typ: 7},
	}

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			head := map[string]any{"alg": "RS256"}
			if tc.typ != nil {
				head["typ"] = tc.typ
			}

			_, err := ValidateHeader(context.Background(), decodedHeader(t, head), nil, model.JWS, &model.JoseOptions{AcceptedTypes: tc.accepted})
			if tc.accept && err != nil {
				t.Errorf("[%s] expected the header to be accepted, got %v", tc.reference, err)
			}
			if !tc.accept && err == nil {
				t.Errorf("[%s] %q does not name an accepted type, so the token must be refused", tc.reference, tc.typ)
			}
		})
	}
}

func TestValidateHeader_AKeyIdentifierCanBeRequired(t *testing.T) {
	tests := map[string]struct {
		reference string
		require   bool
		kid       any
		accept    bool
	}{
		"not required and absent":       {reference: "RFC 7517 4.5", accept: true},
		"not required and present":      {reference: "RFC 7517 4.5", kid: "a-key", accept: true},
		"required and present":          {reference: "RFC 7517 4.5", require: true, kid: "a-key", accept: true},
		"required and absent":           {reference: "RFC 7517 4.5", require: true},
		"required and empty":            {reference: "RFC 7517 4.5", require: true, kid: ""},
		"required and not a string":     {reference: "RFC 7517 4.5", require: true, kid: 7},
		"not required and not a string": {reference: "RFC 7517 4.5", kid: 7},
	}

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			head := map[string]any{"alg": "RS256"}
			if tc.kid != nil {
				head["kid"] = tc.kid
			}

			_, err := ValidateHeader(context.Background(), decodedHeader(t, head), nil, model.JWS, &model.JoseOptions{RequireKeyIdentifier: tc.require})
			if tc.accept && err != nil {
				t.Errorf("[%s] expected the header to be accepted, got %v", tc.reference, err)
			}
			if !tc.accept && err == nil {
				t.Errorf("[%s] expected the header to be refused", tc.reference)
			}
		})
	}
}

func TestValidateHeader_ACriticalExtensionMustBeUnderstood(t *testing.T) {
	tests := map[string]struct {
		reference  string
		understood []string
		crit       []any
		extra      map[string]any
		accept     bool
	}{
		"no crit at all": {reference: "RFC 7515 4.1.11", accept: true},
		"an extension the caller understands": {
			reference: "RFC 7515 4.1.11", understood: []string{"x-example"},
			crit: []any{"x-example"}, extra: map[string]any{"x-example": "value"}, accept: true,
		},
		"two extensions, both understood": {
			reference: "RFC 7515 4.1.11", understood: []string{"x-one", "x-two"},
			crit: []any{"x-one", "x-two"}, extra: map[string]any{"x-one": 1, "x-two": 2}, accept: true,
		},
		"an extension the caller does not understand": {
			reference: "RFC 7515 4.1.11", understood: []string{"x-example"},
			crit: []any{"x-other"}, extra: map[string]any{"x-other": "value"},
		},
		"one understood beside one not": {
			reference: "RFC 7515 4.1.11", understood: []string{"x-one"},
			crit: []any{"x-one", "x-two"}, extra: map[string]any{"x-one": 1, "x-two": 2},
		},
		"an extension with nothing declared understood": {
			reference: "RFC 7515 4.1.11",
			crit:      []any{"x-example"}, extra: map[string]any{"x-example": "value"},
		},
		"an understood extension whose claim is absent": {
			reference: "RFC 7515 4.1.11", understood: []string{"x-example"},
			crit: []any{"x-example"},
		},
		"a declared name differing in case is not the same name": {
			reference: "RFC 7515 4.1.11", understood: []string{"x-example"},
			crit: []any{"X-Example"}, extra: map[string]any{"X-Example": "value"},
		},
	}

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			head := map[string]any{"alg": "RS256"}
			for k, v := range tc.extra {
				head[k] = v
			}
			if tc.crit != nil {
				head["crit"] = tc.crit
			}

			_, err := ValidateHeader(context.Background(), decodedHeader(t, head), nil, model.JWS, &model.JoseOptions{UnderstoodCriticalHeaders: tc.understood})
			if tc.accept && err != nil {
				t.Errorf("[%s] expected the header to be accepted, got %v", tc.reference, err)
			}
			if !tc.accept {
				if err == nil {
					t.Fatalf("[%s] a crit entry the recipient does not understand means the JWS MUST be rejected", tc.reference)
				}
				if !errors.Is(err, joseerror.ErrMissingCriticalClaim) && !errors.Is(err, joseerror.ErrMalformedClaim) {
					t.Errorf("[%s] the refusal must name the critical header fault, got %v", tc.reference, err)
				}
			}
		})
	}
}

func TestValidateHeader_ARefusedAlgorithmStopsBeforeAnyOutboundRequest(t *testing.T) {
	var fetched atomic.Int64
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		fetched.Add(1)
		w.Header().Set("Content-Type", "application/json")
		if _, err := w.Write([]byte(`{"keys":[]}`)); err != nil {
			return
		}
	}))
	defer server.Close()

	head := decodedHeader(t, map[string]any{"alg": "RS256", "jku": server.URL})
	opts := &model.JoseOptions{AllowedSigningAlgorithms: []jwa.Algorithm{jwa.ES256}}

	retrievers, err := ValidateHeader(context.Background(), head, server.Client(), model.JWS, opts)
	if err == nil {
		t.Fatalf("[RFC 8725 3.1] an algorithm the caller has not permitted must be refused, got %d retrievers", len(retrievers))
	}
	if !errors.Is(err, joseerror.ErrUnsupportedAlgorithm) {
		t.Errorf("an algorithm the caller declined was never examined as a signature, so the refusal must name the algorithm, got %v", err)
	}
	for _, retrieve := range retrievers {
		_, _ = retrieve()
	}
	if got := fetched.Load(); got != 0 {
		t.Errorf("the algorithm is declined before any key is sought, so no outbound request may be made on this header's behalf, got %d", got)
	}
}

func TestValidateHeader_APermittedAlgorithmIsStillAccepted(t *testing.T) {
	head := decodedHeader(t, map[string]any{"alg": "RS256"})
	opts := &model.JoseOptions{AllowedSigningAlgorithms: []jwa.Algorithm{jwa.ES256, jwa.RS256}}

	if _, err := ValidateHeader(context.Background(), head, nil, model.JWS, opts); err != nil {
		t.Errorf("an algorithm the caller permitted must be accepted, got %v", err)
	}
}
