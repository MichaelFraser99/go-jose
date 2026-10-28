package jwk

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"testing"

	"github.com/MichaelFraser99/go-jose/joseerror"
)

const rfc7638ExampleN = "0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx4cbbfAAtVT86zwu1RK7aPFFxuhDR1L6tSoc_BJECPebWKRXjBZCiFV4n3oknjhMstn64tZ_2W-5JsGY4Hc5n9yBXArwl93lqt7_RN5w6Cf0h4QyQ5v-65YGjQR0_FDW2QvzqY368QQMicAtaSqzs8KJZgnYb9c7d0zgdAZHzu6qMQvRL5hajrn1n91CbOpbISD08qNLyrdkt-bFTWhAI4vMQFh6WeZu0fM4lFd2NcRwr3XPksINHaQ-G_xBniIqbw0Ls1jF44-csFCur-kEgU8awapJzKnqDKgw"

func TestThumbprint_MatchesTheRFCExamples(t *testing.T) {
	tests := map[string]struct {
		jwk       map[string]any
		want      string
		reference string
	}{
		"the RFC 7638 RSA example, with its optional members": {
			jwk:       map[string]any{"kty": "RSA", "n": rfc7638ExampleN, "e": "AQAB", "alg": "RS256", "kid": "2011-04-29"},
			want:      "NzbLsXh8uDCcd-6MNwXF4W_7noWXFZAfHkxZsRGC9Xs",
			reference: "RFC 7638 3.1",
		},
		"the RFC 8037 Ed25519 example": {
			jwk:       map[string]any{"kty": "OKP", "crv": "Ed25519", "x": "11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo"},
			want:      "kPrK_qmxVWaYVA9wwBF6Iuo3vVzz7TxHCTwXBygrS4k",
			reference: "RFC 8037 A.3",
		},
		"the RFC 8037 Ed25519 example as a private key": {
			jwk:       map[string]any{"kty": "OKP", "crv": "Ed25519", "d": "nWGxne_9WmC6hEr0kuwsxERJxWl7MmkZcDusAxyuf2A", "x": "11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo"},
			want:      "kPrK_qmxVWaYVA9wwBF6Iuo3vVzz7TxHCTwXBygrS4k",
			reference: "RFC 7638 3.2.1",
		},
	}

	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			got, err := Thumbprint(test.jwk)
			if err != nil {
				t.Fatalf("[%s] expected a thumbprint, got %v", test.reference, err)
			}
			if got != test.want {
				t.Errorf("[%s] expected %s, got %s", test.reference, test.want, got)
			}
		})
	}
}

func TestThumbprint_AnECKeyHashesItsCanonicalRequiredMembers(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	public, err := key.PublicKey.Bytes()
	if err != nil {
		t.Fatal(err)
	}
	x := base64.RawURLEncoding.EncodeToString(public[1:33])
	y := base64.RawURLEncoding.EncodeToString(public[33:])
	canonical := `{"crv":"P-256","kty":"EC","x":"` + x + `","y":"` + y + `"}`
	digest := sha256.Sum256([]byte(canonical))
	want := base64.RawURLEncoding.EncodeToString(digest[:])

	got, err := Thumbprint(map[string]any{"y": y, "use": "sig", "x": x, "kty": "EC", "crv": "P-256"})
	if err != nil {
		t.Fatal(err)
	}
	if got != want {
		t.Errorf("[RFC 7638 3.2] an EC thumbprint hashes crv, kty, x and y in that order with no whitespace, expected %s, got %s", want, got)
	}
}

func TestJwk_TheKeyIdentifierIsTheRFC7638Thumbprint(t *testing.T) {
	for name, pair := range keyPairs(t) {
		t.Run(name, func(t *testing.T) {
			public, err := PublicJwk(pair.public)
			if err != nil {
				t.Fatal(err)
			}
			private, err := PrivateJwk(pair.private)
			if err != nil {
				t.Fatal(err)
			}
			want, err := Thumbprint(*public)
			if err != nil {
				t.Fatal(err)
			}
			if (*public)["kid"] != want {
				t.Errorf("[RFC 7638 3] the kid of a public jwk must be its thumbprint, expected %s, got %v", want, (*public)["kid"])
			}
			if (*private)["kid"] != want {
				t.Errorf("[RFC 7638 3.2.1] the kid of a private jwk must be the thumbprint of its public key, expected %s, got %v", want, (*private)["kid"])
			}
		})
	}
}

func TestJwk_KeysOfDifferentTypesCannotShareAKeyIdentifier(t *testing.T) {
	edPublic, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	ed, err := PublicJwk(edPublic)
	if err != nil {
		t.Fatal(err)
	}
	rsaWithTheSameBytes := map[string]any{"kty": "RSA", "n": (*ed)["x"], "e": ""}

	ecKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	ec, err := PublicJwk(&ecKey.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	joined := (*ec)["x"].(string) + (*ec)["y"].(string)
	rsaSplitFromTheEC := map[string]any{"kty": "RSA", "n": joined[:82], "e": joined[82:]}

	tests := map[string]struct {
		a map[string]any
		b map[string]any
	}{
		"Ed25519 x read as an RSA n with an empty e": {a: *ed, b: rsaWithTheSameBytes},
		"P-256 x and y split into an RSA n and e":    {a: *ec, b: rsaSplitFromTheEC},
	}

	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			a, err := Thumbprint(test.a)
			if err != nil {
				t.Fatal(err)
			}
			b, err := Thumbprint(test.b)
			if err != nil {
				t.Fatal(err)
			}
			if a == b {
				t.Errorf("[RFC 7638 3] kty is a required member of every thumbprint, so keys of different types cannot share one, got %s for both", a)
			}
		})
	}
}

func TestThumbprint_RefusesAJwkWhoseThumbprintIsUndefined(t *testing.T) {
	tests := map[string]struct {
		jwk  map[string]any
		want error
	}{
		"no kty":                       {jwk: map[string]any{"n": "AQAB", "e": "AQAB"}, want: joseerror.ErrMalformedClaim},
		"a kty that is not a string":   {jwk: map[string]any{"kty": 7}, want: joseerror.ErrMalformedClaim},
		"an unsupported kty":           {jwk: map[string]any{"kty": "nonsense"}, want: joseerror.ErrUnsupportedAlgorithm},
		"an RSA key with no e":         {jwk: map[string]any{"kty": "RSA", "n": "AQAB"}, want: joseerror.ErrMalformedClaim},
		"an EC key with a numeric x":   {jwk: map[string]any{"kty": "EC", "crv": "P-256", "x": 7, "y": "AQAB"}, want: joseerror.ErrMalformedClaim},
		"an OKP key with no crv":       {jwk: map[string]any{"kty": "OKP", "x": "AQAB"}, want: joseerror.ErrMalformedClaim},
		"an oct key with no k":         {jwk: map[string]any{"kty": "oct"}, want: joseerror.ErrMalformedClaim},
		"a value holding a quote":      {jwk: map[string]any{"kty": "RSA", "n": `AQ"AB`, "e": "AQAB"}, want: joseerror.ErrMalformedClaim},
		"a value holding a backslash":  {jwk: map[string]any{"kty": "RSA", "n": `AQ\AB`, "e": "AQAB"}, want: joseerror.ErrMalformedClaim},
		"a value holding a line break": {jwk: map[string]any{"kty": "RSA", "n": "AQ\nAB", "e": "AQAB"}, want: joseerror.ErrMalformedClaim},
		"a value that is not UTF-8":    {jwk: map[string]any{"kty": "RSA", "n": "AQ\xffAB", "e": "AQAB"}, want: joseerror.ErrMalformedClaim},
	}

	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			got, err := Thumbprint(test.jwk)
			if !errors.Is(err, test.want) {
				t.Errorf("[RFC 7638 3.3] expected %v, got %q and %v", test.want, got, err)
			}
			if got != "" {
				t.Errorf("no thumbprint may be returned alongside the refusal, got %q", got)
			}
		})
	}
}

func TestThumbprint_AnOctKeyHashesKAndKty(t *testing.T) {
	digest := sha256.Sum256([]byte(`{"k":"GawgguFyGrWKav7AX4VKUg","kty":"oct"}`))
	want := base64.RawURLEncoding.EncodeToString(digest[:])
	got, err := Thumbprint(map[string]any{"kty": "oct", "k": "GawgguFyGrWKav7AX4VKUg", "alg": "A128KW"})
	if err != nil {
		t.Fatal(err)
	}
	if got != want {
		t.Errorf("[RFC 7638 3.2] an oct thumbprint hashes k and kty, expected %s, got %s", want, got)
	}
}
