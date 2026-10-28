package jwt

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"math"
	"testing"
	"time"

	"github.com/MichaelFraser99/go-jose/internal/algorithms/es256"
	"github.com/MichaelFraser99/go-jose/joseerror"
	"github.com/MichaelFraser99/go-jose/model"
)

var claimsTestNow = time.Unix(1700000000, 400_000_000)

func claimsTestFixClock(t *testing.T, at time.Time) {
	t.Helper()
	previous := clock
	clock = func() time.Time { return at }
	t.Cleanup(func() { clock = previous })
}

func claimsTestValidate(t *testing.T, payload string, opts *model.JoseOptions) error {
	t.Helper()
	signer, err := es256.NewSigner()
	if err != nil {
		t.Fatalf("building an ES256 signer: %s", err)
	}
	input := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"ES256","typ":"JWT"}`)) + "." + base64.RawURLEncoding.EncodeToString([]byte(payload))
	signature, err := signer.Sign(rand.Reader, []byte(input), nil)
	if err != nil {
		t.Fatalf("signing: %s", err)
	}
	_, _, err = Validate(context.Background(), input+"."+base64.RawURLEncoding.EncodeToString(signature), newTestRetriever(signer.Public()), opts)
	return err
}

type claimsTestCase struct {
	name    string
	payload string
	opts    *model.JoseOptions
	want    error
	clause  string
}

func claimsTestRun(t *testing.T, tests []claimsTestCase) {
	t.Helper()
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			claimsTestFixClock(t, claimsTestNow)
			err := claimsTestValidate(t, tt.payload, tt.opts)
			if tt.want == nil {
				if err != nil {
					t.Errorf("[%s] %s was refused at %s: %s", tt.clause, tt.payload, claimsTestNow.UTC().Format(time.RFC3339Nano), err)
				}
				return
			}
			if err == nil {
				t.Fatalf("[%s] %s was accepted at %s", tt.clause, tt.payload, claimsTestNow.UTC().Format(time.RFC3339Nano))
			}
			if !errors.Is(err, tt.want) {
				t.Errorf("[%s] %s: want %q, got %q", tt.clause, tt.payload, tt.want, err)
			}
		})
	}
}

func TestValidate_TimeClaimsAreJudgedAtFullPrecision(t *testing.T) {
	leeway := &model.JoseOptions{ClockSkewLeeway: 30 * time.Second}
	claimsTestRun(t, []claimsTestCase{
		{name: "exp equal to now is expired", payload: `{"exp":1700000000.4}`, want: joseerror.ErrExpired, clause: "RFC 7519 4.1.4"},
		{name: "exp at the start of the current second is expired", payload: `{"exp":1700000000}`, want: joseerror.ErrExpired, clause: "RFC 7519 4.1.4"},
		{name: "exp a tenth of a second ahead is accepted", payload: `{"exp":1700000000.5}`, clause: "RFC 7519 4.1.4"},
		{name: "nbf equal to now is accepted", payload: `{"nbf":1700000000.4}`, clause: "RFC 7519 4.1.5"},
		{name: "nbf a tenth of a second ahead is not yet valid", payload: `{"nbf":1700000000.5}`, want: joseerror.ErrNotYetValid, clause: "RFC 7519 4.1.5"},
		{name: "nbf a tenth of a second behind is accepted", payload: `{"nbf":1700000000.3}`, clause: "RFC 7519 4.1.5"},
		{name: "iat equal to now is accepted", payload: `{"iat":1700000000.4}`, clause: "jwt.Validate future iat rule"},
		{name: "iat a tenth of a second ahead is not yet valid", payload: `{"iat":1700000000.5}`, want: joseerror.ErrNotYetValid, clause: "jwt.Validate future iat rule"},
		{name: "exp exactly the leeway behind is expired", payload: `{"exp":1699999970.4}`, opts: leeway, want: joseerror.ErrExpired, clause: "RFC 7519 4.1.4"},
		{name: "exp a tenth of a second inside the leeway is accepted", payload: `{"exp":1699999970.5}`, opts: leeway, clause: "RFC 7519 4.1.4"},
		{name: "nbf exactly the leeway ahead is accepted", payload: `{"nbf":1700000030.4}`, opts: leeway, clause: "RFC 7519 4.1.5"},
		{name: "nbf a tenth of a second beyond the leeway is not yet valid", payload: `{"nbf":1700000030.5}`, opts: leeway, want: joseerror.ErrNotYetValid, clause: "RFC 7519 4.1.5"},
		{name: "iat exactly the leeway ahead is accepted", payload: `{"iat":1700000030.4}`, opts: leeway, clause: "jwt.Validate future iat rule"},
		{name: "iat a tenth of a second beyond the leeway is not yet valid", payload: `{"iat":1700000030.5}`, opts: leeway, want: joseerror.ErrNotYetValid, clause: "jwt.Validate future iat rule"},
		{name: "a negative leeway grants none to exp", payload: `{"exp":1700000000.4}`, opts: &model.JoseOptions{ClockSkewLeeway: -time.Minute}, want: joseerror.ErrExpired, clause: "RFC 7519 4.1.4"},
		{name: "a negative leeway does not narrow nbf", payload: `{"nbf":1700000000.4}`, opts: &model.JoseOptions{ClockSkewLeeway: -time.Minute}, clause: "RFC 7519 4.1.5"},
	})
}

func TestValidate_NumericDatesBeyondInt64BehaveTheSameOnEveryArchitecture(t *testing.T) {
	maximumLeeway := &model.JoseOptions{ClockSkewLeeway: time.Duration(math.MaxInt64)}
	claimsTestRun(t, []claimsTestCase{
		{name: "nbf of 1e19 is not yet valid", payload: `{"nbf":1e19}`, want: joseerror.ErrNotYetValid, clause: "RFC 7519 4.1.5"},
		{name: "nbf of 1e300 is not yet valid", payload: `{"nbf":1e300}`, want: joseerror.ErrNotYetValid, clause: "RFC 7519 4.1.5"},
		{name: "nbf of 1e300 is not yet valid under the largest leeway", payload: `{"nbf":1e300}`, opts: maximumLeeway, want: joseerror.ErrNotYetValid, clause: "RFC 7519 4.1.5"},
		{name: "iat of 1e19 is not yet valid", payload: `{"iat":1e19}`, want: joseerror.ErrNotYetValid, clause: "jwt.Validate future iat rule"},
		{name: "exp of 1e19 is accepted", payload: `{"exp":1e19}`, clause: "RFC 7519 4.1.4"},
		{name: "exp of 1e300 is accepted", payload: `{"exp":1e300}`, clause: "RFC 7519 4.1.4"},
		{name: "exp of 1e300 is accepted under the largest leeway", payload: `{"exp":1e300}`, opts: maximumLeeway, clause: "RFC 7519 4.1.4"},
		{name: "exp of -1e19 is expired", payload: `{"exp":-1e19}`, want: joseerror.ErrExpired, clause: "RFC 7519 4.1.4"},
		{name: "exp of -1e300 is expired under the largest leeway", payload: `{"exp":-1e300}`, opts: maximumLeeway, want: joseerror.ErrExpired, clause: "RFC 7519 4.1.4"},
		{name: "nbf of -1e19 is accepted", payload: `{"nbf":-1e19}`, clause: "RFC 7519 4.1.5"},
		{name: "iat of -1e300 is accepted", payload: `{"iat":-1e300}`, clause: "jwt.Validate future iat rule"},
	})
}

func TestValidate_ATimeClaimThatIsNotANumberIsMalformed(t *testing.T) {
	claimsTestRun(t, []claimsTestCase{
		{name: "iat as a string", payload: `{"iat":"1"}`, want: joseerror.ErrMalformedClaim, clause: "RFC 7519 4.1.6"},
		{name: "iat as an object", payload: `{"iat":{}}`, want: joseerror.ErrMalformedClaim, clause: "RFC 7519 4.1.6"},
		{name: "nbf as null", payload: `{"nbf":null}`, want: joseerror.ErrMalformedClaim, clause: "RFC 7519 4.1.5"},
		{name: "nbf as a boolean", payload: `{"nbf":true}`, want: joseerror.ErrMalformedClaim, clause: "RFC 7519 4.1.5"},
		{name: "exp as a string", payload: `{"exp":"soon"}`, want: joseerror.ErrMalformedClaim, clause: "RFC 7519 4.1.4"},
		{name: "exp as an array", payload: `{"exp":[1800000000]}`, want: joseerror.ErrMalformedClaim, clause: "RFC 7519 4.1.4"},
		{name: "exp as a numeric string far in the future", payload: `{"exp":"1800000000"}`, want: joseerror.ErrMalformedClaim, clause: "RFC 7519 4.1.4"},
	})
}

func TestValidate_RegisteredStringClaimsMustBeStrings(t *testing.T) {
	claimsTestRun(t, []claimsTestCase{
		{name: "iss as a number", payload: `{"iss":5}`, want: joseerror.ErrMalformedClaim, clause: "RFC 7519 4.1.1"},
		{name: "iss as null", payload: `{"iss":null}`, want: joseerror.ErrMalformedClaim, clause: "RFC 7519 4.1.1"},
		{name: "sub as an object", payload: `{"sub":{}}`, want: joseerror.ErrMalformedClaim, clause: "RFC 7519 4.1.2"},
		{name: "jti as an array", payload: `{"jti":[]}`, want: joseerror.ErrMalformedClaim, clause: "RFC 7519 4.1.7"},
		{name: "aud as a number", payload: `{"aud":5}`, want: joseerror.ErrMalformedClaim, clause: "RFC 7519 4.1.3"},
		{name: "aud as an object", payload: `{"aud":{}}`, want: joseerror.ErrMalformedClaim, clause: "RFC 7519 4.1.3"},
		{name: "aud as an array of numbers", payload: `{"aud":[1,2]}`, want: joseerror.ErrMalformedClaim, clause: "RFC 7519 4.1.3"},
		{name: "aud as an array with one string and one number", payload: `{"aud":["a",1]}`, want: joseerror.ErrMalformedClaim, clause: "RFC 7519 4.1.3"},
		{name: "aud as an array holding null", payload: `{"aud":[null]}`, want: joseerror.ErrMalformedClaim, clause: "RFC 7519 4.1.3"},
		{name: "every string claim as a string", payload: `{"iss":"https://issuer.example","sub":"","jti":"j1","aud":"https://rp.example"}`, clause: "RFC 7519 4.1"},
		{name: "aud as an array of strings", payload: `{"aud":["https://a.example","https://b.example"]}`, clause: "RFC 7519 4.1.3"},
		{name: "aud as an empty array", payload: `{"aud":[]}`, clause: "RFC 7519 4.1.3"},
	})
}

func TestValidate_ExpectedAudience(t *testing.T) {
	expect := func(audience ...string) *model.JoseOptions {
		return &model.JoseOptions{ExpectedAudience: audience}
	}
	claimsTestRun(t, []claimsTestCase{
		{name: "no expectation accepts any audience", payload: `{"aud":"https://someone-else.example"}`, clause: "RFC 7519 4.1.3"},
		{name: "an empty expectation accepts any audience", payload: `{"aud":"https://someone-else.example"}`, opts: &model.JoseOptions{ExpectedAudience: []string{}}, clause: "RFC 7519 4.1.3"},
		{name: "a single string naming this recipient", payload: `{"aud":"https://rp.example"}`, opts: expect("https://rp.example"), clause: "RFC 7519 4.1.3"},
		{name: "an array naming this recipient second", payload: `{"aud":["https://other.example","https://rp.example"]}`, opts: expect("https://rp.example"), clause: "RFC 7519 4.1.3"},
		{name: "a token naming the second of two expected values", payload: `{"aud":"https://rp.example"}`, opts: expect("https://alias.example", "https://rp.example"), clause: "RFC 7519 4.1.3"},
		{name: "a single string naming someone else", payload: `{"aud":"https://someone-else.example"}`, opts: expect("https://rp.example"), want: joseerror.ErrAudienceMismatch, clause: "RFC 7519 4.1.3"},
		{name: "a value differing only in case", payload: `{"aud":"https://RP.example"}`, opts: expect("https://rp.example"), want: joseerror.ErrAudienceMismatch, clause: "RFC 7519 4.1.3"},
		{name: "a value with a trailing space", payload: `{"aud":"https://rp.example "}`, opts: expect("https://rp.example"), want: joseerror.ErrAudienceMismatch, clause: "RFC 7519 4.1.3"},
		{name: "a value that is a prefix of this recipient", payload: `{"aud":"https://rp"}`, opts: expect("https://rp.example"), want: joseerror.ErrAudienceMismatch, clause: "RFC 7519 4.1.3"},
		{name: "an array naming only others", payload: `{"aud":["https://other.example"]}`, opts: expect("https://rp.example"), want: joseerror.ErrAudienceMismatch, clause: "RFC 7519 4.1.3"},
		{name: "an empty array", payload: `{"aud":[]}`, opts: expect("https://rp.example"), want: joseerror.ErrAudienceMismatch, clause: "RFC 7519 4.1.3"},
		{name: "an empty string", payload: `{"aud":""}`, opts: expect("https://rp.example"), want: joseerror.ErrAudienceMismatch, clause: "RFC 7519 4.1.3"},
		{name: "no aud at all", payload: `{"sub":"a"}`, opts: expect("https://rp.example"), want: joseerror.ErrMissingClaim, clause: "RFC 8725 3.9"},
		{name: "an aud of the wrong type", payload: `{"aud":5}`, opts: expect("https://rp.example"), want: joseerror.ErrMalformedClaim, clause: "RFC 7519 4.1.3"},
		{name: "an array holding this recipient and a number", payload: `{"aud":["https://rp.example",5]}`, opts: expect("https://rp.example"), want: joseerror.ErrMalformedClaim, clause: "RFC 7519 4.1.3"},
		{name: "an array holding this recipient and null", payload: `{"aud":["https://rp.example",null]}`, opts: expect("https://rp.example"), want: joseerror.ErrMalformedClaim, clause: "RFC 7519 4.1.3"},
	})
}
