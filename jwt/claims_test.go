package jwt

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"math"
	"strings"
	"testing"
	"time"

	"github.com/MichaelFraser99/go-jose/internal/algorithms/es256"
	"github.com/MichaelFraser99/go-jose/joseerror"
	"github.com/MichaelFraser99/go-jose/jwa"
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
	_, err = Validate(context.Background(), input+"."+base64.RawURLEncoding.EncodeToString(signature), newTestRetriever(signer.Public()), nil, opts, nil)
	return err
}

type claimsTestCase struct {
	name    string
	payload string
	opts    *model.JoseOptions
	want    error
	notWant error
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
			if tt.notWant != nil && errors.Is(err, tt.notWant) {
				t.Errorf("[%s] %s: must not match %q, got %q", tt.clause, tt.payload, tt.notWant, err)
			}
		})
	}
}

func TestValidate_TimeClaimsKeepTheirFraction(t *testing.T) {
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
		{name: "an empty expected value against an empty string", payload: `{"aud":""}`, opts: expect(""), want: joseerror.ErrInvalidOptions, clause: "RFC 7519 4.1.3"},
		{name: "an empty expected value against an array holding an empty string", payload: `{"aud":[""]}`, opts: expect(""), want: joseerror.ErrInvalidOptions, clause: "RFC 7519 4.1.3"},
		{name: "an empty expected value beside one the token names", payload: `{"aud":"https://rp.example"}`, opts: expect("https://rp.example", ""), want: joseerror.ErrInvalidOptions, clause: "RFC 7519 4.1.3"},
		{name: "an empty expected value against a token with no aud", payload: `{"sub":"a"}`, opts: expect(""), want: joseerror.ErrInvalidOptions, clause: "RFC 7519 4.1.3"},
	})
}

func TestValidate_AnEmptyExpectedAudienceIsRefusedBeforeTheTokenIsRead(t *testing.T) {
	for _, token := range []string{"", "not a token", "a.b.c"} {
		_, err := Validate(context.Background(), token, nil, nil, &model.JoseOptions{ExpectedAudience: []string{""}}, nil)
		if !errors.Is(err, joseerror.ErrInvalidOptions) {
			t.Errorf("[RFC 7519 4.1.3] an empty string names no recipient, so the options are refused whatever the token %q: want %q, got %v", token, joseerror.ErrInvalidOptions, err)
		}
	}
}

func TestValidate_TimeClaimsAreJudgedToTheMicrosecond(t *testing.T) {
	claimsTestRun(t, []claimsTestCase{
		{name: "exp a microsecond ahead is accepted", payload: `{"exp":1700000000.400001}`, clause: "RFC 7519 4.1.4"},
		{name: "exp a microsecond behind is expired", payload: `{"exp":1700000000.399999}`, want: joseerror.ErrExpired, clause: "RFC 7519 4.1.4"},
		{name: "nbf a microsecond ahead is not yet valid", payload: `{"nbf":1700000000.400001}`, want: joseerror.ErrNotYetValid, clause: "RFC 7519 4.1.5"},
		{name: "nbf a microsecond behind is accepted", payload: `{"nbf":1700000000.399999}`, clause: "RFC 7519 4.1.5"},
	})
}

func TestValidate_ANumberBeyondTheFloat64RangeIsRefusedAsAMalformedToken(t *testing.T) {
	claimsTestRun(t, []claimsTestCase{
		{name: "exp of 1e400", payload: `{"exp":1e400}`, want: joseerror.ErrMalformedToken, clause: "RFC 8259 6"},
		{name: "nbf of -1e400", payload: `{"nbf":-1e400}`, want: joseerror.ErrMalformedToken, clause: "RFC 8259 6"},
		{name: "a private claim of 1e400", payload: `{"n":1e400}`, want: joseerror.ErrMalformedToken, clause: "RFC 8259 6"},
		{name: "exp of the largest float64 is accepted", payload: `{"exp":1.7976931348623157e308}`, clause: "RFC 7519 4.1.4"},
		{name: "nbf of the largest float64 is not yet valid", payload: `{"nbf":1.7976931348623157e308}`, want: joseerror.ErrNotYetValid, clause: "RFC 7519 4.1.5"},
	})
	for _, payload := range []string{`{"exp":1e400}`, `{"iat":1e400}`} {
		claimsTestFixClock(t, claimsTestNow)
		if err := claimsTestValidate(t, payload, nil); errors.Is(err, joseerror.ErrMalformedClaim) {
			t.Errorf("[RFC 8259 6] %s is refused by the JSON decoder before any claim is judged, so it must not match ErrMalformedClaim, got %q", payload, err)
		}
	}
}

func TestValidate_RefusesOptionValuesNoTokenCanMeetWhateverTheToken(t *testing.T) {
	for name, opts := range map[string]*model.JoseOptions{
		"a JWE alg in AllowedSigningAlgorithms": {AllowedSigningAlgorithms: []jwa.Algorithm{jwa.A128KW}},
		"an AcceptedTypes entry with a space":   {AcceptedTypes: []string{"JWT "}},
	} {
		for _, token := range []string{"a.b.c", "a.b.c.d.e", "garbage"} {
			if validated, err := Validate(context.Background(), token, nil, nil, opts, nil); !errors.Is(err, joseerror.ErrInvalidOptions) || validated != nil {
				t.Errorf("[RFC 6838 4.2, RFC 8725 3.1] %s can match no token, so Validate must refuse %q with ErrInvalidOptions, got %v", name, token, err)
			}
		}
	}
	for name, jweOpts := range map[string]*model.JWEOptions{
		"a JWS alg in AllowedKeyManagementAlgorithms": {AllowedKeyManagementAlgorithms: []jwa.Algorithm{jwa.ES256}},
		"an AcceptedTypes entry with a space":         {AcceptedTypes: []string{" JWT"}},
	} {
		for _, token := range []string{"a.b.c", "a.b.c.d.e", "garbage"} {
			if validated, err := Validate(context.Background(), token, nil, nil, nil, jweOpts); !errors.Is(err, joseerror.ErrInvalidOptions) || validated != nil {
				t.Errorf("[RFC 6838 4.2, RFC 8725 3.1] JWEOptions with %s can match no token, so Validate must refuse %q with ErrInvalidOptions, even one of three segments, got %v", name, token, err)
			}
		}
	}
}

func TestValidate_RequiredClaims(t *testing.T) {
	require := func(names ...string) *model.JoseOptions {
		return &model.JoseOptions{RequiredClaims: names}
	}
	claimsTestRun(t, []claimsTestCase{
		{name: "nil options require nothing", payload: `{}`, clause: "RFC 7519 4.1"},
		{name: "zero options require nothing", payload: `{}`, opts: &model.JoseOptions{}, clause: "RFC 7519 4.1"},
		{name: "an empty list requires nothing", payload: `{}`, opts: require(), clause: "RFC 7519 4.1"},
		{name: "a required exp that is absent", payload: `{"sub":"a"}`, opts: require("exp"), want: joseerror.ErrMissingClaim, clause: "RFC 7519 4.1"},
		{name: "a required exp that is present", payload: `{"exp":1800000000}`, opts: require("exp"), clause: "RFC 7519 4.1"},
		{name: "a required exp that is null is still not a NumericDate", payload: `{"exp":null}`, opts: require("exp"), want: joseerror.ErrMalformedClaim, notWant: joseerror.ErrMissingClaim, clause: "RFC 7519 4.1.4"},
		{name: "a required exp that is present and expired", payload: `{"exp":1600000000}`, opts: require("exp"), want: joseerror.ErrExpired, clause: "RFC 7519 4.1.4"},
		{name: "a required private claim that is null is a member", payload: `{"tenant":null}`, opts: require("tenant"), clause: "RFC 7519 4"},
		{name: "a required private claim that is false is a member", payload: `{"tenant":false}`, opts: require("tenant"), clause: "RFC 7519 4"},
		{name: "a required private claim that is an empty string is a member", payload: `{"tenant":""}`, opts: require("tenant"), clause: "RFC 7519 4"},
		{name: "a required private claim that is an empty object is a member", payload: `{"tenant":{}}`, opts: require("tenant"), clause: "RFC 7519 4"},
		{name: "a claim nested in another object is not a member", payload: `{"ext":{"tenant":"a"}}`, opts: require("tenant"), want: joseerror.ErrMissingClaim, clause: "RFC 7519 4"},
		{name: "every required claim present", payload: `{"iss":"https://issuer.example","sub":"a","exp":1800000000}`, opts: require("iss", "sub", "exp"), clause: "RFC 7519 4.1"},
		{name: "one of several required claims absent", payload: `{"iss":"https://issuer.example","exp":1800000000}`, opts: require("iss", "sub", "exp"), want: joseerror.ErrMissingClaim, clause: "RFC 7519 4.1"},
		{name: "a name differing only in case", payload: `{"EXP":1800000000}`, opts: require("exp"), want: joseerror.ErrMissingClaim, clause: "RFC 7519 10.1.1"},
		{name: "a required name differing only in case", payload: `{"exp":1800000000}`, opts: require("EXP"), want: joseerror.ErrMissingClaim, clause: "RFC 7519 10.1.1"},
		{name: "a name with a trailing space", payload: `{"exp ":1800000000}`, opts: require("exp"), want: joseerror.ErrMissingClaim, clause: "RFC 7519 7.3"},
		{name: "a name written with a JSON escape", payload: `{"exp":1800000000}`, opts: require("exp"), clause: "RFC 8259 8.3"},
		{name: "a name in NFD against one in NFC", payload: `{"café":1}`, opts: require("café"), want: joseerror.ErrMissingClaim, clause: "RFC 7519 7.3"},
		{name: "a name in NFC against one in NFC", payload: `{"café":1}`, opts: require("café"), clause: "RFC 7519 7.3"},
		{name: "a duplicated requirement that is met", payload: `{"exp":1800000000}`, opts: require("exp", "exp"), clause: "RFC 7519 4.1"},
		{name: "a duplicated requirement that is not met", payload: `{}`, opts: require("exp", "exp"), want: joseerror.ErrMissingClaim, clause: "RFC 7519 4.1"},
		{name: "a duplicated member whose last value is null is a member", payload: `{"tenant":1,"tenant":null}`, opts: require("tenant"), clause: "RFC 7519 4"},
		{name: "an empty name against a token with an empty-named member", payload: `{"":1}`, opts: require(""), want: joseerror.ErrInvalidOptions, clause: "RFC 7519 4"},
		{name: "an empty name beside one that is met", payload: `{"exp":1800000000}`, opts: require("exp", ""), want: joseerror.ErrInvalidOptions, clause: "RFC 7519 4"},
		{name: "an empty name against an expired token", payload: `{"exp":1600000000}`, opts: require(""), want: joseerror.ErrInvalidOptions, notWant: joseerror.ErrExpired, clause: "RFC 7519 4"},
		{name: "an empty name against a token with a malformed iss", payload: `{"iss":5}`, opts: require(""), want: joseerror.ErrInvalidOptions, notWant: joseerror.ErrMalformedClaim, clause: "RFC 7519 4"},
	})
}

func TestValidate_AMissingRequiredClaimIsNamedInTheError(t *testing.T) {
	claimsTestFixClock(t, claimsTestNow)
	err := claimsTestValidate(t, `{"iss":"https://issuer.example","exp":1800000000}`, &model.JoseOptions{RequiredClaims: []string{"iss", "sub", "exp"}})
	if !errors.Is(err, joseerror.ErrMissingClaim) || !strings.Contains(err.Error(), `"sub"`) {
		t.Fatalf(`[RFC 7519 4.1] the error must name the absent claim "sub", got %v`, err)
	}
	for _, present := range []string{`"iss"`, `"exp"`} {
		if strings.Contains(err.Error(), present) {
			t.Errorf("[RFC 7519 4.1] the error must not name %s, which is present, got %q", present, err)
		}
	}
}

func TestValidate_ExpectedIssuer(t *testing.T) {
	expect := func(issuers ...string) *model.JoseOptions {
		return &model.JoseOptions{ExpectedIssuer: issuers}
	}
	one := expect("https://issuer.example")
	claimsTestRun(t, []claimsTestCase{
		{name: "no expectation accepts any issuer", payload: `{"iss":"https://someone-else.example"}`, clause: "RFC 7519 4.1.1"},
		{name: "zero options accept any issuer", payload: `{"iss":"https://someone-else.example"}`, opts: &model.JoseOptions{}, clause: "RFC 7519 4.1.1"},
		{name: "an empty expectation accepts any issuer", payload: `{"iss":"https://someone-else.example"}`, opts: expect(), clause: "RFC 7519 4.1.1"},
		{name: "zero options accept no iss", payload: `{}`, opts: &model.JoseOptions{}, clause: "RFC 7519 4.1.1"},
		{name: "the expected issuer", payload: `{"iss":"https://issuer.example"}`, opts: one, clause: "RFC 7519 4.1.1"},
		{name: "the second of two expected issuers", payload: `{"iss":"https://issuer.example"}`, opts: expect("https://other.example", "https://issuer.example"), clause: "RFC 7519 4.1.1"},
		{name: "an iss written with JSON escapes is the same string", payload: `{"iss":"https:\/\/issuer.example"}`, opts: one, clause: "RFC 8259 8.3"},
		{name: "another issuer", payload: `{"iss":"https://someone-else.example"}`, opts: one, want: joseerror.ErrIssuerMismatch, notWant: joseerror.ErrMissingClaim, clause: "RFC 7519 4.1.1"},
		{name: "an iss differing only in case", payload: `{"iss":"https://ISSUER.example"}`, opts: one, want: joseerror.ErrIssuerMismatch, clause: "RFC 7519 2"},
		{name: "an iss with a trailing slash", payload: `{"iss":"https://issuer.example/"}`, opts: one, want: joseerror.ErrIssuerMismatch, clause: "RFC 7519 2"},
		{name: "an iss without the expected trailing slash", payload: `{"iss":"https://issuer.example"}`, opts: expect("https://issuer.example/"), want: joseerror.ErrIssuerMismatch, clause: "RFC 7519 2"},
		{name: "an iss with the default port", payload: `{"iss":"https://issuer.example:443"}`, opts: one, want: joseerror.ErrIssuerMismatch, clause: "RFC 7519 2"},
		{name: "an iss with a percent-encoded unreserved character", payload: `{"iss":"https://issuer.example/%7Eid"}`, opts: expect("https://issuer.example/~id"), want: joseerror.ErrIssuerMismatch, clause: "RFC 7519 2"},
		{name: "an iss with a trailing space", payload: `{"iss":"https://issuer.example "}`, opts: one, want: joseerror.ErrIssuerMismatch, clause: "RFC 7519 2"},
		{name: "an iss that is a prefix of the expected issuer", payload: `{"iss":"https://issuer"}`, opts: one, want: joseerror.ErrIssuerMismatch, clause: "RFC 7519 2"},
		{name: "an iss that extends the expected issuer", payload: `{"iss":"https://issuer.example.attacker.example"}`, opts: one, want: joseerror.ErrIssuerMismatch, clause: "RFC 7519 2"},
		{name: "an iss that is an empty string", payload: `{"iss":""}`, opts: one, want: joseerror.ErrIssuerMismatch, clause: "RFC 7519 4.1.1"},
		{name: "an iss in NFD against an expected issuer in NFC", payload: `{"iss":"https://café.example"}`, opts: expect("https://café.example"), want: joseerror.ErrIssuerMismatch, clause: "RFC 7519 2"},
		{name: "an iss with a lookalike Cyrillic letter", payload: `{"iss":"https://іssuer.example"}`, opts: one, want: joseerror.ErrIssuerMismatch, clause: "RFC 7519 2"},
		{name: "no iss at all", payload: `{"sub":"a"}`, opts: one, want: joseerror.ErrMissingClaim, notWant: joseerror.ErrIssuerMismatch, clause: "RFC 7519 4.1.1"},
		{name: "an iss that is a number", payload: `{"iss":5}`, opts: one, want: joseerror.ErrMalformedClaim, notWant: joseerror.ErrIssuerMismatch, clause: "RFC 7519 4.1.1"},
		{name: "an iss that is null", payload: `{"iss":null}`, opts: one, want: joseerror.ErrMalformedClaim, notWant: joseerror.ErrMissingClaim, clause: "RFC 7519 4.1.1"},
		{name: "an iss that is an array holding the expected issuer", payload: `{"iss":["https://issuer.example"]}`, opts: one, want: joseerror.ErrMalformedClaim, notWant: joseerror.ErrIssuerMismatch, clause: "RFC 7519 4.1.1"},
		{name: "the expected issuer named in a private claim only", payload: `{"issuer":"https://issuer.example"}`, opts: one, want: joseerror.ErrMissingClaim, clause: "RFC 7519 4.1.1"},
		{name: "an empty expected issuer against an empty iss", payload: `{"iss":""}`, opts: expect(""), want: joseerror.ErrInvalidOptions, clause: "RFC 7519 4.1.1"},
		{name: "an empty expected issuer beside one the token names", payload: `{"iss":"https://issuer.example"}`, opts: expect("https://issuer.example", ""), want: joseerror.ErrInvalidOptions, clause: "RFC 7519 4.1.1"},
		{name: "an empty expected issuer against a token with no iss", payload: `{}`, opts: expect(""), want: joseerror.ErrInvalidOptions, notWant: joseerror.ErrMissingClaim, clause: "RFC 7519 4.1.1"},
		{name: "an empty expected issuer against an expired token", payload: `{"exp":1600000000}`, opts: expect(""), want: joseerror.ErrInvalidOptions, notWant: joseerror.ErrExpired, clause: "RFC 7519 4.1.1"},
	})
}

func TestValidate_AnIssuerMismatchQuotesTheIssBounded(t *testing.T) {
	opts := &model.JoseOptions{ExpectedIssuer: []string{"https://issuer.example"}}
	for name, iss := range map[string]string{
		"a megabyte of ASCII":               strings.Repeat("a", 1<<20),
		"an escaped line break":             `https://issuer.example\nlevel=admin`,
		"half a megabyte of two-byte runes": strings.Repeat("é", 1<<18),
	} {
		t.Run(name, func(t *testing.T) {
			claimsTestFixClock(t, claimsTestNow)
			err := claimsTestValidate(t, `{"iss":"`+iss+`"}`, opts)
			if !errors.Is(err, joseerror.ErrIssuerMismatch) {
				t.Fatalf("[RFC 7519 4.1.1] an iss of %s is not the expected issuer, want %q, got %v", name, joseerror.ErrIssuerMismatch, err)
			}
			if strings.ContainsAny(err.Error(), "\n\r") {
				t.Errorf("[RFC 7519 4.1.1] the error must quote the peer's iss, not echo a raw line break, got %q", err)
			}
			if len(err.Error()) > 512 {
				t.Errorf("[RFC 7519 4.1.1] the error must echo a bounded prefix of the peer's iss, got %d bytes", len(err.Error()))
			}
		})
	}
}

func TestValidate_AnEmptyRequiredClaimOrExpectedIssuerIsRefusedBeforeTheTokenIsRead(t *testing.T) {
	for name, opts := range map[string]*model.JoseOptions{
		"RequiredClaims": {RequiredClaims: []string{""}},
		"ExpectedIssuer": {ExpectedIssuer: []string{""}},
	} {
		for _, token := range []string{"", "not a token", "a.b.c", "a.b.c.d.e"} {
			if validated, err := Validate(context.Background(), token, nil, nil, opts, nil); !errors.Is(err, joseerror.ErrInvalidOptions) || validated != nil {
				t.Errorf("[RFC 7519 4.1] an empty string in %s names nothing, so the options are refused whatever the token %q: want %q, got %v", name, token, joseerror.ErrInvalidOptions, err)
			}
		}
	}
}
