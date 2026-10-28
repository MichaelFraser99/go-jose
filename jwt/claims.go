package jwt

import (
	"fmt"
	"math"
	"slices"
	"time"

	"github.com/MichaelFraser99/go-jose/joseerror"
	"github.com/MichaelFraser99/go-jose/model"
)

var clock = time.Now

func validateClaims(body map[string]any, opts *model.JoseOptions) error {
	for _, name := range []string{"iss", "sub", "jti"} {
		if value, present := body[name]; present {
			if _, ok := value.(string); !ok {
				return fmt.Errorf("%wthe '%s' claim must be a string", joseerror.ErrMalformedClaim, name)
			}
		}
	}
	audience, audiencePresent, err := audienceClaim(body)
	if err != nil {
		return err
	}

	iat, err := numericDate(body, "iat", math.Inf(-1))
	if err != nil {
		return err
	}
	nbf, err := numericDate(body, "nbf", math.Inf(-1))
	if err != nil {
		return err
	}
	exp, err := numericDate(body, "exp", math.Inf(1))
	if err != nil {
		return err
	}

	leeway := 0.0
	if opts != nil && opts.ClockSkewLeeway > 0 {
		leeway = opts.ClockSkewLeeway.Seconds()
	}
	now := float64(clock().UnixNano()) / 1e9

	if now+leeway < iat {
		return fmt.Errorf("%wthe 'iat' claim is after the current time", joseerror.ErrNotYetValid)
	}
	if now+leeway < nbf {
		return fmt.Errorf("%wthe 'nbf' claim is after the current time", joseerror.ErrNotYetValid)
	}
	if now-leeway >= exp {
		return fmt.Errorf("%wthe current time is not before the 'exp' claim", joseerror.ErrExpired)
	}

	if opts == nil || len(opts.ExpectedAudience) == 0 {
		return nil
	}
	if !audiencePresent {
		return fmt.Errorf("%wthe 'aud' claim is required when an audience is expected", joseerror.ErrMissingClaim)
	}
	for _, value := range audience {
		if slices.Contains(opts.ExpectedAudience, value) {
			return nil
		}
	}
	return fmt.Errorf("%wthe 'aud' claim does not name this recipient", joseerror.ErrAudienceMismatch)
}

func numericDate(body map[string]any, name string, absent float64) (float64, error) {
	value, present := body[name]
	if !present {
		return absent, nil
	}
	seconds, ok := value.(float64)
	if !ok {
		return 0, fmt.Errorf("%wthe '%s' claim must be a NumericDate", joseerror.ErrMalformedClaim, name)
	}
	return seconds, nil
}

func audienceClaim(body map[string]any) ([]string, bool, error) {
	value, present := body["aud"]
	if !present {
		return nil, false, nil
	}
	if single, ok := value.(string); ok {
		return []string{single}, true, nil
	}
	malformed := fmt.Errorf("%wthe 'aud' claim must be a string or an array of strings", joseerror.ErrMalformedClaim)
	values, ok := value.([]any)
	if !ok {
		return nil, false, malformed
	}
	audience := make([]string, 0, len(values))
	for _, entry := range values {
		s, ok := entry.(string)
		if !ok {
			return nil, false, malformed
		}
		audience = append(audience, s)
	}
	return audience, true, nil
}
