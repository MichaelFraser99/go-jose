package jws

import (
	"context"
	"errors"
	"fmt"
	"github.com/MichaelFraser99/go-jose/internal/jose/header"
	"github.com/MichaelFraser99/go-jose/internal/jose/jsonutils"
	"github.com/MichaelFraser99/go-jose/joseerror"
	"github.com/MichaelFraser99/go-jose/jwa"
	"github.com/MichaelFraser99/go-jose/model"
	"net/http"
	"strings"
)

//todo: should we consider json serialization? - no-one really uses it

// Verify verifies a JWS Compact Serialization as RFC 7515 section 5.2 describes
// and returns its protected header and its payload octets. The payload is not
// parsed: section 2 lets it be an arbitrary sequence of octets.
func Verify(ctx context.Context, compactSerialization string, outOfBoundsPublicKey model.Retriever, opts *model.JoseOptions) (protectedHeader map[string]any, payload []byte, err error) {
	protectedHeader, payload, _, err = verify(ctx, compactSerialization, outOfBoundsPublicKey, opts, false)
	return protectedHeader, payload, err
}

// VerifyCompactSerialization verifies a JWS Compact Serialization as Verify does,
// and also requires the payload to be a UTF-8 JSON object, as RFC 7519 section
// 7.2 step 10 requires of a JWT Claims Set. A cty of "JWT" marks a Nested JWT
// (RFC 7519 section 5.2), which is refused as unsupported before any key is sought.
func VerifyCompactSerialization(ctx context.Context, compactSerialization string, outOfBoundsPublicKey model.Retriever, opts *model.JoseOptions) (protectedHeader, body map[string]any, err error) {
	protectedHeader, _, body, err = verify(ctx, compactSerialization, outOfBoundsPublicKey, opts, true)
	return protectedHeader, body, err
}

const defaultMaxKeysTried = 100

func verify(ctx context.Context, compactSerialization string, outOfBoundsPublicKey model.Retriever, opts *model.JoseOptions, payloadIsJSONObject bool) (protectedHeader map[string]any, payload []byte, body map[string]any, err error) {
	if ctx == nil {
		return nil, nil, nil, fmt.Errorf("%wthe context passed is nil", joseerror.ErrInvalidOptions)
	}
	components := strings.Split(compactSerialization, ".")
	if len(components) != 3 {
		return nil, nil, nil, fmt.Errorf("%winvalid compact serialization format", joseerror.ErrMalformedToken)
	}

	protectedHeader, err = jsonutils.DecodeBase64urlMap(components[0])
	if err != nil {
		return nil, nil, nil, fmt.Errorf("%werror processing protected header: %v", joseerror.ErrMalformedToken, err)
	}

	if name, ok := protectedHeader["alg"].(string); ok {
		if alg := jwa.GetAlgorithm(name); alg != jwa.Unknown && !hasValidator(alg) {
			return nil, nil, nil, fmt.Errorf("%werror validating header: %w%q has no validator in this library", joseerror.ErrMalformedToken, joseerror.ErrUnsupportedAlgorithm, alg.String())
		}
	}

	var jwkRetrievers []model.Retriever

	if outOfBoundsPublicKey != nil {
		jwkRetrievers = append(jwkRetrievers, outOfBoundsPublicKey)
	}

	var client *http.Client
	if opts != nil {
		client = opts.HttpClient
	}

	headerJwkRetrievers, err := header.ValidateHeader(ctx, protectedHeader, client, opts)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("%werror validating header: %w", joseerror.ErrMalformedToken, err)
	}

	if payloadIsJSONObject && header.NamesNestedJWT(protectedHeader) {
		return nil, nil, nil, fmt.Errorf("%wnested JWTs are not supported: the 'cty' header names JWT", joseerror.ErrMalformedToken)
	}

	jwkRetrievers = append(jwkRetrievers, headerJwkRetrievers...)

	if len(jwkRetrievers) == 0 {
		return nil, nil, nil, fmt.Errorf("%wno cryptographic material provided for signature validation", joseerror.ErrMalformedToken)
	}

	payload, err = jsonutils.DecodeBase64url(components[1])
	if err != nil {
		return nil, nil, nil, fmt.Errorf("%werror decoding payload: %v", joseerror.ErrMalformedToken, err)
	}
	if payloadIsJSONObject {
		body, err = jsonutils.DecodeJSONObject(payload)
		if err != nil {
			return nil, nil, nil, fmt.Errorf("%werror processing body: %v", joseerror.ErrMalformedToken, err)
		}
	}

	signature, err := jsonutils.DecodeBase64url(components[2])
	if err != nil {
		return nil, nil, nil, fmt.Errorf("%werror decoding signature: %v", joseerror.ErrMalformedToken, err)
	}

	algorithm := jwa.GetAlgorithm(protectedHeader["alg"].(string))

	maxKeysTried := defaultMaxKeysTried
	if opts != nil && opts.MaxKeysTried > 0 {
		maxKeysTried = opts.MaxKeysTried
	}
	keysTried := 0
	signingInput := []byte(components[0] + "." + components[1])

	var noKeyIdentifierErrors, sourceFailures []error
	for _, retriever := range jwkRetrievers {
		if keysTried == maxKeysTried {
			return nil, nil, nil, tooManyKeys(maxKeysTried, sourceFailures)
		}
		publicKeys, err := retriever()
		if errors.Is(err, joseerror.ErrNoKeyIdentifierMatch) {
			noKeyIdentifierErrors = append(noKeyIdentifierErrors, err)
			continue
		}
		if err != nil {
			if header.FromCarriedSource(err) {
				return nil, nil, nil, err
			}
			sourceFailures = append(sourceFailures, err)
			continue
		}

		for _, pubKey := range publicKeys {
			validator, err := GetValidator(algorithm, pubKey)
			if err != nil {
				continue
			}
			if keysTried == maxKeysTried {
				return nil, nil, nil, tooManyKeys(maxKeysTried, sourceFailures)
			}
			keysTried++

			if valid, err := validator.ValidateSignature(signingInput, signature); err == nil && valid {
				return protectedHeader, payload, body, nil
			}
		}
	}

	if len(sourceFailures) > 0 {
		return nil, nil, nil, wrapAll(sourceFailures)
	}
	if len(noKeyIdentifierErrors) > 0 {
		return nil, nil, nil, fmt.Errorf("%wunable to validate jws signature - possibly due to the following errors encountered retrieving cryptographic material: %w", joseerror.ErrInvalidSignature, wrapAll(noKeyIdentifierErrors))
	}
	return nil, nil, nil, fmt.Errorf("%wunable to validate jws signature", joseerror.ErrInvalidSignature)
}

func tooManyKeys(maxKeysTried int, sourceFailures []error) error {
	refusal := fmt.Errorf("%wthe signature did not verify under the %d keys JoseOptions.MaxKeysTried allows", joseerror.ErrTooManyKeys, maxKeysTried)
	if len(sourceFailures) == 0 {
		return refusal
	}
	return wrapAll(append([]error{refusal}, sourceFailures...))
}

func wrapAll(errs []error) error {
	format := strings.TrimSuffix(strings.Repeat("%w; ", len(errs)), "; ")
	args := make([]any, len(errs))
	for i, err := range errs {
		args[i] = err
	}
	return fmt.Errorf(format, args...)
}
