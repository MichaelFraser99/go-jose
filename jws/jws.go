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
// parsed: section 2 lets it be an arbitrary sequence of octets. A token that
// breaks RFC 7515 is refused with ErrMalformedToken wrapping the reason. A
// well-formed token refused by opts, or naming what this library does not
// implement, is refused with that reason alone.
//
// ctx bounds any jku or x5u fetch, and is checked after the token's format and
// header are checked, before each key source is tried, and after the last. Once
// it has ended, its error is returned, matching context.Canceled or
// context.DeadlineExceeded, and no further source is tried. A key that has
// already verified the token still verifies it: ending ctx stops work, and
// does not undo a signature that was checked.
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

// CheckOptions refuses, with ErrInvalidOptions, options that are wrong whatever
// the token: an AllowedSigningAlgorithms entry this library has no validator
// for, such as a JWE alg, an AcceptedTypes entry that is not a media type
// name (RFC 6838 section 4.2), and an AllowedKeyURLs entry that is not an https
// URL with a host (RFC 7515 sections 4.1.2 and 4.1.5, RFC 9110 section 4.2.2)
// or that holds a character outside RFC 3986 section 2. Verify and
// VerifyCompactSerialization call it before reading the token.
func CheckOptions(opts *model.JoseOptions) error {
	if opts == nil {
		return nil
	}
	for _, alg := range opts.AllowedSigningAlgorithms {
		if !hasValidator(alg) {
			name := alg.String()
			if alg == jwa.Unknown {
				name = "jwa.Unknown (what GetAlgorithm returns for a name it does not recognise)"
			} else if name == "" {
				name = fmt.Sprintf("jwa.Algorithm(%d)", int(alg))
			}
			return fmt.Errorf("%wAllowedSigningAlgorithms holds %s, which is not a signature algorithm this library implements", joseerror.ErrInvalidOptions, name)
		}
	}
	if err := header.CheckAcceptedTypes(opts.AcceptedTypes); err != nil {
		return err
	}
	return header.CheckAllowedKeyURLs(opts.AllowedKeyURLs)
}

func verify(ctx context.Context, compactSerialization string, outOfBoundsPublicKey model.Retriever, opts *model.JoseOptions, payloadIsJSONObject bool) (protectedHeader map[string]any, payload []byte, body map[string]any, err error) {
	if ctx == nil {
		return nil, nil, nil, fmt.Errorf("%wthe context passed is nil", joseerror.ErrInvalidOptions)
	}
	if err := CheckOptions(opts); err != nil {
		return nil, nil, nil, err
	}
	components := strings.SplitN(compactSerialization, ".", 4)
	if len(components) != 3 {
		return nil, nil, nil, fmt.Errorf("%winvalid compact serialization format", joseerror.ErrMalformedToken)
	}

	protectedHeader, err = jsonutils.DecodeBase64urlMap(components[0])
	if err != nil {
		return nil, nil, nil, fmt.Errorf("%werror processing protected header: %v", joseerror.ErrMalformedToken, err)
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
		return nil, nil, nil, err
	}
	if alg := jwa.GetAlgorithm(protectedHeader["alg"].(string)); !hasValidator(alg) {
		return nil, nil, nil, fmt.Errorf("%w%q has no validator in this library", joseerror.ErrUnsupportedAlgorithm, alg.String())
	}

	if payloadIsJSONObject && header.NamesNestedJWT(protectedHeader) {
		return nil, nil, nil, fmt.Errorf("%wa JWT signed inside a JWS is not supported: the 'cty' header names JWT. A JWT signed and then encrypted is, through jwt.Validate", joseerror.ErrUnsupportedAlgorithm)
	}

	jwkRetrievers = append(jwkRetrievers, headerJwkRetrievers...)

	if len(jwkRetrievers) == 0 {
		if opts == nil || !opts.UseTokenProvidedKeys && opts.X509Roots == nil {
			return nil, nil, nil, fmt.Errorf("%wno retriever was given and no key the token names is allowed, so no token can verify; pass a retriever, or set UseTokenProvidedKeys or X509Roots", joseerror.ErrInvalidOptions)
		}
		return nil, nil, nil, fmt.Errorf("%wno retriever was given and the token names no key this verifier may use", joseerror.ErrNoKeyIdentifierMatch)
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
		if err := ctx.Err(); err != nil {
			return nil, nil, nil, err
		}
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

	if err := ctx.Err(); err != nil {
		return nil, nil, nil, err
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
