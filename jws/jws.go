package jws

import (
	"crypto"
	"encoding/base64"
	"errors"
	"fmt"
	"github.com/MichaelFraser99/go-jose/internal/jose/header"
	"github.com/MichaelFraser99/go-jose/internal/jose/jsonutils"
	"github.com/MichaelFraser99/go-jose/joseerror"
	"github.com/MichaelFraser99/go-jose/jwa"
	"github.com/MichaelFraser99/go-jose/model"
	"slices"
	"strings"
)

//todo: should we consider json serialization? - no-one really uses it

func VerifyCompactSerialization(compactSerialization string, outOfBoundsPublicKey model.Retriever, opts *model.JoseOptions) (protectedHeader, body map[string]any, err error) {
	components := strings.Split(compactSerialization, ".")
	if len(components) != 3 {
		return nil, nil, fmt.Errorf("%winvalid compact serialization format", joseerror.ErrMalformedToken)
	}

	protectedHeader, err = jsonutils.DecodeBase64urlMap(components[0])
	if err != nil {
		return nil, nil, fmt.Errorf("%werror processing protected header: %v", joseerror.ErrMalformedToken, err)
	}

	var jwkRetrievers []model.Retriever

	if outOfBoundsPublicKey != nil {
		jwkRetrievers = append(jwkRetrievers, outOfBoundsPublicKey)
	}

	headerJwkRetrievers, err := header.ValidateHeader(protectedHeader, nil, model.JWS) //todo: sort out http client providing
	if err != nil {
		return nil, nil, fmt.Errorf("%werror validating header: %v", joseerror.ErrMalformedToken, err)
	}

	if opts == nil || opts.UseTokenProvidedKeys {
		jwkRetrievers = append(jwkRetrievers, headerJwkRetrievers...)
	}

	if len(jwkRetrievers) == 0 {
		return nil, nil, fmt.Errorf("%wno cyptographic material provided for signature validation", joseerror.ErrMalformedToken)
	}

	body, err = jsonutils.DecodeBase64urlMap(components[1])
	if err != nil {
		return nil, nil, fmt.Errorf("%werror processing body: %v", joseerror.ErrMalformedToken, err)
	}

	signature, err := base64.RawURLEncoding.DecodeString(components[2])
	if err != nil {
		return nil, nil, fmt.Errorf("%werror decoding signature: %v", joseerror.ErrMalformedToken, err)
	}

	algorithm := jwa.GetAlgorithm(protectedHeader["alg"].(string)) //validated to exist and be of correct type earlier

	if opts != nil && len(opts.AllowedSigningAlgorithms) > 0 {
		if !slices.Contains(opts.AllowedSigningAlgorithms, algorithm) {
			return nil, nil, fmt.Errorf("%walgorithm not permitted by application-level constraints", joseerror.ErrInvalidSignature)
		}
	}

	var noKeyIdentifierErrors []error
	for _, retriever := range jwkRetrievers {
		var publicKeys []crypto.PublicKey
		publicKeys, err = retriever()
		if err != nil {
			if !errors.Is(err, joseerror.ErrNoKeyIdentifierMatch) {
				return nil, nil, err
			} else {
				//if error is 'no key identifier', we ignore failure and store for later reporting
				noKeyIdentifierErrors = append(noKeyIdentifierErrors, err)
				continue
			}
		}

		for _, pubKey := range publicKeys {
			validator, err := GetValidator(algorithm, pubKey)
			if err != nil {
				continue //ignore public key invalid for given algorithm
			}

			valid, err := validator.ValidateSignature([]byte(fmt.Sprintf("%s.%s", components[0], components[1])), signature)
			if err != nil {
				continue //ignore errors on validating signatures
			}

			if valid {
				return protectedHeader, body, nil
			}
		}
	}

	if len(noKeyIdentifierErrors) > 0 {
		return nil, nil, fmt.Errorf("%wunable to validate jws signature - possibly due to the following errors encountered retrieving cryptographic material: %v", joseerror.ErrInvalidSignature, noKeyIdentifierErrors)
	}
	return nil, nil, fmt.Errorf("%wunable to validate jws signature", joseerror.ErrInvalidSignature)
}
