package header

import (
	"context"
	"fmt"
	"slices"
	"strings"

	"errors"
	"github.com/MichaelFraser99/go-jose/internal/httputils"
	"github.com/MichaelFraser99/go-jose/internal/jose/jsonutils"
	"github.com/MichaelFraser99/go-jose/internal/jose/jwk"
	"github.com/MichaelFraser99/go-jose/internal/jose/x5"
	"github.com/MichaelFraser99/go-jose/joseerror"
	"github.com/MichaelFraser99/go-jose/jwa"
	"github.com/MichaelFraser99/go-jose/model"
	"net/http"
)

// ValidateHeader performs standard JOSE header validation upon the decoded protected header portion of a given JOSE object.
//
// On success, a series of Retriever functions are returned which will yield key(s) for validation purposes.
// On failure, an error object is returned
func ValidateHeader(ctx context.Context, header map[string]any, client *http.Client, mode model.Mode, opts *model.JoseOptions) ([]model.Retriever, error) {
	if opts == nil {
		opts = &model.JoseOptions{}
	}
	//todo: as different considerations must be made between JWS/JWE (think how JWE needs to be aware of the zip parameter if included in the header for further processing, should we return an "additional info" struct?
	//todo: we haven't allowed for the StringOrURI stipulation some keys have - go back through JWS and JWE and adjust as appropriate
	alg, err := jsonutils.RetrieveClaim(header, "alg", jsonutils.ValidateAlg)
	if err != nil {
		return nil, err
	}

	if len(opts.AllowedSigningAlgorithms) > 0 && !slices.Contains(opts.AllowedSigningAlgorithms, jwa.GetAlgorithm(*alg)) {
		return nil, fmt.Errorf("%w'%s' is not permitted by application-level constraints", joseerror.ErrUnsupportedAlgorithm, *alg)
	}

	if err := validateExpectedType(header, opts.AcceptedTypes); err != nil {
		return nil, err
	}

	if err := validateKeyIdentifierRequirement(header, opts.RequireKeyIdentifier); err != nil {
		return nil, err
	}

	if mode == model.JWE {
		_, err = jsonutils.RetrieveClaim(header, "enc", jsonutils.ValidateAlg)
		if err != nil {
			return nil, err
		} //todo: do something with value

		_, err = jsonutils.RetrieveClaim[string](header, "zip")       //todo: we can do a validator for zip options this implementation understands
		if err != nil && !errors.Is(err, joseerror.ErrMissingClaim) { //optional claim
			return nil, err
		} //todo: do something with value

	}

	jku, err := jsonutils.RetrieveClaim(header, "jku", jsonutils.ValidateHttpsUrlClaim)
	if err != nil && !errors.Is(err, joseerror.ErrMissingClaim) { //optional claim
		return nil, err
	}

	includedJwk, err := jsonutils.RetrieveClaim[map[string]any](header, "jwk")
	if err != nil && !errors.Is(err, joseerror.ErrMissingClaim) { //optional claim
		return nil, err
	}

	kid, err := jsonutils.RetrieveClaim[string](header, "kid")
	if err != nil && !errors.Is(err, joseerror.ErrMissingClaim) { //optional claim
		return nil, err
	}

	x5u, err := jsonutils.RetrieveClaim(header, "x5u", jsonutils.ValidateHttpsUrlClaim)
	if err != nil && !errors.Is(err, joseerror.ErrMissingClaim) { //optional claim
		return nil, err
	}

	var x5c *[]string
	if rawX5c, present := header["x5c"]; present { //optional claim
		chain, err := x5.CertificateChainStrings(rawX5c)
		if err != nil {
			return nil, err
		}
		if err := x5.ValidateCertificateChain(header, chain); err != nil {
			return nil, err
		}
		x5c = &chain
	}

	x5t, err := jsonutils.RetrieveClaim(header, "x5t", jsonutils.ValidateBase64Url)
	if err != nil && !errors.Is(err, joseerror.ErrMissingClaim) { //optional claim
		return nil, err
	}

	x5ts256, err := jsonutils.RetrieveClaim(header, "x5t#S256", jsonutils.ValidateBase64Url)
	if err != nil && !errors.Is(err, joseerror.ErrMissingClaim) { //optional claim
		return nil, err
	}

	// typ isn't processed as jws applications are instructed to ignore
	// cty isn't processed as jws applications are instructed to ignore

	if b64, present := header["b64"]; present && b64 == false {
		return nil, fmt.Errorf("%wthe 'b64' header is false, and this library always base64url-decodes the payload", joseerror.ErrMissingCriticalClaim)
	}

	critValidators := []jsonutils.Validator[[]any]{jsonutils.ValidateNonEmptySlice, jsonutils.ValidateNoDuplicateSliceValues, jsonutils.ValidateNoBannedCriticalValues, jsonutils.ValidateCriticalValuesPresent, jsonutils.UnderstoodCriticalValues(opts.UnderstoodCriticalHeaders)}
	if mode == model.JWE {
		critValidators = append(critValidators, jsonutils.ValidateNoBannedCriticalJWEValues)
	}

	_, err = jsonutils.RetrieveClaim[[]any](header, "crit", critValidators...)
	if err != nil && !errors.Is(err, joseerror.ErrMissingClaim) { //optional claim
		return nil, err
	}

	var jwkRetrievers []model.Retriever
	if includedJwk != nil && opts.UseTokenProvidedKeys { // prefer an in-line jwk
		jwkRetrievers = append(jwkRetrievers, jwk.InlineJWK(*includedJwk, kid, *alg, opts.IgnoreKeyUse))
	}
	if x5c != nil && opts.X509Roots != nil { // then try an in-line certificate, if a trust anchor is configured for it
		jwkRetrievers = append(jwkRetrievers, x5.InlineCertificate(*x5c, x5t, x5ts256, opts.X509Roots, opts.X509ExtKeyUsages))
	}
	if jku != nil && opts.UseTokenProvidedKeys && client != nil { // check for specified keystore
		jwkRetrievers = append(jwkRetrievers, jwk.RetrieveJKU(*jku, httputils.Fetcher(ctx, client, opts.FetchTimeout), kid, *alg, opts.IgnoreKeyUse))
	}
	if x5u != nil && opts.X509Roots != nil && client != nil { // check for specified remote certificate chain, if a trust anchor is configured for it
		jwkRetrievers = append(jwkRetrievers, x5.RetrieveX5U(*x5u, httputils.Fetcher(ctx, client, opts.FetchTimeout), x5t, x5ts256, opts.X509Roots, opts.X509ExtKeyUsages))
	}

	return jwkRetrievers, nil
}

func validateExpectedType(header map[string]any, accepted []string) error {
	if len(accepted) == 0 {
		return nil
	}

	raw, present := header["typ"]
	if !present {
		return fmt.Errorf("%wthe 'typ' header is required and names one of %v", joseerror.ErrMissingClaim, accepted)
	}
	typ, ok := raw.(string)
	if !ok {
		return fmt.Errorf("%wthe 'typ' header must be a string", joseerror.ErrMalformedClaim)
	}

	for _, candidate := range accepted {
		if mediaTypesMatch(typ, candidate) {
			return nil
		}
	}
	return fmt.Errorf("%wthe 'typ' header names %s, which is not one of %v", joseerror.ErrMalformedClaim, jsonutils.QuoteBounded(typ), accepted)
}

// NamesNestedJWT reports whether the header's cty is "JWT", which RFC 7519
// section 5.2 requires of a Nested JWT. The comparison follows RFC 7515 section
// 4.1.10: case-insensitive, with "application/" prepended to a value without a '/'.
// Media-type parameters (RFC 9110 section 8.3.1) are ignored.
func NamesNestedJWT(header map[string]any) bool {
	cty, _ := header["cty"].(string)
	if i := strings.IndexByte(cty, ';'); i >= 0 {
		cty = strings.TrimRight(cty[:i], " \t")
	}
	return mediaTypesMatch(cty, "JWT")
}

func mediaTypesMatch(declared, accepted string) bool {
	return strings.EqualFold(qualifyMediaType(declared), qualifyMediaType(accepted))
}

func qualifyMediaType(value string) string {
	if strings.Contains(value, "/") {
		return value
	}
	return "application/" + value
}

func validateKeyIdentifierRequirement(header map[string]any, required bool) error {
	if !required {
		return nil
	}

	raw, present := header["kid"]
	if !present {
		return fmt.Errorf("%wthe 'kid' header is required", joseerror.ErrMissingClaim)
	}
	kid, ok := raw.(string)
	if !ok || kid == "" {
		return fmt.Errorf("%wthe 'kid' header must be a non-empty string", joseerror.ErrMalformedClaim)
	}
	return nil
}
