package header

import (
	"context"
	"crypto"
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
		return nil, fmt.Errorf("%w%s is not permitted by application-level constraints", joseerror.ErrUnsupportedAlgorithm, jsonutils.QuoteBounded(*alg))
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

		_, err = jsonutils.RetrieveClaim[string](header, "zip") //todo: we can do a validator for zip options this implementation understands
		if err != nil && !errors.Is(err, joseerror.ErrMissingClaim) {
			return nil, err
		} //todo: do something with value

	}

	params, err := readHeaderShape(header)
	if err != nil {
		return nil, err
	}

	critValidators := []jsonutils.Validator[[]any]{jsonutils.UnderstoodCriticalValues(opts.UnderstoodCriticalHeaders)}
	if mode == model.JWE {
		critValidators = append(critValidators, jsonutils.ValidateNoBannedCriticalJWEValues)
	}

	_, err = jsonutils.RetrieveClaim[[]any](header, "crit", critValidators...)
	if err != nil && !errors.Is(err, joseerror.ErrMissingClaim) {
		return nil, err
	}

	var jwkRetrievers []model.Retriever
	if params.jwk != nil && opts.UseTokenProvidedKeys {
		jwkRetrievers = append(jwkRetrievers, carried(jwk.InlineJWK(*params.jwk, params.kid, *alg, opts.IgnoreKeyUse)))
	}
	if params.x5c != nil && opts.X509Roots != nil {
		jwkRetrievers = append(jwkRetrievers, carried(x5.InlineCertificate(*params.x5c, params.x5t, params.x5ts256, opts.X509Roots, opts.X509ExtKeyUsages)))
	}
	if params.jku != nil && opts.UseTokenProvidedKeys && client != nil {
		jwkRetrievers = append(jwkRetrievers, jwk.RetrieveJKU(*params.jku, httputils.Fetcher(ctx, client, opts.FetchTimeout), params.kid, *alg, opts.IgnoreKeyUse))
	}
	if params.x5u != nil && opts.X509Roots != nil && client != nil {
		jwkRetrievers = append(jwkRetrievers, x5.RetrieveX5U(*params.x5u, httputils.Fetcher(ctx, client, opts.FetchTimeout), params.x5t, params.x5ts256, opts.X509Roots, opts.X509ExtKeyUsages))
	}

	return jwkRetrievers, nil
}

type carriedSourceError struct {
	err error
}

func (c carriedSourceError) Error() string { return c.err.Error() }

func (c carriedSourceError) Unwrap() error { return c.err }

func carried(retriever model.Retriever) model.Retriever {
	return func() ([]crypto.PublicKey, error) {
		keys, err := retriever()
		if err != nil {
			return nil, carriedSourceError{err: err}
		}
		return keys, nil
	}
}

// FromCarriedSource reports whether err came from a key the token carries in its
// header, a jwk or an x5c, rather than one fetched from a jku or an x5u. Those
// bytes are in the signed header, so a fault in them is the same every time.
func FromCarriedSource(err error) bool {
	var c carriedSourceError
	return errors.As(err, &c)
}

type headerShape struct {
	jku, kid, x5u, x5t, x5ts256 *string
	jwk                         *map[string]any
	x5c                         *[]string
}

// CheckHeaderShape refuses a JWS header whose registered parameters break the
// type and format rules of RFC 7515 section 4.1 or RFC 7797 section 3. It reads
// no key and fetches nothing, so a producer can hold a header it emits to the
// rules ValidateHeader applies to one it receives.
//
// "jku" and "x5u" must be HTTPS URLs (sections 4.1.2 and 4.1.5), "jwk" an object
// (section 4.1.3), "kid", "typ" and "cty" strings (sections 4.1.4, 4.1.9 and
// 4.1.10), "x5c" a non-empty array of base64 DER certificates (section 4.1.6),
// and "x5t" and "x5t#S256" base64url (sections 4.1.7 and 4.1.8). "crit" must be
// a non-empty array of distinct names, each present in the header and none
// defined by RFC 7515 (section 4.1.11). Each fault is ErrMalformedClaim, except
// a "crit" name the header does not hold, which is ErrMissingCriticalClaim. "b64"
// must be a boolean, else ErrMalformedClaim, and a "b64" of false is refused with
// ErrMissingCriticalClaim, since this library handles only a base64url-encoded
// payload.
func CheckHeaderShape(header map[string]any) error {
	_, err := readHeaderShape(header)
	return err
}

func readHeaderShape(header map[string]any) (headerShape, error) {
	var params headerShape
	var err error

	params.jku, err = jsonutils.RetrieveClaim(header, "jku", jsonutils.ValidateHttpsUrlClaim)
	if err != nil && !errors.Is(err, joseerror.ErrMissingClaim) {
		return headerShape{}, err
	}

	params.jwk, err = jsonutils.RetrieveClaim[map[string]any](header, "jwk")
	if err != nil && !errors.Is(err, joseerror.ErrMissingClaim) {
		return headerShape{}, err
	}

	params.kid, err = jsonutils.RetrieveClaim[string](header, "kid")
	if err != nil && !errors.Is(err, joseerror.ErrMissingClaim) {
		return headerShape{}, err
	}

	params.x5u, err = jsonutils.RetrieveClaim(header, "x5u", jsonutils.ValidateHttpsUrlClaim)
	if err != nil && !errors.Is(err, joseerror.ErrMissingClaim) {
		return headerShape{}, err
	}

	if rawX5c, present := header["x5c"]; present {
		chain, err := x5.CertificateChainStrings(rawX5c)
		if err != nil {
			return headerShape{}, err
		}
		if err := x5.ValidateCertificateChain(header, chain); err != nil {
			return headerShape{}, err
		}
		params.x5c = &chain
	}

	params.x5t, err = jsonutils.RetrieveClaim(header, "x5t", jsonutils.ValidateBase64Url)
	if err != nil && !errors.Is(err, joseerror.ErrMissingClaim) {
		return headerShape{}, err
	}

	params.x5ts256, err = jsonutils.RetrieveClaim(header, "x5t#S256", jsonutils.ValidateBase64Url)
	if err != nil && !errors.Is(err, joseerror.ErrMissingClaim) {
		return headerShape{}, err
	}

	for _, name := range []string{"typ", "cty"} {
		if _, err := jsonutils.RetrieveClaim[string](header, name); err != nil && !errors.Is(err, joseerror.ErrMissingClaim) {
			return headerShape{}, err
		}
	}

	if b64, present := header["b64"]; present {
		encoded, ok := b64.(bool)
		if !ok {
			return headerShape{}, fmt.Errorf("%wthe 'b64' header must be a JSON boolean", joseerror.ErrMalformedClaim)
		}
		if !encoded {
			return headerShape{}, fmt.Errorf("%wthe 'b64' header is false, and this library handles only a base64url-encoded payload", joseerror.ErrMissingCriticalClaim)
		}
	}

	_, err = jsonutils.RetrieveClaim[[]any](header, "crit", jsonutils.ValidateNonEmptySlice, jsonutils.ValidateNoDuplicateSliceValues, jsonutils.ValidateNoBannedCriticalValues, jsonutils.ValidateCriticalValuesPresent)
	if err != nil && !errors.Is(err, joseerror.ErrMissingClaim) {
		return headerShape{}, err
	}

	return params, nil
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
	return mediaTypesMatch(cty, "JWT")
}

func mediaTypesMatch(declared, accepted string) bool {
	declared = withoutParameters(declared)
	return declared != "" && strings.EqualFold(qualifyMediaType(declared), qualifyMediaType(withoutParameters(accepted)))
}

func withoutParameters(mediaType string) string {
	if i := strings.IndexByte(mediaType, ';'); i >= 0 {
		return strings.TrimRight(mediaType[:i], " \t")
	}
	return mediaType
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
