package header

import (
	"errors"
	"github.com/MichaelFraser99/go-jose/internal/jose/jsonutils"
	"github.com/MichaelFraser99/go-jose/internal/jose/jwk"
	"github.com/MichaelFraser99/go-jose/internal/jose/x5"
	"github.com/MichaelFraser99/go-jose/joseerror"
	"github.com/MichaelFraser99/go-jose/model"
	"net/http"
)

// ValidateHeader performs standard JOSE header validation upon the decoded protected header portion of a given JOSE object.
//
// On success, a series of Retriever functions are returned which will yield key(s) for validation purposes.
// On failure, an error object is returned
func ValidateHeader(header map[string]any, client *http.Client, mode model.Mode) ([]model.Retriever, error) {
	//todo: as different considerations must be made between JWS/JWE (think how JWE needs to be aware of the zip parameter if included in the header for further processing, should we return an "additional info" struct?
	//todo: we haven't allowed for the StringOrURI stipulation some keys have - go back through JWS and JWE and adjust as appropriate
	alg, err := jsonutils.RetrieveClaim(header, "alg", jsonutils.ValidateAlg)
	if err != nil {
		return nil, err
	}

	if mode == model.JWE {
		_, err = jsonutils.RetrieveClaim(header, "enc", jsonutils.ValidateAlg)
		if err != nil {
			return nil, err
		} //todo: do something with value

		_, err = jsonutils.RetrieveClaim[string](header, "zip")    //todo: we can do a validator for zip options this implementation understands
		if err != nil && !errors.Is(err, joseerror.MissingClaim) { //optional claim
			return nil, err
		} //todo: do something with value

	}

	jku, err := jsonutils.RetrieveClaim(header, "jku", jsonutils.ValidateHttpsUrlClaim)
	if err != nil && !errors.Is(err, joseerror.MissingClaim) { //optional claim
		return nil, err
	}

	includedJwk, err := jsonutils.RetrieveClaim[map[string]any](header, "jwk")
	if err != nil && !errors.Is(err, joseerror.MissingClaim) { //optional claim
		return nil, err
	}

	kid, err := jsonutils.RetrieveClaim[string](header, "kid")
	if err != nil && !errors.Is(err, joseerror.MissingClaim) { //optional claim
		return nil, err
	}

	x5u, err := jsonutils.RetrieveClaim(header, "x5u", jsonutils.ValidateHttpsUrlClaim)
	if err != nil && !errors.Is(err, joseerror.MissingClaim) { //optional claim
		return nil, err
	}

	x5c, err := jsonutils.RetrieveClaim[[]string](header, "x5c", x5.ValidateCertificateChain)
	if err != nil && !errors.Is(err, joseerror.MissingClaim) { //optional claim
		return nil, err
	}

	x5t, err := jsonutils.RetrieveClaim(header, "x5t", jsonutils.ValidateBase64Url)
	if err != nil && !errors.Is(err, joseerror.MissingClaim) { //optional claim
		return nil, err
	}

	x5ts256, err := jsonutils.RetrieveClaim(header, "x5t#S256", jsonutils.ValidateBase64Url)
	if err != nil && !errors.Is(err, joseerror.MissingClaim) { //optional claim
		return nil, err
	}

	// typ isn't processed as jws applications are instructed to ignore
	// cty isn't processed as jws applications are instructed to ignore

	critValidators := []jsonutils.Validator[[]any]{jsonutils.ValidateNonEmptySlice, jsonutils.ValidateNoDuplicateSliceValues, jsonutils.ValidateNoBannedCriticalValues, jsonutils.ValidateCriticalValuesPresent}
	if mode == model.JWE {
		critValidators = append(critValidators, jsonutils.ValidateNoBannedCriticalJWEValues)
	}

	_, err = jsonutils.RetrieveClaim[[]any](header, "crit", critValidators...)
	if err != nil && !errors.Is(err, joseerror.MissingClaim) { //optional claim
		return nil, err
	}

	var jwkRetrievers []model.Retriever
	if includedJwk != nil { // prefer an in-line jwk
		jwkRetrievers = append(jwkRetrievers, jwk.InlineJWK(*includedJwk, kid, *alg))
	}
	if x5c != nil { // then try an in-line certificate
		jwkRetrievers = append(jwkRetrievers, x5.InlineCertificate(*x5c, x5t, x5ts256, *alg))
	}
	if jku != nil { // check for specified keystore
		jwkRetrievers = append(jwkRetrievers, jwk.RetrieveJKU(*jku, client, kid, *alg))
	}
	if x5u != nil { // check for specified remote certificate chain
		jwkRetrievers = append(jwkRetrievers, x5.RetrieveX5U(*x5u, client, x5t, x5ts256, *alg))
	}

	return jwkRetrievers, nil
}
