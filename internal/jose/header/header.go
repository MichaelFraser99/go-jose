package header

import (
	"context"
	"crypto"
	"fmt"
	"slices"
	"strings"

	"errors"
	"github.com/MichaelFraser99/go-jose/internal/algorithms/ecdhes"
	"github.com/MichaelFraser99/go-jose/internal/algorithms/gcmkw"
	"github.com/MichaelFraser99/go-jose/internal/algorithms/pbes2"
	"github.com/MichaelFraser99/go-jose/internal/httputils"
	"github.com/MichaelFraser99/go-jose/internal/jose/jsonutils"
	"github.com/MichaelFraser99/go-jose/internal/jose/jwk"
	"github.com/MichaelFraser99/go-jose/internal/jose/x5"
	"github.com/MichaelFraser99/go-jose/joseerror"
	"github.com/MichaelFraser99/go-jose/jwa"
	"github.com/MichaelFraser99/go-jose/model"
	"net/http"
)

// ValidateHeader performs standard JOSE header validation upon the decoded protected header portion of a JWS.
//
// On success, a series of Retriever functions are returned which will yield key(s) for validation purposes.
// A header that breaks RFC 7515 is refused with ErrMalformedToken wrapping the
// reason. A header that is well formed but names what this library does not
// implement, or what the options refuse, is refused with that reason alone.
func ValidateHeader(ctx context.Context, header map[string]any, client *http.Client, opts *model.JoseOptions) ([]model.Retriever, error) {
	if opts == nil {
		opts = &model.JoseOptions{}
	}
	//todo: we haven't allowed for the StringOrURI stipulation some keys have - go back through JWS and JWE and adjust as appropriate
	alg, err := jsonutils.RetrieveClaim[string](header, "alg")
	if err != nil {
		return nil, malformed(err)
	}
	params, err := readHeaderShape(header, jwsMode)
	if err != nil {
		return nil, malformed(err)
	}

	if err := refuseUnencodedPayload(header); err != nil {
		return nil, err
	}
	if jwa.GetAlgorithm(*alg) == jwa.Unknown {
		return nil, fmt.Errorf("%w%s is not a supported algorithm", joseerror.ErrUnsupportedAlgorithm, jsonutils.QuoteBounded(*alg))
	}
	if len(opts.AllowedSigningAlgorithms) > 0 && !slices.Contains(opts.AllowedSigningAlgorithms, jwa.GetAlgorithm(*alg)) {
		return nil, fmt.Errorf("%w%s is not permitted by application-level constraints", joseerror.ErrUnsupportedAlgorithm, jsonutils.QuoteBounded(*alg))
	}

	if err := ValidateExpectedType(header, opts.AcceptedTypes); err != nil {
		return nil, err
	}

	if err := validateKeyIdentifierRequirement(header, opts.RequireKeyIdentifier); err != nil {
		return nil, err
	}

	_, err = jsonutils.RetrieveClaim[[]any](header, "crit", jsonutils.UnderstoodCriticalValues(opts.UnderstoodCriticalHeaders))
	if err != nil && !errors.Is(err, joseerror.ErrMissingClaim) {
		return nil, err
	}

	var jwkRetrievers []model.Retriever
	if params.jwk != nil && opts.UseTokenProvidedKeys {
		jwkRetrievers = append(jwkRetrievers, carried(jwk.InlineJWK(*params.jwk, params.kid, *alg, opts.IgnoreKeyUse, opts.StrictKeyOperations)))
	}
	if params.x5c != nil && opts.X509Roots != nil {
		jwkRetrievers = append(jwkRetrievers, carried(x5.InlineCertificate(*params.x5c, params.x5t, params.x5ts256, opts.X509Roots, opts.X509ExtKeyUsages)))
	}
	if params.jku != nil && opts.UseTokenProvidedKeys && client != nil {
		jwkRetrievers = append(jwkRetrievers, jwk.RetrieveJKU(*params.jku, httputils.Fetcher(ctx, client, opts.FetchTimeout), params.kid, *alg, opts.IgnoreKeyUse, opts.StrictKeyOperations))
	}
	if params.x5u != nil && opts.X509Roots != nil && client != nil {
		jwkRetrievers = append(jwkRetrievers, x5.RetrieveX5U(*params.x5u, httputils.Fetcher(ctx, client, opts.FetchTimeout), params.x5t, params.x5ts256, opts.X509Roots, opts.X509ExtKeyUsages))
	}

	return jwkRetrievers, nil
}

func checkAlgorithmParameters(header map[string]any) error {
	if raw, present := header["zip"]; present {
		if _, ok := raw.(string); !ok {
			return fmt.Errorf("%wthe 'zip' header must be a string (RFC 7516 section 4.1.3)", joseerror.ErrMalformedClaim)
		}
	}
	alg, _ := header["alg"].(string)
	switch algorithm := jwa.GetAlgorithm(alg); {
	case slices.Contains(keyAgreementAlgorithms, algorithm):
		if err := checkEphemeralKey(header); err != nil {
			return err
		}
		_, _, err := ecdhes.PartyInfo(header)
		return err
	case slices.Contains(gcmKeyWrapAlgorithms, algorithm):
		_, _, err := gcmkw.Parameters(header)
		return err
	case slices.Contains(PasswordAlgorithms, algorithm):
		_, _, err := pbes2.Parameters(header)
		return err
	}
	return nil
}

func checkAlgorithmBounds(header map[string]any, alg jwa.Algorithm, opts *model.JWEOptions) error {
	if slices.Contains(PasswordAlgorithms, alg) {
		_, count, _ := pbes2.Parameters(header)
		if maximum := MaxPBES2Count(opts); count > maximum {
			return fmt.Errorf("%wthe 'p2c' header asks for more PBKDF2 iterations than the %d MaxPBES2Count allows", joseerror.ErrOutOfBounds, maximum)
		}
		if opts.RequireRecommendedPBES2Count && count < pbes2.RecommendedCount {
			return fmt.Errorf("%wthe 'p2c' header of %d is below the %d RFC 7518 section 4.8.1.2 recommends, and RequireRecommendedPBES2Count is set", joseerror.ErrOutOfBounds, count, pbes2.RecommendedCount)
		}
	}
	if raw, present := header["zip"]; present {
		if zip := raw.(string); zip != "DEF" {
			return fmt.Errorf("%wthe 'zip' header names %s, and this library implements only DEF", joseerror.ErrUnsupportedAlgorithm, jsonutils.QuoteBounded(zip))
		}
		if opts.MaxDecompressedSize <= 0 {
			return fmt.Errorf("%wthe 'zip' header asks for decompression, which MaxDecompressedSize turns on", joseerror.ErrUnsupportedAlgorithm)
		}
	}
	return nil
}

func checkEphemeralKey(header map[string]any) error {
	raw, present := header["epk"]
	if !present {
		return fmt.Errorf("%wthe 'epk' header is required for ECDH-ES (RFC 7518 section 4.6.1.1)", joseerror.ErrMissingClaim)
	}
	epk, ok := raw.(map[string]any)
	if !ok {
		return fmt.Errorf("%wthe 'epk' header must be a JSON object", joseerror.ErrMalformedClaim)
	}
	if _, err := ecdhes.EphemeralPublicKey(epk); err != nil {
		if errors.Is(err, joseerror.ErrUnsupportedAlgorithm) {
			return err
		}
		return fmt.Errorf("%wthe 'epk' header is not a valid public key: %w", joseerror.ErrMalformedClaim, err)
	}
	return nil
}

func malformed(err error) error {
	return fmt.Errorf("%werror validating header: %w", joseerror.ErrMalformedToken, err)
}

// KeyManagementAlgorithms are the JWE "alg" values this library implements.
var KeyManagementAlgorithms = []jwa.Algorithm{
	jwa.RSAOAEP, jwa.RSAOAEP256, jwa.RSAOAEP384, jwa.RSAOAEP512,
	jwa.A128KW, jwa.A192KW, jwa.A256KW,
	jwa.Dir,
	jwa.ECDHES, jwa.ECDHESA128KW, jwa.ECDHESA192KW, jwa.ECDHESA256KW,
	jwa.A128GCMKW, jwa.A192GCMKW, jwa.A256GCMKW,
	jwa.PBES2HS256A128KW, jwa.PBES2HS384A192KW, jwa.PBES2HS512A256KW,
}

var keyAgreementAlgorithms = []jwa.Algorithm{jwa.ECDHES, jwa.ECDHESA128KW, jwa.ECDHESA192KW, jwa.ECDHESA256KW}

var gcmKeyWrapAlgorithms = []jwa.Algorithm{jwa.A128GCMKW, jwa.A192GCMKW, jwa.A256GCMKW}

// PasswordAlgorithms are the PBES2 "alg" values (RFC 7518 section 4.8).
var PasswordAlgorithms = []jwa.Algorithm{jwa.PBES2HS256A128KW, jwa.PBES2HS384A192KW, jwa.PBES2HS512A256KW}

// DefaultMaxPBES2Count is the "p2c" bound when JWEOptions.MaxPBES2Count is
// unset: twice the 600,000 iterations draft-ietf-oauth-rfc8725bis section 3.13
// cites, as that section recommends.
const DefaultMaxPBES2Count = 1_200_000

// MaxPBES2Count returns the PBKDF2 iterations one JWE may cost: opts.MaxPBES2Count,
// or DefaultMaxPBES2Count when that is zero or less.
func MaxPBES2Count(opts *model.JWEOptions) int {
	if opts != nil && opts.MaxPBES2Count > 0 {
		return opts.MaxPBES2Count
	}
	return DefaultMaxPBES2Count
}

// ValidateJWEHeader checks a decoded JWE Protected Header, as RFC 7516 section
// 5.2 step 5 requires, and returns the alg and enc it names.
//
// "alg" must name an algorithm in KeyManagementAlgorithms and "enc" a content
// encryption algorithm this library implements (RFC 7516 sections 4.1.1 and
// 4.1.2), each within the caller's allow-list if one is set, else
// ErrUnsupportedAlgorithm. "zip" must be a string, else ErrMalformedToken. It
// must be "DEF", and JWEOptions.MaxDecompressedSize must be set, else
// ErrUnsupportedAlgorithm (section 4.1.3). The parameters RFC 7516 shares with RFC 7515 have the shapes
// CheckHeaderShape describes, except that "b64" (RFC 7797, JWS only) is not
// read, and "crit" may name no parameter RFC 7516 or RFC 7518 defines for JWE
// (RFC 7516 section 4.1.13). For an ECDH-ES alg, "epk" must be a key
// ecdhes.EphemeralPublicKey accepts, and "apu" and "apv" must be distinct
// base64url strings (RFC 7518 section 4.6); no other alg reads them. For an
// AES GCM key wrap alg, "iv" and "tag" must be base64url strings of 12 and 16
// octets (section 4.7.1). For a PBES2 alg, "p2s" must be a base64url string of
// at least 8 octets and "p2c" a positive integer (section 4.8.1), else
// ErrMalformedToken; a "p2c" above JWEOptions.MaxPBES2Count (1,200,000 when
// unset), or below 1000 with RequireRecommendedPBES2Count, is ErrOutOfBounds.
// AcceptedTypes, RequireKeyIdentifier and UnderstoodCriticalHeaders apply as
// they do to a JWS, except that "b64" in UnderstoodCriticalHeaders is ignored,
// as RFC 7797 defines it for JWS only.
func ValidateJWEHeader(header map[string]any, opts *model.JWEOptions) (jwa.Algorithm, jwa.Encryption, error) {
	if opts == nil {
		opts = &model.JWEOptions{}
	}
	algName, err := jsonutils.RetrieveClaim[string](header, "alg")
	if err != nil {
		return jwa.Unknown, jwa.UnknownEncryption, malformed(err)
	}
	encName, err := jsonutils.RetrieveClaim[string](header, "enc")
	if err != nil {
		return jwa.Unknown, jwa.UnknownEncryption, malformed(err)
	}
	if _, err := readHeaderShape(header, jweMode); err != nil {
		return jwa.Unknown, jwa.UnknownEncryption, malformed(err)
	}
	if err := checkAlgorithmParameters(header); err != nil {
		if errors.Is(err, joseerror.ErrUnsupportedAlgorithm) {
			return jwa.Unknown, jwa.UnknownEncryption, err
		}
		return jwa.Unknown, jwa.UnknownEncryption, malformed(err)
	}

	alg := jwa.GetAlgorithm(*algName)
	if !slices.Contains(KeyManagementAlgorithms, alg) {
		return jwa.Unknown, jwa.UnknownEncryption, fmt.Errorf("%w%s is not a key management algorithm this library implements", joseerror.ErrUnsupportedAlgorithm, jsonutils.QuoteBounded(*algName))
	}
	if len(opts.AllowedKeyManagementAlgorithms) > 0 && !slices.Contains(opts.AllowedKeyManagementAlgorithms, alg) {
		return jwa.Unknown, jwa.UnknownEncryption, fmt.Errorf("%w%s is not permitted by application-level constraints", joseerror.ErrUnsupportedAlgorithm, jsonutils.QuoteBounded(*algName))
	}

	enc := jwa.GetEncryption(*encName)
	if enc == jwa.UnknownEncryption {
		return jwa.Unknown, jwa.UnknownEncryption, fmt.Errorf("%w%s is not a content encryption algorithm this library implements", joseerror.ErrUnsupportedAlgorithm, jsonutils.QuoteBounded(*encName))
	}
	if len(opts.AllowedContentEncryptionAlgorithms) > 0 && !slices.Contains(opts.AllowedContentEncryptionAlgorithms, enc) {
		return jwa.Unknown, jwa.UnknownEncryption, fmt.Errorf("%w%s is not permitted by application-level constraints", joseerror.ErrUnsupportedAlgorithm, jsonutils.QuoteBounded(*encName))
	}

	if err := checkAlgorithmBounds(header, alg, opts); err != nil {
		return jwa.Unknown, jwa.UnknownEncryption, err
	}

	if err := ValidateExpectedType(header, opts.AcceptedTypes); err != nil {
		return jwa.Unknown, jwa.UnknownEncryption, err
	}
	if err := validateKeyIdentifierRequirement(header, opts.RequireKeyIdentifier); err != nil {
		return jwa.Unknown, jwa.UnknownEncryption, err
	}
	understood := slices.DeleteFunc(slices.Clone(opts.UnderstoodCriticalHeaders), func(name string) bool { return name == "b64" })
	_, err = jsonutils.RetrieveClaim[[]any](header, "crit", jsonutils.UnderstoodCriticalValues(understood))
	if err != nil && !errors.Is(err, joseerror.ErrMissingClaim) {
		return jwa.Unknown, jwa.UnknownEncryption, err
	}
	return alg, enc, nil
}

// CheckJWEHeaderShape checks the shape of a JWE Protected Header a producer is
// about to emit, as ValidateJWEHeader checks it on receipt, without its
// allow-lists or expectations.
func CheckJWEHeaderShape(header map[string]any) error {
	if _, err := readHeaderShape(header, jweMode); err != nil {
		return err
	}
	return checkAlgorithmParameters(header)
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
	if _, err := readHeaderShape(header, jwsMode); err != nil {
		return err
	}
	return refuseUnencodedPayload(header)
}

func refuseUnencodedPayload(header map[string]any) error {
	if encoded, ok := header["b64"].(bool); ok && !encoded {
		return fmt.Errorf("%wthe 'b64' header is false, and this library handles only a base64url-encoded payload", joseerror.ErrMissingCriticalClaim)
	}
	return nil
}

type mode int

const (
	jwsMode mode = iota
	jweMode
)

func readHeaderShape(header map[string]any, mode mode) (headerShape, error) {
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

	if b64, present := header["b64"]; present && mode == jwsMode {
		if _, ok := b64.(bool); !ok {
			return headerShape{}, fmt.Errorf("%wthe 'b64' header must be a JSON boolean", joseerror.ErrMalformedClaim)
		}
	}

	banned := jsonutils.ValidateNoBannedCriticalValues
	if mode == jweMode {
		banned = jsonutils.ValidateNoBannedCriticalJWEValues
	}
	_, err = jsonutils.RetrieveClaim[[]any](header, "crit", jsonutils.ValidateNonEmptySlice, jsonutils.ValidateNoDuplicateSliceValues, banned, jsonutils.ValidateCriticalValuesPresent)
	if err != nil && !errors.Is(err, joseerror.ErrMissingClaim) {
		return headerShape{}, err
	}

	return params, nil
}

// ValidateExpectedType refuses a header whose "typ" is not one of accepted, as
// RFC 7515 section 4.1.9 compares media types. With none accepted, "typ" is not
// checked. A missing "typ" is ErrMissingClaim, and any other refusal
// ErrMalformedClaim.
func ValidateExpectedType(header map[string]any, accepted []string) error {
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
// 4.1.10: case-insensitive for ASCII letters only (RFC 6838 section 4.2), with
// "application/" prepended to a value without a '/'. Media-type parameters (RFC
// 9110 section 8.3.1) are ignored.
func NamesNestedJWT(header map[string]any) bool {
	cty, _ := header["cty"].(string)
	return mediaTypesMatch(cty, "JWT")
}

func mediaTypesMatch(declared, accepted string) bool {
	declared = withoutParameters(declared)
	return declared != "" && equalFoldASCII(qualifyMediaType(declared), qualifyMediaType(withoutParameters(accepted)))
}

func equalFoldASCII(a, b string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range len(a) {
		if lowerASCII(a[i]) != lowerASCII(b[i]) {
			return false
		}
	}
	return true
}

func lowerASCII(c byte) byte {
	if 'A' <= c && c <= 'Z' {
		return c + 'a' - 'A'
	}
	return c
}

// CheckAcceptedTypes refuses, with ErrInvalidOptions, an AcceptedTypes entry
// that no "typ" can match: one that is not a media type name of RFC 6838
// section 4.2, as a subtype alone or as a type and subtype, before any
// parameters.
func CheckAcceptedTypes(accepted []string) error {
	for _, entry := range accepted {
		name := withoutParameters(entry)
		parts := strings.Split(name, "/")
		if len(parts) > 2 || !slices.ContainsFunc(parts, isRestrictedName) || slices.ContainsFunc(parts, func(part string) bool { return !isRestrictedName(part) }) {
			return fmt.Errorf("%wAcceptedTypes holds %s, which is not a media type name (RFC 6838 section 4.2), so no 'typ' can match it", joseerror.ErrInvalidOptions, jsonutils.QuoteBounded(entry))
		}
	}
	return nil
}

func isRestrictedName(name string) bool {
	if len(name) == 0 || len(name) > 127 || !isASCIIAlphanumeric(name[0]) {
		return false
	}
	for i := 1; i < len(name); i++ {
		if !isASCIIAlphanumeric(name[i]) && !strings.ContainsRune("!#$&-^_.+", rune(name[i])) {
			return false
		}
	}
	return true
}

func isASCIIAlphanumeric(c byte) bool {
	return 'a' <= c && c <= 'z' || 'A' <= c && c <= 'Z' || '0' <= c && c <= '9'
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
