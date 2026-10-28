package jwt

import (
	"bytes"
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/mldsa"
	"crypto/rand"
	"crypto/rsa"
	"encoding/asn1"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"github.com/MichaelFraser99/go-jose/internal/algorithms/common"
	"github.com/MichaelFraser99/go-jose/joseerror"
	"github.com/MichaelFraser99/go-jose/jwa"
	"github.com/MichaelFraser99/go-jose/jws"
	"github.com/MichaelFraser99/go-jose/model"
	"maps"
	"math/big"
	"strings"
)

type Opts struct {
	Algorithm jwa.Algorithm
}

//todo: jwe support

// New signs a JWS Compact Serialization from head and body, writing to neither.
//
// The "alg" header is the algorithm that signs, as RFC 7515 section 4.1.1 requires: a
// model.Signer's own Alg, otherwise opts.Algorithm or an "alg" the head names. A head
// or opts naming any other algorithm is refused with ErrUnsupportedAlgorithm. A nil
// head is an empty header and a nil body an empty claims set.
//
// A model.Signer is called in JOSE mode, with the whole JWS Signing Input.
//
// Any other crypto.Signer is called as Go's crypto.Signer contract defines. Its ASN.1
// DER ECDSA output becomes R||S (RFC 7518 section 3.4), each of R and S in [1, n-1]
// (FIPS 186-5 section 6.4.1). A PS algorithm requests RSASSA-PSS with a salt the size
// of the hash (RFC 7518 section 3.5). Its public key must suit the algorithm, and it
// cannot sign an HS algorithm.
func New(signer crypto.Signer, head, body map[string]any, opts Opts) (*string, error) {
	h := maps.Clone(head)
	if h == nil {
		h = map[string]any{}
	}
	if body == nil {
		body = map[string]any{}
	}
	alg, err := signingAlgorithm(signer, h, opts)
	if err != nil {
		return nil, err
	}
	h["alg"] = alg.String()
	return newJwt(signer, h, body, alg)
}

// Validate verifies a token's structure, signature and registered claims, returning its
// header and body.
//
// iss, sub and jti must be strings and aud a string or an array of strings (RFC 7519
// section 4.1), else ErrMalformedClaim. iat, nbf and exp must be numbers (RFC 7519
// section 2, NumericDate), compared with the current time at full precision and widened
// by ClockSkewLeeway. The current time must be before exp (RFC 7519 section 4.1.4), else
// ErrExpired, and at or after nbf (section 4.1.5), else ErrNotYetValid. An iat after the
// current time is also refused with ErrNotYetValid: RFC 7519 section 4.1.6 sets no such
// rule, but a token issued in the future signals a clock fault or a forged timestamp.
// When opts.ExpectedAudience is set, aud must name one of its values (section 4.1.3).
// Options whose ExpectedAudience holds an empty string are refused with
// ErrInvalidOptions, whatever the token.
func Validate(ctx context.Context, token string, outOfBoundsPublicKey model.Retriever, opts *model.JoseOptions) (head, body map[string]any, err error) {
	if err := validateOptions(opts); err != nil {
		return nil, nil, err
	}
	segments := strings.Split(token, ".")
	if len(segments) == 3 {
		head, body, err = jws.VerifyCompactSerialization(ctx, token, outOfBoundsPublicKey, opts)
		if err != nil {
			return nil, nil, fmt.Errorf("failed to verify jws compact serialization: %w", err)
		}
	} else if len(segments) == 5 {
		//todo jwe
		return nil, nil, fmt.Errorf("jwe not yet supported")
	} else {
		return nil, nil, fmt.Errorf("invalid token")
	}

	if err := validateClaims(body, opts); err != nil {
		return nil, nil, err
	}

	return head, body, nil
}

func signingAlgorithm(signer crypto.Signer, head map[string]any, opts Opts) (jwa.Algorithm, error) {
	alg := opts.Algorithm
	if s, ok := signer.(model.Signer); ok {
		if alg != jwa.Unknown && alg != s.Alg() {
			return jwa.Unknown, fmt.Errorf("%wopts names %s but the signer signs with %s", joseerror.ErrUnsupportedAlgorithm, alg, s.Alg())
		}
		alg = s.Alg()
	}
	if named, found := head["alg"]; found {
		name, _ := named.(string)
		if alg != jwa.Unknown && name != alg.String() {
			return jwa.Unknown, fmt.Errorf("%wthe 'alg' header names %#v but the token is signed with %s", joseerror.ErrUnsupportedAlgorithm, named, alg)
		}
		alg = jwa.GetAlgorithm(name)
	}
	if alg == jwa.EdDSA {
		return jwa.Unknown, fmt.Errorf("%wEdDSA is accepted only for verification: RFC 9864 section 4.1.2 deprecates it, so sign with Ed25519", joseerror.ErrUnsupportedAlgorithm)
	}
	if alg == jwa.Unknown {
		return jwa.Unknown, fmt.Errorf("%wno algorithm to sign with: name one in opts or in the 'alg' header", joseerror.ErrUnsupportedAlgorithm)
	}
	return alg, nil
}

func signingHash(alg jwa.Algorithm) crypto.Hash {
	switch alg {
	case jwa.RS256, jwa.PS256, jwa.ES256:
		return crypto.SHA256
	case jwa.RS384, jwa.PS384, jwa.ES384:
		return crypto.SHA384
	case jwa.RS512, jwa.PS512, jwa.ES512:
		return crypto.SHA512
	case jwa.HS256, jwa.HS384, jwa.HS512, jwa.EdDSA, jwa.Ed25519, jwa.MLDSA44, jwa.MLDSA65, jwa.MLDSA87, jwa.Unknown:
		return 0
	}
	return 0
}

func newJwt(signer crypto.Signer, head, body map[string]any, alg jwa.Algorithm) (*string, error) {
	if _, found := head["typ"]; !found {
		head["typ"] = "JWT"
	}

	headBytes, err := json.Marshal(head)
	if err != nil {
		return nil, err
	}
	bodyBytes, err := json.Marshal(body)
	if err != nil {
		return nil, err
	}
	b64Head := make([]byte, base64.RawURLEncoding.EncodedLen(len(headBytes)))
	b64Body := make([]byte, base64.RawURLEncoding.EncodedLen(len(bodyBytes)))
	base64.RawURLEncoding.Encode(b64Head, headBytes)
	base64.RawURLEncoding.Encode(b64Body, bodyBytes)

	signingInput := append(append(b64Head, '.'), b64Body...)
	var signatureBytes []byte
	if _, ok := signer.(model.Signer); ok {
		signatureBytes, err = signer.Sign(rand.Reader, signingInput, model.SignerOpts{})
	} else {
		signatureBytes, err = signWithCryptoSigner(signer, alg, signingInput)
	}
	if err != nil {
		return nil, err
	}
	b64Signature := make([]byte, base64.RawURLEncoding.EncodedLen(len(signatureBytes)))
	base64.RawURLEncoding.Encode(b64Signature, signatureBytes)

	finalJwt := fmt.Sprintf("%s.%s.%s", string(b64Head), string(b64Body), string(b64Signature))
	return &finalJwt, nil
}

func signWithCryptoSigner(signer crypto.Signer, alg jwa.Algorithm, signingInput []byte) ([]byte, error) {
	hash := signingHash(alg)
	digest := signingInput
	if hash != 0 {
		hasher := hash.New()
		hasher.Write(signingInput)
		digest = hasher.Sum(nil)
	}
	switch alg {
	case jwa.ES256, jwa.ES384, jwa.ES512:
		curves := map[jwa.Algorithm]string{jwa.ES256: "P-256", jwa.ES384: "P-384", jwa.ES512: "P-521"}
		public, ok := signer.Public().(*ecdsa.PublicKey)
		if !ok || public.Curve.Params().Name != curves[alg] {
			return nil, fmt.Errorf("%w%s needs an ecdsa key on %s", joseerror.ErrInvalidPrivateKey, alg, curves[alg])
		}
		der, err := signer.Sign(rand.Reader, digest, hash)
		if err != nil {
			return nil, err
		}
		return concatenatedRS(der, public.Params())
	case jwa.RS256, jwa.RS384, jwa.RS512, jwa.PS256, jwa.PS384, jwa.PS512:
		if _, ok := signer.Public().(*rsa.PublicKey); !ok {
			return nil, fmt.Errorf("%w%s needs an rsa key", joseerror.ErrInvalidPrivateKey, alg)
		}
		if alg == jwa.PS256 || alg == jwa.PS384 || alg == jwa.PS512 {
			return signer.Sign(rand.Reader, digest, &rsa.PSSOptions{SaltLength: rsa.PSSSaltLengthEqualsHash, Hash: hash})
		}
		return signer.Sign(rand.Reader, digest, hash)
	case jwa.Ed25519:
		if _, ok := signer.Public().(ed25519.PublicKey); !ok {
			return nil, fmt.Errorf("%w%s needs an ed25519 key", joseerror.ErrInvalidPrivateKey, alg)
		}
		return signer.Sign(rand.Reader, digest, crypto.Hash(0))
	case jwa.MLDSA44, jwa.MLDSA65, jwa.MLDSA87:
		public, ok := signer.Public().(*mldsa.PublicKey)
		params, _ := common.MLDSAParameters(alg.String())
		if _, err := common.UsableMLDSAPublicKey(public, params, joseerror.ErrInvalidPrivateKey); !ok || err != nil {
			return nil, fmt.Errorf("%w%s needs an %s key", joseerror.ErrInvalidPrivateKey, alg, alg)
		}
		return signer.Sign(rand.Reader, signingInput, crypto.Hash(0))
	case jwa.HS256, jwa.HS384, jwa.HS512, jwa.EdDSA, jwa.Unknown:
	}
	return nil, fmt.Errorf("%wonly a signer from this library can sign %s", joseerror.ErrInvalidPrivateKey, alg)
}

func concatenatedRS(der []byte, curve *elliptic.CurveParams) ([]byte, error) {
	var signature struct{ R, S *big.Int }
	if _, err := asn1.Unmarshal(der, &signature); err != nil || !isDER(signature, der) {
		return nil, fmt.Errorf("%wthe signer did not return an ASN.1 DER ECDSA signature", joseerror.ErrSigningError)
	}
	size := (curve.BitSize + 7) / 8
	concatenated := make([]byte, 2*size)
	for i, v := range []*big.Int{signature.R, signature.S} {
		if v.Sign() <= 0 || v.Cmp(curve.N) >= 0 {
			return nil, fmt.Errorf("%wthe signer returned an ECDSA signature value outside [1, n-1]", joseerror.ErrSigningError)
		}
		v.FillBytes(concatenated[i*size : (i+1)*size])
	}
	return concatenated, nil
}

func isDER(signature any, der []byte) bool {
	canonical, _ := asn1.Marshal(signature)
	return bytes.Equal(canonical, der)
}
