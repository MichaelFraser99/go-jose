package common

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"github.com/MichaelFraser99/go-jose/internal/jose/jsonutils"
	jose_errors "github.com/MichaelFraser99/go-jose/joseerror"
	"github.com/MichaelFraser99/go-jose/model"
	"io"
	"math/big"
)

type SecretKey []byte

func (s *SecretKey) Equal(x crypto.PublicKey) bool {
	secretKey, ok := x.(*SecretKey)
	if !ok {
		return false
	}

	return bytes.Equal(*s, *secretKey)
}

func ECDSAPrivateKeyFromJwk(jwk map[string]any) (*ecdsa.PrivateKey, error) {
	curve, err := extractECDSACurveFromJwk(jwk)
	if err != nil {
		return nil, fmt.Errorf("error extracting curve from ECDSA jwk: %w", err)
	}

	x, y, d, err := extractECDSACoordinatesFromJwk(jwk)
	if err != nil {
		return nil, fmt.Errorf("error extacting x and y co-ordinates from ECDSA jwk: %w", err)
	}

	return &ecdsa.PrivateKey{
		PublicKey: ecdsa.PublicKey{
			Curve: curve,
			X:     x,
			Y:     y,
		},
		D: d,
	}, nil
}

func ECDSAPublicKeyFromJwk(jwk map[string]any) (*ecdsa.PublicKey, error) {
	curve, err := extractECDSACurveFromJwk(jwk)
	if err != nil {
		return nil, fmt.Errorf("error extracting curve from ECDSA jwk: %w", err)
	}

	x, y, _, err := extractECDSACoordinatesFromJwk(jwk)
	if err != nil {
		return nil, fmt.Errorf("error extacting x and y co-ordinates from ECDSA jwk: %w", err)
	}
	publicKey := &ecdsa.PublicKey{
		Curve: curve,
		X:     x,
		Y:     y,
	}
	return publicKey, nil
}

func extractECDSACurveFromJwk(jwk map[string]any) (elliptic.Curve, error) {
	curveName := jwk["crv"].(string)
	var curve elliptic.Curve
	switch curveName {
	case "P-256":
		curve = elliptic.P256()
	case "P-384":
		curve = elliptic.P384()
	case "P-521":
		curve = elliptic.P521()
	default:
		return nil, fmt.Errorf("unsupported elliptic curve: %s", curveName)
	}

	return curve, nil
}

// extractECDSACoordinatesFromJwk attempts to extract the x and y coordinates from an ECDSA JWK
//
// returns x, y, and d (if present) in that order as *big.Int
func extractECDSACoordinatesFromJwk(jwk map[string]any) (*big.Int, *big.Int, *big.Int, error) {
	xBytes, err := jsonutils.ExtractAndDecodeBase64urlString(jwk, "x")
	if err != nil {
		return nil, nil, nil, fmt.Errorf("error extracting 'x' coordinate from jwk: %w", err)
	}

	yBytes, err := jsonutils.ExtractAndDecodeBase64urlString(jwk, "y")
	if err != nil {
		return nil, nil, nil, fmt.Errorf("error extracting 'y' coordinate from jwk: %w", err)
	}

	dBytes, err := jsonutils.ExtractAndDecodeBase64urlString(jwk, "d")
	if err != nil && !errors.Is(err, jose_errors.MissingClaim) { //won't be present on public key material
		return nil, nil, nil, fmt.Errorf("error extracting 'd' coordinate from jwk: %w", err)
	}

	if dBytes == nil {
		return new(big.Int).SetBytes(xBytes), new(big.Int).SetBytes(yBytes), nil, nil
	} else {
		return new(big.Int).SetBytes(xBytes), new(big.Int).SetBytes(yBytes), new(big.Int).SetBytes(dBytes), nil
	}
}

func JwkFromECDSAPublicKey(publicKey *ecdsa.PublicKey) map[string]any {
	jwk := map[string]any{}

	curveBits := publicKey.Curve.Params().BitSize
	curveBytes := curveBits / 8
	if curveBits%8 > 0 {
		curveBytes++
	}

	xBytes := publicKey.X.Bytes()
	yBytes := publicKey.Y.Bytes()

	if len(xBytes) < curveBytes {
		padding := make([]byte, curveBytes-len(xBytes))
		xBytes = append(padding, xBytes...)
	}
	if len(yBytes) < curveBytes {
		padding := make([]byte, curveBytes-len(yBytes))
		yBytes = append(padding, yBytes...)
	}

	b64X := make([]byte, base64.RawURLEncoding.EncodedLen(len(xBytes)))
	base64.RawURLEncoding.Encode(b64X, xBytes)

	b64Y := make([]byte, base64.RawURLEncoding.EncodedLen(len(yBytes)))
	base64.RawURLEncoding.Encode(b64Y, yBytes)

	h := sha256.New()
	h.Write(append(b64X, b64Y...))
	jwk["x"] = string(b64X)
	jwk["y"] = string(b64Y)
	jwk["kty"] = "EC"
	jwk["crv"] = publicKey.Curve.Params().Name
	jwk["kid"] = base64.RawURLEncoding.EncodeToString(h.Sum(nil))
	return jwk
}

func JwkFromECDSAPrivateKey(privateKey *ecdsa.PrivateKey) map[string]any {
	jwk := map[string]any{}

	curveBits := privateKey.Curve.Params().BitSize
	curveBytes := curveBits / 8
	if curveBits%8 > 0 {
		curveBytes++
	}

	xBytes := privateKey.X.Bytes()
	yBytes := privateKey.Y.Bytes()
	dBytes := privateKey.D.Bytes()

	if len(xBytes) < curveBytes {
		padding := make([]byte, curveBytes-len(xBytes))
		xBytes = append(padding, xBytes...)
	}
	if len(yBytes) < curveBytes {
		padding := make([]byte, curveBytes-len(yBytes))
		yBytes = append(padding, yBytes...)
	}

	b64X := make([]byte, base64.RawURLEncoding.EncodedLen(len(xBytes)))
	base64.RawURLEncoding.Encode(b64X, xBytes)

	b64Y := make([]byte, base64.RawURLEncoding.EncodedLen(len(yBytes)))
	base64.RawURLEncoding.Encode(b64Y, yBytes)

	b64D := make([]byte, base64.RawURLEncoding.EncodedLen(len(dBytes)))
	base64.RawURLEncoding.Encode(b64D, dBytes)

	h := sha256.New()
	h.Write(append(b64X, b64Y...))
	jwk["x"] = string(b64X)
	jwk["y"] = string(b64Y)
	jwk["d"] = string(b64D)
	jwk["kty"] = "EC"
	jwk["crv"] = privateKey.Curve.Params().Name
	jwk["kid"] = base64.RawURLEncoding.EncodeToString(h.Sum(nil))
	return jwk
}

//todo: pull out kid calculation from these methods and break out into a different function
// this can be completely algorithm agnostic and doesn't impose a particular method of calculating
// the kid on the consumer

func JwkFromEdDSAPublicKey(publicKey *ed25519.PublicKey) map[string]any {
	jwk := map[string]any{}

	b64X := make([]byte, base64.RawURLEncoding.EncodedLen(ed25519.PublicKeySize))
	base64.RawURLEncoding.Encode(b64X, *publicKey)

	h := sha256.New()
	h.Write(b64X)
	jwk["x"] = string(b64X)
	jwk["kty"] = "OKP"
	jwk["crv"] = "Ed25519" //Ed448 not supported - prevailing opinion amongst the crypto peeps is there is no point
	return jwk
}

func JwkFromEdDSAPrivateKey(privateKey *ed25519.PrivateKey) map[string]any {
	jwk := map[string]any{}

	b64X := make([]byte, base64.RawURLEncoding.EncodedLen(ed25519.PublicKeySize))
	base64.RawURLEncoding.Encode(b64X, (*privateKey)[ed25519.PublicKeySize:])

	b64D := make([]byte, base64.RawURLEncoding.EncodedLen(ed25519.PrivateKeySize-ed25519.PublicKeySize))
	base64.RawURLEncoding.Encode(b64D, (*privateKey)[:ed25519.PublicKeySize])

	jwk["x"] = string(b64X)
	jwk["d"] = string(b64D)
	jwk["kty"] = "OKP"
	jwk["crv"] = "Ed25519" //Ed448 not supported - prevailing opinion amongst the crypto peeps is there is no point
	return jwk
}

func EdDSAPublicKeyFromJwk(jwk map[string]any) (*ed25519.PublicKey, error) {
	xBytes, err := jsonutils.ExtractAndDecodeBase64urlString(jwk, "x")
	if err != nil {
		return nil, fmt.Errorf("error extracting 'x' parameter from jwk: %w", err)
	}

	if _, present := jwk["crv"]; !present { //don't care the value at this stage - the spec is extensible and the curve depends on use
		return nil, fmt.Errorf("no 'crv' claim present in jwk")
	}

	return model.Pointer(ed25519.PublicKey(xBytes)), nil
}

func EdDSAPrivateKeyFromJwk(jwk map[string]any) (*ed25519.PrivateKey, error) {
	xBytes, err := jsonutils.ExtractAndDecodeBase64urlString(jwk, "x")
	if err != nil {
		return nil, fmt.Errorf("error extracting 'x' parameter from jwk: %w", err)
	}

	dBytes, err := jsonutils.ExtractAndDecodeBase64urlString(jwk, "d")
	if err != nil {
		return nil, fmt.Errorf("error extracting 'd' parameter from jwk: %w", err)
	}

	if _, present := jwk["crv"]; !present { //don't care the value at this stage - the spec is extensible and the curve depends on use
		return nil, fmt.Errorf("no 'crv' claim present in jwk")
	}

	return model.Pointer(ed25519.PrivateKey(append(dBytes, xBytes...))), nil
}

func RSAPrivateKeyFromJwk(jwk map[string]any) (*rsa.PrivateKey, error) {
	publicKey, err := RSAPublicKeyFromJwk(jwk)
	if err != nil {
		return nil, fmt.Errorf("error extracting public portion of RSA jwk: %w", err)
	}

	dBytes, err := jsonutils.ExtractAndDecodeBase64urlString(jwk, "d")
	if err != nil {
		return nil, fmt.Errorf("error extracting 'd' parameter from jwk: %w", err)
	}

	pBytes, err := jsonutils.ExtractAndDecodeBase64urlString(jwk, "p")
	if err != nil && !errors.Is(err, jose_errors.MissingClaim) {
		return nil, fmt.Errorf("error extracting 'p' parameter from jwk: %w", err)
	}

	qBytes, err := jsonutils.ExtractAndDecodeBase64urlString(jwk, "q")
	if err != nil && !errors.Is(err, jose_errors.MissingClaim) {
		return nil, fmt.Errorf("error extracting 'q' parameter from jwk: %w", err)
	}

	pPresent := jsonutils.KeyPresent(jwk, "p") //if one additional value is present, they all must be
	for _, v := range []string{"q", "dp", "dq", "qi"} {
		present := jsonutils.KeyPresent(jwk, v)
		if present != pPresent {
			return nil, fmt.Errorf("%wmalformed RSA jwk - refer to text in section 6.3.2 of RFC 7518 for explanation", jose_errors.InvalidPrivateKey)
		}
	}

	privateKey := rsa.PrivateKey{
		PublicKey: *publicKey,
		D:         new(big.Int).SetBytes(dBytes),
	}
	if pBytes != nil && qBytes != nil {
		privateKey.Primes = []*big.Int{new(big.Int).SetBytes(pBytes), new(big.Int).SetBytes(qBytes)}
	}
	privateKey.Precompute()

	return &privateKey, nil
}

func RSAPublicKeyFromJwk(jwk map[string]any) (*rsa.PublicKey, error) {
	nBytes, err := jsonutils.ExtractAndDecodeBase64urlString(jwk, "n")
	if err != nil {
		return nil, fmt.Errorf("error extracting 'n' parameter from jwk: %w", err)
	}

	eBytes, err := jsonutils.ExtractAndDecodeBase64urlString(jwk, "e")
	if err != nil {
		return nil, fmt.Errorf("error extracting 'e' parameter from jwk: %w", err)
	}

	return &rsa.PublicKey{
		N: new(big.Int).SetBytes(nBytes),
		E: int(new(big.Int).SetBytes(eBytes).Int64()),
	}, nil
}

func JwkFromRSAPublicKey(publicKey *rsa.PublicKey) map[string]any {
	jwk := map[string]any{}

	nBytes := publicKey.N.Bytes()
	eBytes := big.NewInt(int64(publicKey.E)).Bytes()

	b64N := make([]byte, base64.RawURLEncoding.EncodedLen(len(nBytes)))
	base64.RawURLEncoding.Encode(b64N, nBytes)

	b64E := make([]byte, base64.RawURLEncoding.EncodedLen(len(eBytes)))
	base64.RawURLEncoding.Encode(b64E, eBytes)

	h := sha256.New()
	h.Write(append(b64N, b64E...))
	jwk["n"] = string(b64N)
	jwk["e"] = string(b64E)
	jwk["kty"] = "RSA"
	jwk["kid"] = base64.RawURLEncoding.EncodeToString(h.Sum(nil))
	return jwk
}

func JwkFromRSAPrivateKey(privateKey *rsa.PrivateKey) map[string]any {
	jwk := map[string]any{}

	nBytes := privateKey.N.Bytes()
	eBytes := big.NewInt(int64(privateKey.E)).Bytes()
	dBytes := privateKey.D.Bytes()
	dpBytes := privateKey.Precomputed.Dp.Bytes()
	dqBytes := privateKey.Precomputed.Dq.Bytes()
	qiBytes := privateKey.Precomputed.Qinv.Bytes()

	b64N := make([]byte, base64.RawURLEncoding.EncodedLen(len(nBytes)))
	base64.RawURLEncoding.Encode(b64N, nBytes)

	b64E := make([]byte, base64.RawURLEncoding.EncodedLen(len(eBytes)))
	base64.RawURLEncoding.Encode(b64E, eBytes)

	b64D := make([]byte, base64.RawURLEncoding.EncodedLen(len(dBytes)))
	base64.RawURLEncoding.Encode(b64D, dBytes)

	b64Dp := make([]byte, base64.RawURLEncoding.EncodedLen(len(dpBytes)))
	base64.RawURLEncoding.Encode(b64Dp, dpBytes)

	b64Dq := make([]byte, base64.RawURLEncoding.EncodedLen(len(dqBytes)))
	base64.RawURLEncoding.Encode(b64Dq, dqBytes)

	b64Qi := make([]byte, base64.RawURLEncoding.EncodedLen(len(qiBytes)))
	base64.RawURLEncoding.Encode(b64Qi, qiBytes)

	//retrieve primes
	b64Primes := make([][]byte, len(privateKey.Primes))
	for i, b := range privateKey.Primes {
		b64Primes[i] = make([]byte, base64.RawURLEncoding.EncodedLen(len(b.Bytes())))
		base64.RawURLEncoding.Encode(b64Primes[i], b.Bytes())
	}

	// This is deprecated but until the spec formally eliminates them, this must stay
	// nolint:staticcheck
	if len(privateKey.Precomputed.CRTValues) > 0 {
		var oth []map[string]string
		// nolint:staticcheck
		for _, prime := range privateKey.Precomputed.CRTValues {
			rBytes := prime.R.Bytes()
			expBytes := prime.Exp.Bytes()
			coeffBytes := prime.Coeff.Bytes()

			b64r := make([]byte, base64.RawURLEncoding.EncodedLen(len(rBytes)))
			base64.RawURLEncoding.Encode(b64r, rBytes)

			b64exp := make([]byte, base64.RawURLEncoding.EncodedLen(len(expBytes)))
			base64.RawURLEncoding.Encode(b64exp, expBytes)

			b64coeff := make([]byte, base64.RawURLEncoding.EncodedLen(len(coeffBytes)))
			base64.RawURLEncoding.Encode(b64coeff, coeffBytes)

			oth = append(oth, map[string]string{
				"r": string(rBytes),
				"d": string(b64exp),
				"t": string(b64coeff),
			})
		}
		jwk["oth"] = oth
	}
	h := sha256.New()
	h.Write(append(b64N, b64E...))
	jwk["n"] = string(b64N)
	jwk["e"] = string(b64E)
	jwk["d"] = string(b64D)
	jwk["dp"] = string(b64Dp)
	jwk["dq"] = string(b64Dq)
	jwk["qi"] = string(b64Qi)
	jwk["p"] = string(b64Primes[0])
	jwk["q"] = string(b64Primes[1])
	jwk["kty"] = "RSA"
	jwk["kid"] = base64.RawURLEncoding.EncodeToString(h.Sum(nil))
	return jwk
}

func ExtractRSFromSignature(signature []byte, keySize int) (*big.Int, *big.Int, error) {
	if len(signature) != keySize {
		return nil, nil, fmt.Errorf("%wsignature should be %d bytes for given algorithm", jose_errors.InvalidSignature, keySize)
	}
	rb := signature[:keySize/2]
	sb := signature[keySize/2:]

	r := big.NewInt(0).SetBytes(rb)
	s := big.NewInt(0).SetBytes(sb)

	return r, s, nil
}

func EllipticCurveSign(rand io.Reader, pk ecdsa.PrivateKey, digest []byte, keySize int) ([]byte, error) {
	r, s, err := ecdsa.Sign(rand, &pk, digest)
	if err != nil {
		return nil, fmt.Errorf("%wfailed to sign token: %s", jose_errors.SigningError, err.Error())
	}

	sigBytes := make([]byte, keySize)

	r.FillBytes(sigBytes[0 : keySize/2])
	s.FillBytes(sigBytes[keySize/2:])

	return sigBytes, nil
}

func RsaPkcs1Sign(rand io.Reader, pk rsa.PrivateKey, digest []byte, hash crypto.Hash) ([]byte, error) {
	s, err := rsa.SignPKCS1v15(rand, &pk, hash, digest)
	if err != nil {
		return nil, fmt.Errorf("%wfailed to sign token: %s", jose_errors.SigningError, err.Error())
	}
	return s, nil
}

func RsaPSSSign(rand io.Reader, pk rsa.PrivateKey, digest []byte, hash crypto.Hash, saltLength int) ([]byte, error) {
	opts := &rsa.PSSOptions{
		SaltLength: saltLength,
		Hash:       hash,
	}
	s, err := rsa.SignPSS(rand, &pk, hash, digest, opts)
	if err != nil {
		return nil, fmt.Errorf("%wfailed to sign token: %s", jose_errors.SigningError, err.Error())
	}
	return s, nil
}
