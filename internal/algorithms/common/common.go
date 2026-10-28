package common

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"github.com/MichaelFraser99/go-jose/internal/jose/jsonutils"
	jose_errors "github.com/MichaelFraser99/go-jose/joseerror"
	"github.com/MichaelFraser99/go-jose/model"
	"hash"
	"io"
	"math/big"
)

type SecretKey []byte

// Equal reports, in constant time, whether x holds the same bytes. x may be a
// SecretKey or a *SecretKey.
//
// It answers on the bytes, not on what HMAC treats as one key: HMAC pads a key
// shorter than its block size and hashes a longer one, so two distinct byte
// strings can key identically.
func (s SecretKey) Equal(x crypto.PublicKey) bool {
	switch other := x.(type) {
	case SecretKey:
		return subtle.ConstantTimeCompare(s, other) == 1
	case *SecretKey:
		if other == nil {
			return false
		}
		return subtle.ConstantTimeCompare(s, *other) == 1
	default:
		return false
	}
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
	curveName, ok := jwk["crv"].(string)
	if !ok {
		return nil, fmt.Errorf("%wthe 'crv' claim must be a string naming a registered curve", jose_errors.ErrInvalidPublicKey)
	}
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
	if err != nil && !errors.Is(err, jose_errors.ErrMissingClaim) { //won't be present on public key material
		return nil, nil, nil, fmt.Errorf("error extracting 'd' coordinate from jwk: %w", err)
	}

	if dBytes == nil {
		return new(big.Int).SetBytes(xBytes), new(big.Int).SetBytes(yBytes), nil, nil
	} else {
		return new(big.Int).SetBytes(xBytes), new(big.Int).SetBytes(yBytes), new(big.Int).SetBytes(dBytes), nil
	}
}

// JwkFromECDSAPublicKey builds the jwk of an ECDSA public key.
//
// RFC 7518 sections 6.2.1.2 and 6.2.1.3 fix "x" and "y" at the full coordinate
// size of the curve, so a point that is not on its curve is refused rather than
// encoded.
func JwkFromECDSAPublicKey(publicKey *ecdsa.PublicKey) (map[string]any, error) {
	if err := checkECDSAPublicKey(publicKey, jose_errors.ErrInvalidPublicKey, jwkCurves); err != nil {
		return nil, err
	}
	jwk := map[string]any{}

	coordinateBytes := (publicKey.Curve.Params().BitSize + 7) / 8
	b64X := []byte(base64.RawURLEncoding.EncodeToString(publicKey.X.FillBytes(make([]byte, coordinateBytes))))
	b64Y := []byte(base64.RawURLEncoding.EncodeToString(publicKey.Y.FillBytes(make([]byte, coordinateBytes))))

	h := sha256.New()
	h.Write(append(b64X, b64Y...))
	jwk["x"] = string(b64X)
	jwk["y"] = string(b64Y)
	jwk["kty"] = "EC"
	jwk["crv"] = publicKey.Curve.Params().Name
	jwk["kid"] = base64.RawURLEncoding.EncodeToString(h.Sum(nil))
	return jwk, nil
}

const jwkCurves = "the curve of an EC jwk is one of P-256, P-384 and P-521"

func checkECDSAPublicKey(publicKey *ecdsa.PublicKey, class error, unsupportedCurve string) error {
	if publicKey == nil || publicKey.Curve == nil || publicKey.X == nil || publicKey.Y == nil {
		return fmt.Errorf("%wan ECDSA key needs a curve and a point", class)
	}
	switch publicKey.Curve {
	case elliptic.P256(), elliptic.P384(), elliptic.P521():
	default:
		return fmt.Errorf("%w%s", class, unsupportedCurve)
	}
	if _, err := publicKey.ECDH(); err != nil {
		return fmt.Errorf("%wthe point of an ECDSA key is not on its curve: %w", class, err)
	}
	return nil
}

// JwkFromECDSAPrivateKey builds the jwk of an ECDSA private key.
//
// RFC 7518 section 6.2.2.1 fixes "d" at the length of the curve order n, so a
// d outside [1, n-1] is refused rather than encoded.
func JwkFromECDSAPrivateKey(privateKey *ecdsa.PrivateKey) (map[string]any, error) {
	if privateKey == nil {
		return nil, fmt.Errorf("%wan ECDSA key needs a curve and a point", jose_errors.ErrInvalidPrivateKey)
	}
	if err := checkECDSAPublicKey(&privateKey.PublicKey, jose_errors.ErrInvalidPrivateKey, jwkCurves); err != nil {
		return nil, err
	}
	if privateKey.D == nil {
		return nil, fmt.Errorf("%wan ECDSA private key needs its scalar d", jose_errors.ErrInvalidPrivateKey)
	}
	if privateKey.D.Sign() <= 0 || privateKey.D.Cmp(privateKey.Params().N) >= 0 {
		return nil, fmt.Errorf("%wan ECDSA private key's scalar d is in [1, n-1]", jose_errors.ErrInvalidPrivateKey)
	}

	jwk, err := JwkFromECDSAPublicKey(&privateKey.PublicKey)
	if err != nil {
		return nil, err
	}
	scalarBytes := (privateKey.Params().N.BitLen() + 7) / 8
	jwk["d"] = base64.RawURLEncoding.EncodeToString(privateKey.D.FillBytes(make([]byte, scalarBytes)))
	return jwk, nil
}

//todo: pull out kid calculation from these methods and break out into a different function
// this can be completely algorithm agnostic and doesn't impose a particular method of calculating
// the kid on the consumer

// JwkFromEdDSAPublicKey builds the jwk of an Ed25519 public key.
//
// RFC 8032 section 5.1.5 makes an Ed25519 public key 32 octets, and RFC 8037
// section 2 carries it as "x", so a key of any other length is refused rather
// than encoded into a buffer sized for 32.
func JwkFromEdDSAPublicKey(publicKey *ed25519.PublicKey) (map[string]any, error) {
	if publicKey == nil {
		return nil, fmt.Errorf("%wan Ed25519 public key is %d bytes, got none", jose_errors.ErrInvalidPublicKey, ed25519.PublicKeySize)
	}
	if len(*publicKey) != ed25519.PublicKeySize {
		return nil, fmt.Errorf("%wan Ed25519 public key is %d bytes, got %d", jose_errors.ErrInvalidPublicKey, ed25519.PublicKeySize, len(*publicKey))
	}
	jwk := map[string]any{}

	b64X := make([]byte, base64.RawURLEncoding.EncodedLen(ed25519.PublicKeySize))
	base64.RawURLEncoding.Encode(b64X, *publicKey)

	h := sha256.New()
	h.Write(b64X)
	jwk["x"] = string(b64X)
	jwk["kty"] = "OKP"
	jwk["crv"] = "Ed25519" //Ed448 not supported - prevailing opinion amongst the crypto peeps is there is no point
	jwk["kid"] = base64.RawURLEncoding.EncodeToString(h.Sum(nil))
	return jwk, nil
}

// JwkFromEdDSAPrivateKey builds the jwk of an Ed25519 private key.
//
// RFC 8032 section 5.1.5 makes an Ed25519 private key 32 octets and its public
// key 32 octets. RFC 8037 section 2 carries them as "d" and "x", the two halves
// of an ed25519.PrivateKey.
func JwkFromEdDSAPrivateKey(privateKey *ed25519.PrivateKey) (map[string]any, error) {
	if privateKey == nil {
		return nil, fmt.Errorf("%wan Ed25519 private key is %d bytes, got none", jose_errors.ErrInvalidPrivateKey, ed25519.PrivateKeySize)
	}
	if len(*privateKey) != ed25519.PrivateKeySize {
		return nil, fmt.Errorf("%wan Ed25519 private key is %d bytes, got %d", jose_errors.ErrInvalidPrivateKey, ed25519.PrivateKeySize, len(*privateKey))
	}
	jwk := map[string]any{}

	b64X := make([]byte, base64.RawURLEncoding.EncodedLen(ed25519.PublicKeySize))
	base64.RawURLEncoding.Encode(b64X, (*privateKey)[ed25519.PublicKeySize:])

	b64D := make([]byte, base64.RawURLEncoding.EncodedLen(ed25519.PrivateKeySize-ed25519.PublicKeySize))
	base64.RawURLEncoding.Encode(b64D, (*privateKey)[:ed25519.PublicKeySize])

	h := sha256.New()
	h.Write(b64X)

	jwk["x"] = string(b64X)
	jwk["d"] = string(b64D)
	jwk["kty"] = "OKP"
	jwk["crv"] = "Ed25519" //Ed448 not supported - prevailing opinion amongst the crypto peeps is there is no point
	jwk["kid"] = base64.RawURLEncoding.EncodeToString(h.Sum(nil))
	return jwk, nil
}

func requireEd25519Subtype(jwk map[string]any, class error) error {
	raw, present := jwk["crv"]
	if !present {
		return fmt.Errorf("%wan OKP jwk must carry a 'crv' naming its subtype", class)
	}
	crv, ok := raw.(string)
	if !ok {
		return fmt.Errorf("%wthe 'crv' claim must be a string", class)
	}
	if crv != "Ed25519" {
		return fmt.Errorf("%wEd25519 is the only OKP subtype supported", jose_errors.ErrUnsupportedAlgorithm)
	}
	return nil
}

func EdDSAPublicKeyFromJwk(jwk map[string]any) (*ed25519.PublicKey, error) {
	if err := requireEd25519Subtype(jwk, jose_errors.ErrInvalidPublicKey); err != nil {
		return nil, err
	}

	xBytes, err := jsonutils.ExtractAndDecodeBase64urlString(jwk, "x")
	if err != nil {
		return nil, fmt.Errorf("error extracting 'x' parameter from jwk: %w", err)
	}

	if len(xBytes) != ed25519.PublicKeySize {
		return nil, fmt.Errorf("%wthe 'x' parameter of an Ed25519 jwk is %d bytes, got %d", jose_errors.ErrInvalidPublicKey, ed25519.PublicKeySize, len(xBytes))
	}

	return model.Pointer(ed25519.PublicKey(xBytes)), nil
}

func EdDSAPrivateKeyFromJwk(jwk map[string]any) (*ed25519.PrivateKey, error) {
	if err := requireEd25519Subtype(jwk, jose_errors.ErrInvalidPrivateKey); err != nil {
		return nil, err
	}

	xBytes, err := jsonutils.ExtractAndDecodeBase64urlString(jwk, "x")
	if err != nil {
		return nil, fmt.Errorf("error extracting 'x' parameter from jwk: %w", err)
	}

	dBytes, err := jsonutils.ExtractAndDecodeBase64urlString(jwk, "d")
	if err != nil {
		return nil, fmt.Errorf("error extracting 'd' parameter from jwk: %w", err)
	}

	if len(dBytes) != ed25519.SeedSize {
		return nil, fmt.Errorf("%wthe 'd' parameter of an Ed25519 jwk is %d bytes, got %d", jose_errors.ErrInvalidPrivateKey, ed25519.SeedSize, len(dBytes))
	}
	private := ed25519.NewKeyFromSeed(dBytes)
	if !bytes.Equal(private[ed25519.SeedSize:], xBytes) {
		return nil, fmt.Errorf("%wthe 'x' parameter of an Ed25519 jwk is not the public key of its 'd'", jose_errors.ErrInvalidPrivateKey)
	}
	return model.Pointer(private), nil
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
	if err != nil && !errors.Is(err, jose_errors.ErrMissingClaim) {
		return nil, fmt.Errorf("error extracting 'p' parameter from jwk: %w", err)
	}

	qBytes, err := jsonutils.ExtractAndDecodeBase64urlString(jwk, "q")
	if err != nil && !errors.Is(err, jose_errors.ErrMissingClaim) {
		return nil, fmt.Errorf("error extracting 'q' parameter from jwk: %w", err)
	}

	if jsonutils.KeyPresent(jwk, "oth") {
		return nil, fmt.Errorf("%wan RSA jwk with more than two primes is not supported", jose_errors.ErrInvalidPrivateKey)
	}

	pPresent := jsonutils.KeyPresent(jwk, "p") //if one additional value is present, they all must be
	for _, v := range []string{"q", "dp", "dq", "qi"} {
		present := jsonutils.KeyPresent(jwk, v)
		if present != pPresent {
			return nil, fmt.Errorf("%wmalformed RSA jwk - refer to text in section 6.3.2 of RFC 7518 for explanation", jose_errors.ErrInvalidPrivateKey)
		}
	}

	privateKey := rsa.PrivateKey{
		PublicKey: *publicKey,
		D:         new(big.Int).SetBytes(dBytes),
	}
	if pBytes != nil && qBytes != nil {
		privateKey.Primes = []*big.Int{new(big.Int).SetBytes(pBytes), new(big.Int).SetBytes(qBytes)}
		privateKey.Precompute()
	}

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

func JwkFromRSAPublicKey(publicKey *rsa.PublicKey) (map[string]any, error) {
	if err := checkRSAPublicKey(publicKey, jose_errors.ErrInvalidPublicKey); err != nil {
		return nil, err
	}
	jwk := map[string]any{}

	b64N := []byte(base64.RawURLEncoding.EncodeToString(publicKey.N.Bytes()))
	b64E := []byte(base64.RawURLEncoding.EncodeToString(big.NewInt(int64(publicKey.E)).Bytes()))

	h := sha256.New()
	h.Write(append(b64N, b64E...))
	jwk["n"] = string(b64N)
	jwk["e"] = string(b64E)
	jwk["kty"] = "RSA"
	jwk["kid"] = base64.RawURLEncoding.EncodeToString(h.Sum(nil))
	return jwk, nil
}

func checkRSAPublicKey(publicKey *rsa.PublicKey, class error) error {
	if publicKey == nil || publicKey.N == nil || publicKey.N.Sign() <= 0 || publicKey.E < 1 {
		return fmt.Errorf("%wan RSA key needs a positive modulus and exponent", class)
	}
	return nil
}

// JwkFromRSAPrivateKey builds the jwk of an RSA private key with either no
// primes or exactly two.
//
// RFC 7518 section 6.3.2 makes "d" the only required private member, so a key
// with no primes is encoded as "n", "e" and "d". A two-prime key also carries
// "p", "q", "dp", "dq" and "qi", which that section says producers SHOULD
// include. Section 6.3.2.7 says a consumer without multi-prime support MUST NOT
// use a key carrying "oth". The readers here have none, so a key with more than
// two primes is refused rather than produced.
func JwkFromRSAPrivateKey(privateKey *rsa.PrivateKey) (map[string]any, error) {
	if privateKey == nil {
		return nil, fmt.Errorf("%wan RSA key needs a positive modulus and exponent", jose_errors.ErrInvalidPrivateKey)
	}
	if err := checkRSAPublicKey(&privateKey.PublicKey, jose_errors.ErrInvalidPrivateKey); err != nil {
		return nil, err
	}
	if privateKey.D == nil || privateKey.D.Sign() <= 0 || privateKey.D.Cmp(privateKey.N) >= 0 {
		return nil, fmt.Errorf("%wan RSA private key needs d with 0 < d < n", jose_errors.ErrInvalidPrivateKey)
	}

	jwk, err := JwkFromRSAPublicKey(&privateKey.PublicKey)
	if err != nil {
		return nil, err
	}
	encode := func(i *big.Int) string { return base64.RawURLEncoding.EncodeToString(i.Bytes()) }
	jwk["d"] = encode(privateKey.D)
	if len(privateKey.Primes) == 0 {
		return jwk, nil
	}

	if len(privateKey.Primes) != 2 || privateKey.Primes[0] == nil || privateKey.Primes[1] == nil {
		return nil, fmt.Errorf("%wan RSA private key has no primes or exactly two", jose_errors.ErrInvalidPrivateKey)
	}
	if privateKey.Primes[0].Sign() <= 0 || privateKey.Primes[1].Sign() <= 0 {
		return nil, fmt.Errorf("%wthe primes of an RSA private key must be positive", jose_errors.ErrInvalidPrivateKey)
	}
	precomputed := rsa.PrivateKey{PublicKey: privateKey.PublicKey, D: privateKey.D, Primes: privateKey.Primes}
	if err := precomputed.Validate(); err != nil {
		return nil, fmt.Errorf("%wthe RSA private key is inconsistent: %w", jose_errors.ErrInvalidPrivateKey, err)
	}
	precomputed.Precompute()
	if precomputed.Precomputed.Dp == nil || precomputed.Precomputed.Dq == nil || precomputed.Precomputed.Qinv == nil {
		return nil, fmt.Errorf("%wthe CRT values of the RSA private key cannot be computed", jose_errors.ErrInvalidPrivateKey)
	}

	jwk["p"] = encode(privateKey.Primes[0])
	jwk["q"] = encode(privateKey.Primes[1])
	jwk["dp"] = encode(precomputed.Precomputed.Dp)
	jwk["dq"] = encode(precomputed.Precomputed.Dq)
	jwk["qi"] = encode(precomputed.Precomputed.Qinv)
	return jwk, nil
}

func ExtractRSFromSignature(signature []byte, keySize int) (*big.Int, *big.Int, error) {
	if len(signature) != keySize {
		return nil, nil, fmt.Errorf("%wsignature should be %d bytes for given algorithm", jose_errors.ErrInvalidSignature, keySize)
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
		return nil, fmt.Errorf("%wfailed to sign token: %s", jose_errors.ErrSigningError, err.Error())
	}

	sigBytes := make([]byte, keySize)

	r.FillBytes(sigBytes[0 : keySize/2])
	s.FillBytes(sigBytes[keySize/2:])

	return sigBytes, nil
}

func RsaPkcs1Sign(rand io.Reader, pk rsa.PrivateKey, digest []byte, hash crypto.Hash) ([]byte, error) {
	s, err := rsa.SignPKCS1v15(rand, &pk, hash, digest)
	if err != nil {
		return nil, fmt.Errorf("%wfailed to sign token: %s", jose_errors.ErrSigningError, err.Error())
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
		return nil, fmt.Errorf("%wfailed to sign token: %s", jose_errors.ErrSigningError, err.Error())
	}
	return s, nil
}

func ProduceMac(h hash.Hash, digest []byte) []byte {
	h.Write(digest)
	return h.Sum(nil)
}
