package common

import (
	"bytes"
	"crypto"
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
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

// ECDSAPrivateKeyFromJwk reads the jwk of an ECDSA private key.
//
// RFC 7518 section 6.2.2 makes "d" REQUIRED and section 6.2.2.1 fixes it at
// ceiling(log-base-2(n)/8) octets. "d" is the private key value of the point
// "x", "y", so a d outside [1, n-1] or whose public point is not x, y is
// refused.
func ECDSAPrivateKeyFromJwk(jwk map[string]any) (*ecdsa.PrivateKey, error) {
	publicKey, ecdhPublic, err := readECDSAPublicKey(jwk, jose_errors.ErrInvalidPrivateKey)
	if err != nil {
		return nil, err
	}

	dBytes, err := jsonutils.ExtractAndDecodeBase64urlString(jwk, "d")
	if err != nil {
		return nil, fmt.Errorf("%wan EC private key jwk must carry 'd': %w", jose_errors.ErrInvalidPrivateKey, err)
	}
	ecdhPrivate, err := ecdhPublic.Curve().NewPrivateKey(dBytes)
	if err != nil {
		return nil, fmt.Errorf("%wthe 'd' of a %s jwk is %d octets in [1, n-1]: %w", jose_errors.ErrInvalidPrivateKey, publicKey.Params().Name, (publicKey.Params().N.BitLen()+7)/8, err)
	}
	if !ecdhPrivate.PublicKey().Equal(ecdhPublic) {
		return nil, fmt.Errorf("%wthe 'x' and 'y' of an EC jwk are not the public point of its 'd'", jose_errors.ErrInvalidPrivateKey)
	}

	return &ecdsa.PrivateKey{PublicKey: *publicKey, D: new(big.Int).SetBytes(dBytes)}, nil
}

// ECDSAPublicKeyFromJwk reads the jwk of an ECDSA public key.
//
// RFC 7518 sections 6.2.1.2 and 6.2.1.3 fix "x" and "y" at the full size of a
// coordinate of the curve, and section 6.2.1 makes them the coordinates of a
// point on it, so a coordinate of any other length or a point off the curve is
// refused.
func ECDSAPublicKeyFromJwk(jwk map[string]any) (*ecdsa.PublicKey, error) {
	publicKey, _, err := readECDSAPublicKey(jwk, jose_errors.ErrInvalidPublicKey)
	if err != nil {
		return nil, err
	}
	return publicKey, nil
}

func readECDSAPublicKey(jwk map[string]any, class error) (*ecdsa.PublicKey, *ecdh.PublicKey, error) {
	curve, err := extractECDSACurveFromJwk(jwk)
	if err != nil {
		return nil, nil, fmt.Errorf("error extracting curve from ECDSA jwk: %w", err)
	}

	xBytes, err := jsonutils.ExtractAndDecodeBase64urlString(jwk, "x")
	if err != nil {
		return nil, nil, fmt.Errorf("error extracting 'x' coordinate from jwk: %w", err)
	}
	yBytes, err := jsonutils.ExtractAndDecodeBase64urlString(jwk, "y")
	if err != nil {
		return nil, nil, fmt.Errorf("error extracting 'y' coordinate from jwk: %w", err)
	}

	coordinateBytes := (curve.Params().BitSize + 7) / 8
	if len(xBytes) != coordinateBytes || len(yBytes) != coordinateBytes {
		return nil, nil, fmt.Errorf("%wthe 'x' and 'y' of a %s jwk are %d octets each, got %d and %d", class, curve.Params().Name, coordinateBytes, len(xBytes), len(yBytes))
	}

	publicKey := &ecdsa.PublicKey{
		Curve: curve,
		X:     new(big.Int).SetBytes(xBytes),
		Y:     new(big.Int).SetBytes(yBytes),
	}
	ecdhPublic, err := publicKey.ECDH()
	if err != nil {
		return nil, nil, fmt.Errorf("%wthe point of an EC jwk is not on its curve: %w", class, err)
	}
	return publicKey, ecdhPublic, nil
}

func extractECDSACurveFromJwk(jwk map[string]any) (elliptic.Curve, error) {
	curveName, ok := jwk["crv"].(string)
	if !ok {
		return nil, fmt.Errorf("%wthe 'crv' claim must be a string naming a registered curve", jose_errors.ErrInvalidPublicKey)
	}
	switch curveName {
	case "P-256":
		return elliptic.P256(), nil
	case "P-384":
		return elliptic.P384(), nil
	case "P-521":
		return elliptic.P521(), nil
	default:
		return nil, fmt.Errorf("%wthe 'crv' of an EC jwk is not one of P-256, P-384 and P-521", jose_errors.ErrUnsupportedAlgorithm)
	}
}

// JwkFromECDSAPublicKey builds the jwk of an ECDSA public key.
//
// RFC 7518 sections 6.2.1.2 and 6.2.1.3 fix "x" and "y" at the full coordinate
// size of the curve, so a point that is not on its curve is refused rather than
// encoded.
func JwkFromECDSAPublicKey(publicKey *ecdsa.PublicKey) (map[string]any, error) {
	if err := checkECDSAPublicKey(publicKey, jose_errors.ErrInvalidPublicKey); err != nil {
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

func checkECDSAPublicKey(publicKey *ecdsa.PublicKey, class error) error {
	if publicKey == nil || publicKey.Curve == nil || publicKey.X == nil || publicKey.Y == nil {
		return fmt.Errorf("%wan ECDSA key needs a curve and a point", class)
	}
	switch publicKey.Curve {
	case elliptic.P256(), elliptic.P384(), elliptic.P521():
	default:
		return fmt.Errorf("%wthe curve of an EC jwk is one of P-256, P-384 and P-521", class)
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
	if err := checkECDSAPublicKey(&privateKey.PublicKey, jose_errors.ErrInvalidPrivateKey); err != nil {
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

// RSAPrivateKeyFromJwk reads the jwk of an RSA private key with either no
// primes or exactly two.
//
// RFC 7518 section 6.3 gives the members the semantics of RFC 3447 sections
// 3.1 and 3.2: n is a product of odd primes, d is a positive integer less
// than n with e*d == 1 (mod lambda(n)), and dp, dq and qi are the CRT values
// of p and q. A key whose members disagree is refused.
func RSAPrivateKeyFromJwk(jwk map[string]any) (*rsa.PrivateKey, error) {
	publicKey, err := RSAPublicKeyFromJwk(jwk)
	if err != nil {
		return nil, fmt.Errorf("error extracting public portion of RSA jwk: %w", err)
	}

	dBytes, err := jsonutils.ExtractAndDecodeBase64urlString(jwk, "d")
	if err != nil {
		return nil, fmt.Errorf("error extracting 'd' parameter from jwk: %w", err)
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
	if privateKey.D.Sign() <= 0 || privateKey.D.Cmp(privateKey.N) >= 0 {
		return nil, fmt.Errorf("%wthe 'd' of an RSA jwk is a positive integer less than n", jose_errors.ErrInvalidPrivateKey)
	}
	if !pPresent {
		two := big.NewInt(2)
		roundTrip := new(big.Int).Exp(two, privateKey.D, privateKey.N)
		roundTrip.Exp(roundTrip, big.NewInt(int64(privateKey.E)), privateKey.N)
		if roundTrip.Cmp(new(big.Int).Mod(two, privateKey.N)) != 0 {
			return nil, fmt.Errorf("%wthe 'd' of an RSA jwk is not the private exponent of its 'n' and 'e'", jose_errors.ErrInvalidPrivateKey)
		}
		return &privateKey, nil
	}

	members := map[string]*big.Int{}
	for _, v := range []string{"p", "q", "dp", "dq", "qi"} {
		b, err := jsonutils.ExtractAndDecodeBase64urlString(jwk, v)
		if err != nil {
			return nil, fmt.Errorf("error extracting '%s' parameter from jwk: %w", v, err)
		}
		members[v] = new(big.Int).SetBytes(b)
	}

	if privateKey.N.Bit(0) == 0 {
		return nil, fmt.Errorf("%wthe 'n' of an RSA jwk is a product of odd primes", jose_errors.ErrInvalidPrivateKey)
	}
	privateKey.Primes = []*big.Int{members["p"], members["q"]}
	if err := privateKey.Validate(); err != nil {
		return nil, fmt.Errorf("%wthe members of an RSA jwk are not one key: %w", jose_errors.ErrInvalidPrivateKey, err)
	}
	privateKey.Precompute()
	if members["dp"].Cmp(privateKey.Precomputed.Dp) != 0 || members["dq"].Cmp(privateKey.Precomputed.Dq) != 0 || members["qi"].Cmp(privateKey.Precomputed.Qinv) != 0 {
		return nil, fmt.Errorf("%wthe 'dp', 'dq' and 'qi' of an RSA jwk are not the CRT values of its 'p', 'q' and 'd'", jose_errors.ErrInvalidPrivateKey)
	}

	return &privateKey, nil
}

// RSAPublicKeyFromJwk reads the jwk of an RSA public key.
//
// RFC 7518 section 6.3.1.2 carries "e" as a Base64urlUInt and RFC 3447
// section 3.1 makes it at least 3 and coprime to lambda(n), which is even, so
// e is odd. crypto/rsa refuses an exponent
// above 2^31-1, so an "e" outside that range is refused rather than truncated.
func RSAPublicKeyFromJwk(jwk map[string]any) (*rsa.PublicKey, error) {
	nBytes, err := jsonutils.ExtractAndDecodeBase64urlString(jwk, "n")
	if err != nil {
		return nil, fmt.Errorf("error extracting 'n' parameter from jwk: %w", err)
	}

	eBytes, err := jsonutils.ExtractAndDecodeBase64urlString(jwk, "e")
	if err != nil {
		return nil, fmt.Errorf("error extracting 'e' parameter from jwk: %w", err)
	}

	e := new(big.Int).SetBytes(eBytes)
	if e.Cmp(big.NewInt(3)) < 0 || e.Cmp(big.NewInt(1<<31-1)) > 0 || e.Bit(0) == 0 {
		return nil, fmt.Errorf("%wthe 'e' of an RSA jwk is an odd integer from 3 to 2^31-1", jose_errors.ErrInvalidPublicKey)
	}

	return &rsa.PublicKey{
		N: new(big.Int).SetBytes(nBytes),
		E: int(e.Int64()),
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
