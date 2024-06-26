package common

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	jose_errors "github.com/MichaelFraser99/go-jose/error"
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

type ECDSAPublicKey struct {
	Kty string `json:"kty"`
	Crv string `json:"crv"`
	X   string `json:"x"`
	Y   string `json:"y"`
}

func (pubKey *ECDSAPublicKey) Equal(x ECDSAPublicKey) bool {
	if pubKey.X == x.X && pubKey.Y == x.Y && pubKey.Kty == x.Kty && pubKey.Crv == x.Crv {
		return true
	}
	return false
}

type RSAPublicKey struct {
	N string `json:"n"`
	E string `json:"e"`
}

func (pubKey *RSAPublicKey) Equal(x RSAPublicKey) bool {
	if pubKey.N == x.N && pubKey.E == x.E {
		return true
	}
	return false
}

func NewECDSAPublicKeyFromJson(publicKeyJson []byte, curve elliptic.Curve) (*ecdsa.PublicKey, error) {
	var publicKey ECDSAPublicKey
	err := json.Unmarshal(publicKeyJson, &publicKey)
	if err != nil {
		return nil, fmt.Errorf("%wprovided public key json isn't a valid ecdsa public key: %s", jose_errors.InvalidPublicKey, err.Error())
	}

	xBytes, err := base64.RawURLEncoding.DecodeString(publicKey.X)
	if err != nil {
		return nil, fmt.Errorf("%werror decoding provided public key: %s", jose_errors.InvalidPublicKey, err.Error())
	}

	yBytes, err := base64.RawURLEncoding.DecodeString(publicKey.Y)
	if err != nil {
		return nil, fmt.Errorf("%werror decoding provided public key: %s", jose_errors.InvalidPublicKey, err.Error())
	}

	pk := &ecdsa.PublicKey{
		Curve: curve,
		X:     big.NewInt(0).SetBytes(xBytes),
		Y:     big.NewInt(0).SetBytes(yBytes),
	}
	return pk, nil
}

func ECDSAPublicKeyFromJwk(jwk map[string]any) (*ecdsa.PublicKey, error) {
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

	var xBytes, yBytes []byte
	var err error
	if x, present := jwk["x"]; present {
		if xString, ok := x.(string); ok {
			xBytes, err = base64.RawURLEncoding.DecodeString(xString)
			if err != nil {
				return nil, fmt.Errorf("invalid base64url in 'x' claim")
			}
		} else {
			return nil, fmt.Errorf("provided 'x' claim cannot be parsed as a string")
		}
	} else {
		return nil, fmt.Errorf("no 'x' claim present in jwk")
	}

	if y, present := jwk["y"]; present {
		if yString, ok := y.(string); ok {
			yBytes, err = base64.RawURLEncoding.DecodeString(yString)
			if err != nil {
				return nil, fmt.Errorf("invalid base64url in 'y' claim")
			}
		} else {
			return nil, fmt.Errorf("provided 'y' claim cannot be parsed as a string")
		}
	} else {
		return nil, fmt.Errorf("no 'y' claim present in jwk")
	}

	x := new(big.Int).SetBytes(xBytes)
	y := new(big.Int).SetBytes(yBytes)
	publicKey := &ecdsa.PublicKey{
		Curve: curve,
		X:     x,
		Y:     y,
	}
	return publicKey, nil
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

func NewRSAPublicKeyFromJson(publicKeyJson []byte) (*rsa.PublicKey, error) {
	var publicKey RSAPublicKey
	err := json.Unmarshal(publicKeyJson, &publicKey)
	if err != nil {
		return nil, fmt.Errorf("%wprovided public key json isn't a valid rsa public key: %s", jose_errors.InvalidPublicKey, err.Error())
	}

	nBytes, err := base64.RawURLEncoding.DecodeString(publicKey.N)
	if err != nil {
		return nil, fmt.Errorf("%werror decoding provided public key: %s", jose_errors.InvalidPublicKey, err.Error())
	}

	eBytes, err := base64.RawURLEncoding.DecodeString(publicKey.E)
	if err != nil {
		return nil, fmt.Errorf("%werror decoding provided public key: %s", jose_errors.InvalidPublicKey, err.Error())
	}

	pk := &rsa.PublicKey{
		N: new(big.Int).SetBytes(nBytes),
		E: 0,
	}
	if len(eBytes) < 1 {
		return nil, fmt.Errorf("invalid E string: too short")
	}

	e := big.NewInt(0).SetBytes(eBytes)
	if !e.IsInt64() {
		return nil, fmt.Errorf("invalid E string: too large")
	}
	pk.E = int(e.Int64())

	return pk, nil
}

func RSAPublicKeyFromJwk(jwk map[string]any) (*rsa.PublicKey, error) {
	var nBytes, eBytes []byte
	var err error
	if n, present := jwk["n"]; present {
		if nString, ok := n.(string); ok {
			nBytes, err = base64.RawURLEncoding.DecodeString(nString)
			if err != nil {
				return nil, fmt.Errorf("invalid base64url in 'n' claim")
			}
		} else {
			return nil, fmt.Errorf("provided 'n' claim cannot be parsed as a string")
		}
	} else {
		return nil, fmt.Errorf("no 'n' claim present in jwk")
	}

	if e, present := jwk["e"]; present {
		if eString, ok := e.(string); ok {
			eBytes, err = base64.RawURLEncoding.DecodeString(eString)
			if err != nil {
				return nil, fmt.Errorf("invalid base64url in 'e' claim")
			}
		} else {
			return nil, fmt.Errorf("provided 'e' claim cannot be parsed as a string")
		}
	} else {
		return nil, fmt.Errorf("no 'e' claim present in jwk")
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
