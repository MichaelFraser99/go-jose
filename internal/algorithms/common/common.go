package common

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"fmt"
	e "github.com/MichaelFraser99/go-jose/error"
	"io"
	"math/big"
)

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
		return nil, &e.InvalidPublicKey{Message: fmt.Sprintf("provided public key json isn't a valid ecdsa public key: %s", err.Error())}
	}

	xBytes, err := base64.RawURLEncoding.DecodeString(publicKey.X)
	if err != nil {
		return nil, &e.InvalidPublicKey{Message: fmt.Sprintf("error decoding provided public key: %s", err.Error())}
	}

	yBytes, err := base64.RawURLEncoding.DecodeString(publicKey.Y)
	if err != nil {
		return nil, &e.InvalidPublicKey{Message: fmt.Sprintf("error decoding provided public key: %s", err.Error())}
	}

	pk := &ecdsa.PublicKey{
		Curve: curve,
		X:     big.NewInt(0).SetBytes(xBytes),
		Y:     big.NewInt(0).SetBytes(yBytes),
	}
	return pk, nil
}

func JwkFromECDSAPublicKey(publicKey *ecdsa.PublicKey) map[string]string {
	jwk := map[string]string{}

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

	b64X := base64.RawURLEncoding.EncodeToString(xBytes)
	b64Y := base64.RawURLEncoding.EncodeToString(yBytes)

	jwk["x"] = b64X
	jwk["y"] = b64Y
	jwk["kty"] = "EC"
	return jwk
}

func NewRSAPublicKeyFromJson(publicKeyJson []byte) (*rsa.PublicKey, error) {
	var publicKey RSAPublicKey
	err := json.Unmarshal(publicKeyJson, &publicKey)
	if err != nil {
		return nil, &e.InvalidPublicKey{Message: fmt.Sprintf("provided public key json isn't a valid rsa public key: %s", err.Error())}
	}

	nBytes, err := base64.RawURLEncoding.DecodeString(publicKey.N)
	if err != nil {
		return nil, &e.InvalidPublicKey{Message: fmt.Sprintf("error decoding provided public key: %s", err.Error())}
	}

	eBytes, err := base64.RawURLEncoding.DecodeString(publicKey.E)
	if err != nil {
		return nil, &e.InvalidPublicKey{Message: fmt.Sprintf("error decoding provided public key: %s", err.Error())}
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

func JwkFromRSAPublicKey(publicKey *rsa.PublicKey) map[string]string {
	jwk := map[string]string{}

	nBytes := publicKey.N.Bytes()
	eBytes := big.NewInt(int64(publicKey.E)).Bytes()

	b64N := make([]byte, base64.RawURLEncoding.EncodedLen(len(nBytes)))
	base64.RawURLEncoding.Encode(b64N, nBytes)

	b64E := make([]byte, base64.RawURLEncoding.EncodedLen(len(eBytes)))
	base64.RawURLEncoding.Encode(b64E, eBytes)

	jwk["n"] = string(b64N)
	jwk["e"] = string(b64E)
	jwk["kty"] = "RSA"
	return jwk
}

func ExtractRSFromSignature(signature []byte, keySize int) (*big.Int, *big.Int, error) {
	if len(signature) != keySize {
		return nil, nil, &e.InvalidSignature{Message: fmt.Sprintf("signature should be %d bytes for given algorithm", keySize)}
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
		return nil, &e.SigningError{Message: fmt.Sprintf("failed to sign token: %s", err.Error())}
	}

	sigBytes := make([]byte, keySize)

	r.FillBytes(sigBytes[0 : keySize/2])
	s.FillBytes(sigBytes[keySize/2:])

	return sigBytes, nil
}

func RsaPkcs1Sign(rand io.Reader, pk rsa.PrivateKey, digest []byte, hash crypto.Hash) ([]byte, error) {
	s, err := rsa.SignPKCS1v15(rand, &pk, hash, digest)
	if err != nil {
		return nil, &e.SigningError{
			Message: fmt.Sprintf("failed to sign token: %s", err.Error()),
		}
	}
	return s, nil
}
