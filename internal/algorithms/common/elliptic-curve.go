package common

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"encoding/base64"
	"encoding/json"
	"fmt"
	e "github.com/MichaelFraser99/go-jose/error"
	"io"
	"math/big"
)

type PublicKey struct {
	Kty string `json:"kty"`
	Crv string `json:"crv"`
	X   string `json:"x"`
	Y   string `json:"y"`
}

func (pubKey *PublicKey) Equal(x PublicKey) bool {
	if pubKey.X == x.X && pubKey.Y == x.Y && pubKey.Kty == x.Kty && pubKey.Crv == x.Crv {
		return true
	}
	return false
}

func NewPublicKeyFromJson(publicKeyJson []byte, curve elliptic.Curve) (*ecdsa.PublicKey, error) {
	var publicKey PublicKey
	err := json.Unmarshal(publicKeyJson, &publicKey)
	if err != nil {
		return nil, &e.InvalidPublicKey{Message: fmt.Sprintf("provided public key json isn't valid es256 public key: %s", err.Error())}
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

func Sign(rand io.Reader, pk ecdsa.PrivateKey, digest []byte, keySize int) ([]byte, error) {
	r, s, err := ecdsa.Sign(rand, &pk, digest)
	if err != nil {
		return nil, &e.SigningError{Message: fmt.Sprintf("failed to sign token: %s", err.Error())}
	}

	sigBytes := make([]byte, keySize)

	r.FillBytes(sigBytes[0 : keySize/2])
	s.FillBytes(sigBytes[keySize/2:])

	return sigBytes, nil
}

func GeneratePublicKey(pk ecdsa.PrivateKey, curveName string, keySize int) PublicKey {
	cryptoPubKey := pk.PublicKey

	xb := make([]byte, keySize/2)
	yb := make([]byte, keySize/2)

	cryptoPubKey.X.FillBytes(xb)
	cryptoPubKey.Y.FillBytes(yb)

	x := base64.RawURLEncoding.EncodeToString(xb)
	y := base64.RawURLEncoding.EncodeToString(yb)

	return PublicKey{
		Kty: "EC",
		Crv: curveName,
		X:   x,
		Y:   y,
	}
}
