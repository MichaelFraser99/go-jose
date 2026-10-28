package common

import (
	"bytes"
	"crypto/mldsa"
	"encoding/base64"
	"fmt"

	"github.com/MichaelFraser99/go-jose/internal/jose/jsonutils"
	jose_errors "github.com/MichaelFraser99/go-jose/joseerror"
)

var mldsaParameterSets = map[string]mldsa.Parameters{
	"ML-DSA-44": mldsa.MLDSA44(),
	"ML-DSA-65": mldsa.MLDSA65(),
	"ML-DSA-87": mldsa.MLDSA87(),
}

// MLDSAParameters returns the FIPS 204 parameter set an RFC 9964 section 5 alg
// value names.
func MLDSAParameters(alg string) (mldsa.Parameters, bool) {
	params, ok := mldsaParameterSets[alg]
	return params, ok
}

// UsableMLDSAPublicKey returns a copy of publicKey when it is a key of the
// parameter set given, and refuses it otherwise with the error class given. A
// zero-value key is refused: crypto/mldsa panics when asked its parameters.
func UsableMLDSAPublicKey(publicKey *mldsa.PublicKey, params mldsa.Parameters, class error) (*mldsa.PublicKey, error) {
	if publicKey == nil {
		return nil, fmt.Errorf("%wan %s public key is required, got none", class, params)
	}
	rebuilt, err := mldsa.NewPublicKey(params, publicKey.Bytes())
	if err != nil {
		return nil, fmt.Errorf("%wnot an %s public key: %s", class, params, err.Error())
	}
	return rebuilt, nil
}

// UsableMLDSAPrivateKey returns a copy of privateKey when it is a key of the
// parameter set given, and refuses it otherwise. The key is rebuilt from its
// seed, and its public key must be the one that seed derives. A zero-value key
// reports an all-zero seed, so it is refused here rather than replaced by the
// key that seed derives.
func UsableMLDSAPrivateKey(privateKey *mldsa.PrivateKey, params mldsa.Parameters) (*mldsa.PrivateKey, error) {
	if privateKey == nil {
		return nil, fmt.Errorf("%wan %s private key is required, got none", jose_errors.ErrInvalidPrivateKey, params)
	}
	rebuilt, err := mldsa.NewPrivateKey(params, privateKey.Bytes())
	if err != nil {
		return nil, fmt.Errorf("%wnot an %s private key: %s", jose_errors.ErrInvalidPrivateKey, params, err.Error())
	}
	if !bytes.Equal(rebuilt.PublicKey().Bytes(), privateKey.PublicKey().Bytes()) {
		return nil, fmt.Errorf("%wnot an %s private key: its public key is not the one its seed derives", jose_errors.ErrInvalidPrivateKey, params)
	}
	return rebuilt, nil
}

func mldsaParametersOfPublicKey(publicKey *mldsa.PublicKey, class error) (string, mldsa.Parameters, error) {
	if publicKey == nil {
		return "", mldsa.Parameters{}, fmt.Errorf("%wan ML-DSA public key is required, got none", class)
	}
	size := len(publicKey.Bytes())
	for alg, params := range mldsaParameterSets {
		if params.PublicKeySize() == size {
			return alg, params, nil
		}
	}
	return "", mldsa.Parameters{}, fmt.Errorf("%wan ML-DSA public key is 1312, 1952 or 2592 bytes, got %d", class, size)
}

// JwkFromMLDSAPublicKey builds the AKP jwk of an ML-DSA public key, as RFC 9964
// section 3 defines it: "alg" names the parameter set and "pub" carries the
// FIPS 204 encoding.
func JwkFromMLDSAPublicKey(publicKey *mldsa.PublicKey) (map[string]any, error) {
	alg, params, err := mldsaParametersOfPublicKey(publicKey, jose_errors.ErrInvalidPublicKey)
	if err != nil {
		return nil, err
	}
	usable, err := UsableMLDSAPublicKey(publicKey, params, jose_errors.ErrInvalidPublicKey)
	if err != nil {
		return nil, err
	}
	return withThumbprint(map[string]any{
		"kty": "AKP",
		"alg": alg,
		"pub": base64.RawURLEncoding.EncodeToString(usable.Bytes()),
	})
}

// JwkFromMLDSAPrivateKey builds the AKP jwk of an ML-DSA private key. RFC 9964
// section 4 carries the private key only as its 32 byte seed, in "priv".
func JwkFromMLDSAPrivateKey(privateKey *mldsa.PrivateKey) (map[string]any, error) {
	if privateKey == nil {
		return nil, fmt.Errorf("%wan ML-DSA private key is required, got none", jose_errors.ErrInvalidPrivateKey)
	}
	alg, params, err := mldsaParametersOfPublicKey(privateKey.PublicKey(), jose_errors.ErrInvalidPrivateKey)
	if err != nil {
		return nil, err
	}
	usable, err := UsableMLDSAPrivateKey(privateKey, params)
	if err != nil {
		return nil, err
	}
	jwk, err := withThumbprint(map[string]any{
		"kty": "AKP",
		"alg": alg,
		"pub": base64.RawURLEncoding.EncodeToString(usable.PublicKey().Bytes()),
	})
	if err != nil {
		return nil, err
	}
	jwk["priv"] = base64.RawURLEncoding.EncodeToString(usable.Bytes())
	return jwk, nil
}

func mldsaParametersOfJwk(jwk map[string]any, class error) (mldsa.Parameters, error) {
	alg, ok := jwk["alg"].(string)
	if !ok {
		return mldsa.Parameters{}, fmt.Errorf("%wan AKP jwk must carry a string 'alg' naming its algorithm", class)
	}
	params, ok := mldsaParameterSets[alg]
	if !ok {
		return mldsa.Parameters{}, fmt.Errorf("%wML-DSA-44, ML-DSA-65 and ML-DSA-87 are the only AKP algorithms supported", jose_errors.ErrUnsupportedAlgorithm)
	}
	return params, nil
}

// MLDSAPublicKeyFromJwk reads the public key of an AKP jwk. RFC 9964 section 3
// requires "alg", which fixes the parameter set, and "pub", which must be the
// public key size section 5 gives for it. A "priv" member is not read.
func MLDSAPublicKeyFromJwk(jwk map[string]any) (*mldsa.PublicKey, error) {
	params, err := mldsaParametersOfJwk(jwk, jose_errors.ErrInvalidPublicKey)
	if err != nil {
		return nil, err
	}
	pub, err := jsonutils.ExtractAndDecodeBase64urlString(jwk, "pub")
	if err != nil {
		return nil, fmt.Errorf("%werror extracting 'pub' parameter from jwk: %w", jose_errors.ErrInvalidPublicKey, err)
	}
	publicKey, err := mldsa.NewPublicKey(params, pub)
	if err != nil {
		return nil, fmt.Errorf("%wthe 'pub' parameter of an %s jwk is %d bytes, got %d", jose_errors.ErrInvalidPublicKey, params, params.PublicKeySize(), len(pub))
	}
	return publicKey, nil
}

// MLDSAPrivateKeyFromJwk reads the private key of an AKP jwk. RFC 9964 section
// 4 makes "priv" the 32 byte seed, and section 7.4 warns of a "pub" that does
// not belong to it, so "pub" must be the public key the seed derives.
func MLDSAPrivateKeyFromJwk(jwk map[string]any) (*mldsa.PrivateKey, error) {
	params, err := mldsaParametersOfJwk(jwk, jose_errors.ErrInvalidPrivateKey)
	if err != nil {
		return nil, err
	}
	pub, err := jsonutils.ExtractAndDecodeBase64urlString(jwk, "pub")
	if err != nil {
		return nil, fmt.Errorf("%werror extracting 'pub' parameter from jwk: %w", jose_errors.ErrInvalidPrivateKey, err)
	}
	priv, err := jsonutils.ExtractAndDecodeBase64urlString(jwk, "priv")
	if err != nil {
		return nil, fmt.Errorf("%werror extracting 'priv' parameter from jwk: %w", jose_errors.ErrInvalidPrivateKey, err)
	}
	privateKey, err := mldsa.NewPrivateKey(params, priv)
	if err != nil {
		return nil, fmt.Errorf("%wthe 'priv' parameter of an AKP jwk is a %d byte seed, got %d", jose_errors.ErrInvalidPrivateKey, mldsa.PrivateKeySize, len(priv))
	}
	if !bytes.Equal(privateKey.PublicKey().Bytes(), pub) {
		return nil, fmt.Errorf("%wthe 'pub' parameter of an %s jwk is not the public key of its 'priv'", jose_errors.ErrInvalidPrivateKey, params)
	}
	return privateKey, nil
}
