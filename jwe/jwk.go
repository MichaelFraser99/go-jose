package jwe

import (
	"crypto"
	"errors"
	"fmt"
	"slices"
	"strings"

	"github.com/MichaelFraser99/go-jose/internal/jose/header"
	"github.com/MichaelFraser99/go-jose/internal/jose/jsonutils"
	internal_jwk "github.com/MichaelFraser99/go-jose/internal/jose/jwk"
	"github.com/MichaelFraser99/go-jose/joseerror"
	"github.com/MichaelFraser99/go-jose/jwa"
	"github.com/MichaelFraser99/go-jose/jwk"
	"github.com/MichaelFraser99/go-jose/model"
)

var encrypterKeyReaders = map[jwa.Algorithm]func(map[string]any) (crypto.PublicKey, error){
	jwa.RSAOAEP:      jwk.PublicFromJwk,
	jwa.RSAOAEP256:   jwk.PublicFromJwk,
	jwa.RSAOAEP384:   jwk.PublicFromJwk,
	jwa.RSAOAEP512:   jwk.PublicFromJwk,
	jwa.A128KW:       readSharedKey,
	jwa.A192KW:       readSharedKey,
	jwa.A256KW:       readSharedKey,
	jwa.A128GCMKW:    readSharedKey,
	jwa.A192GCMKW:    readSharedKey,
	jwa.A256GCMKW:    readSharedKey,
	jwa.ECDHES:       jwk.PublicFromJwk,
	jwa.ECDHESA128KW: jwk.PublicFromJwk,
	jwa.ECDHESA192KW: jwk.PublicFromJwk,
	jwa.ECDHESA256KW: jwk.PublicFromJwk,
}

var keyAgreementAlgorithms = []jwa.Algorithm{jwa.ECDHES, jwa.ECDHESA128KW, jwa.ECDHESA192KW, jwa.ECDHESA256KW}

func requiredOperations(alg jwa.Algorithm, decrypting bool) []string {
	switch {
	case slices.Contains(keyAgreementAlgorithms, alg) && decrypting:
		return []string{"deriveKey", "deriveBits"}
	case slices.Contains(keyAgreementAlgorithms, alg):
		return nil
	case decrypting:
		return []string{"unwrapKey"}
	}
	return []string{"wrapKey"}
}

func readSharedKey(sharedJwk map[string]any) (crypto.PublicKey, error) {
	return jwk.PrivateFromJwk(sharedJwk)
}

var signatureOperations = map[string]bool{"sign": true, "verify": true}

var agreementOperations = map[string]bool{"deriveKey": true, "deriveBits": true}

// GetEncrypterFromJwk returns an Encrypter for the key management algorithm alg
// from the recipient's jwk, as GetEncrypter does from a key.
//
// For RSA-OAEP, RSA-OAEP-256, RSA-OAEP-384 and RSA-OAEP-512, the jwk is an RSA
// public key. For the ECDH-ES algorithms, it is an EC public key on P-256, P-384
// or P-521, or an OKP X25519 public key. For A128KW, A192KW, A256KW, A128GCMKW,
// A192GCMKW and A256GCMKW, it is an "oct" key. dir is refused with
// ErrUnsupportedAlgorithm, as no jwk member names the "enc" a dir key is bound
// to (RFC 8725 section 3.1); build a DirectKey instead. The PBES2 algorithms
// are refused with ErrUnsupportedAlgorithm too, as a password is not a key a
// jwk holds; build a PasswordKey instead.
//
// RFC 8725 section 3.1 requires each key to be used with exactly one algorithm,
// so a jwk whose "alg" is present and is not the string alg names is refused.
// A jwk whose "use" is present and is not "enc", or whose "key_ops" is present
// and lacks "wrapKey", is refused too (RFC 7517 sections 4.2 and 4.3). So is a
// jwk whose "use" and "key_ops" are not consistent, or whose "key_ops" lists a
// value twice, both of which section 4.3 forbids. No "key_ops" value names a
// public key used for key agreement, so an ECDH-ES jwk needs none. But one whose
// "key_ops" names "sign" or "verify", and neither "deriveKey" nor "deriveBits",
// is refused, as it marks a signing key. With opts.StrictKeyOperations on, a
// jwk that section 4.3 says SHOULD NOT be published is refused too. opts may be
// nil. Every refusal of the jwk carries ErrInvalidPublicKey.
func GetEncrypterFromJwk(alg jwa.Algorithm, publicJwk map[string]any, opts *model.JWEOptions) (model.Encrypter, error) {
	read, ok := encrypterKeyReaders[alg]
	if !ok {
		return nil, notFromJwk(alg)
	}
	if err := checkKeyDeclarations(alg, publicJwk, requiredOperations(alg, false), opts != nil && opts.StrictKeyOperations, joseerror.ErrInvalidPublicKey); err != nil {
		return nil, err
	}
	key, err := read(publicJwk)
	if errors.Is(err, joseerror.ErrInvalidPublicKey) {
		return nil, err
	}
	if err != nil {
		return nil, fmt.Errorf("%wthe jwk is not a key for %s: %w", joseerror.ErrInvalidPublicKey, alg.String(), err)
	}
	e, err := GetEncrypter(alg, key)
	if err != nil {
		return nil, err
	}
	return e, nil
}

// GetDecrypterFromJwk returns a Decrypter for the key management algorithm alg
// from the recipient's jwk, as GetDecrypter does from a key.
//
// For RSA-OAEP, RSA-OAEP-256, RSA-OAEP-384 and RSA-OAEP-512, the jwk is an RSA
// private key. For the ECDH-ES algorithms, it is an EC private key on P-256,
// P-384 or P-521, or an OKP X25519 private key. For A128KW, A192KW, A256KW and
// the AES GCM key wraps, it is an "oct" key. dir and the PBES2 algorithms are
// refused as GetEncrypterFromJwk refuses them. The
// jwk's "alg", "use" and "key_ops" are held to the rules GetEncrypterFromJwk
// applies, with "unwrapKey" in place of "wrapKey", and, for an ECDH-ES key,
// "deriveKey" or "deriveBits" (RFC 7517 section 4.3). opts may be nil, and its
// StrictKeyOperations applies as it does to GetEncrypterFromJwk. Every refusal
// of the jwk carries ErrInvalidPrivateKey.
func GetDecrypterFromJwk(alg jwa.Algorithm, privateJwk map[string]any, opts *model.JWEOptions) (model.Decrypter, error) {
	if _, ok := encrypterKeyReaders[alg]; !ok {
		return nil, notFromJwk(alg)
	}
	if err := checkKeyDeclarations(alg, privateJwk, requiredOperations(alg, true), opts != nil && opts.StrictKeyOperations, joseerror.ErrInvalidPrivateKey); err != nil {
		return nil, err
	}
	key, err := jwk.PrivateFromJwk(privateJwk)
	if errors.Is(err, joseerror.ErrInvalidPrivateKey) {
		return nil, err
	}
	if err != nil {
		return nil, fmt.Errorf("%wthe jwk is not a key for %s: %w", joseerror.ErrInvalidPrivateKey, alg.String(), err)
	}
	d, err := GetDecrypter(alg, key)
	if err != nil {
		return nil, err
	}
	return d, nil
}

func notFromJwk(alg jwa.Algorithm) error {
	if alg == jwa.Dir {
		return fmt.Errorf("%wa jwk does not name the enc a dir key is bound to, so build a jwe.DirectKey instead", joseerror.ErrUnsupportedAlgorithm)
	}
	if slices.Contains(header.PasswordAlgorithms, alg) {
		return fmt.Errorf("%w%s takes a password, which a jwk does not hold, so build a jwe.PasswordKey instead", joseerror.ErrUnsupportedAlgorithm, alg)
	}
	return fmt.Errorf("%w%s is not a key management algorithm this library implements", joseerror.ErrUnsupportedAlgorithm, algorithmName(alg))
}

func checkKeyDeclarations(alg jwa.Algorithm, key map[string]any, operations []string, strictKeyOperations bool, class error) error {
	if member, present := key["alg"]; present {
		if name, isString := member.(string); name != alg.String() {
			return fmt.Errorf("%wthe jwk's alg %s does not name %s", class, describe(name, isString), alg.String())
		}
	}

	member, usePresent := key["use"]
	if usePresent {
		if use, isString := member.(string); use != "enc" {
			return fmt.Errorf("%wthe jwk's use %s is not enc", class, describe(use, isString))
		}
	}

	ops, opsPresent, err := internal_jwk.KeyOperations(key, class)
	if err != nil {
		return err
	}
	if !opsPresent {
		return nil
	}
	permitted := false
	signature, agreement := "", false
	for _, name := range ops {
		if usePresent && signatureOperations[name] {
			return fmt.Errorf("%wthe jwk's use enc and key_ops %s are not consistent", class, jsonutils.QuoteBounded(name))
		}
		if signatureOperations[name] && signature == "" {
			signature = name
		}
		agreement = agreement || agreementOperations[name]
		if slices.Contains(operations, name) {
			permitted = true
		}
	}
	if len(operations) == 0 && signature != "" && !agreement {
		return fmt.Errorf("%wthe jwk's key_ops %s names a signature operation, not key agreement", class, jsonutils.QuoteBounded(signature))
	}
	if !permitted && len(operations) > 0 {
		return fmt.Errorf("%wthe jwk's key_ops do not include %s", class, strings.Join(operations, " or "))
	}
	if strictKeyOperations {
		return internal_jwk.CheckRecommendedKeyOperations(key, class)
	}
	return nil
}

func describe(value string, isString bool) string {
	if !isString {
		return "a value that is not a string"
	}
	return jsonutils.QuoteBounded(value)
}
