package jwe

import (
	"crypto"
	"fmt"

	"github.com/MichaelFraser99/go-jose/internal/jose/jsonutils"
	"github.com/MichaelFraser99/go-jose/joseerror"
	"github.com/MichaelFraser99/go-jose/jwa"
	"github.com/MichaelFraser99/go-jose/jwk"
	"github.com/MichaelFraser99/go-jose/model"
)

var encrypterKeyReaders = map[jwa.Algorithm]func(map[string]any) (crypto.PublicKey, error){
	jwa.RSAOAEP:    jwk.PublicFromJwk,
	jwa.RSAOAEP256: jwk.PublicFromJwk,
	jwa.RSAOAEP384: jwk.PublicFromJwk,
	jwa.RSAOAEP512: jwk.PublicFromJwk,
	jwa.A128KW:     readSharedKey,
	jwa.A192KW:     readSharedKey,
	jwa.A256KW:     readSharedKey,
}

func readSharedKey(sharedJwk map[string]any) (crypto.PublicKey, error) {
	return jwk.PrivateFromJwk(sharedJwk)
}

var signatureOperations = map[string]bool{"sign": true, "verify": true}

// GetEncrypterFromJwk returns an Encrypter for the key management algorithm alg
// from the recipient's jwk, as GetEncrypter does from a key.
//
// For RSA-OAEP, RSA-OAEP-256, RSA-OAEP-384 and RSA-OAEP-512, the jwk is an RSA
// public key. For A128KW, A192KW and A256KW, it is an "oct" key. dir is refused
// with ErrUnsupportedAlgorithm, as no jwk member names the "enc" a dir key is
// bound to (RFC 8725 section 3.1); build a DirectKey instead.
//
// RFC 8725 section 3.1 requires each key to be used with exactly one algorithm,
// so a jwk whose "alg" is present and is not the string alg names is refused.
// A jwk whose "use" is present and is not "enc", or whose "key_ops" is present
// and lacks "wrapKey", is refused too (RFC 7517 sections 4.2 and 4.3). So is a
// jwk whose "use" and "key_ops" are not consistent, or whose "key_ops" lists a
// value twice, both of which section 4.3 forbids.
// Every refusal of the jwk carries ErrInvalidPublicKey.
func GetEncrypterFromJwk(alg jwa.Algorithm, publicJwk map[string]any) (model.Encrypter, error) {
	read, ok := encrypterKeyReaders[alg]
	if !ok {
		return nil, notFromJwk(alg)
	}
	if err := checkKeyDeclarations(alg, publicJwk, "wrapKey", joseerror.ErrInvalidPublicKey); err != nil {
		return nil, err
	}
	key, err := read(publicJwk)
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
// private key. For A128KW, A192KW and A256KW, it is an "oct" key. dir is refused
// as GetEncrypterFromJwk refuses it. The jwk's "alg", "use" and "key_ops" are
// held to the rules GetEncrypterFromJwk applies, with "unwrapKey" in place of
// "wrapKey". Every refusal of the jwk carries ErrInvalidPrivateKey.
func GetDecrypterFromJwk(alg jwa.Algorithm, privateJwk map[string]any) (model.Decrypter, error) {
	if _, ok := encrypterKeyReaders[alg]; !ok {
		return nil, notFromJwk(alg)
	}
	if err := checkKeyDeclarations(alg, privateJwk, "unwrapKey", joseerror.ErrInvalidPrivateKey); err != nil {
		return nil, err
	}
	key, err := jwk.PrivateFromJwk(privateJwk)
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
	return fmt.Errorf("%w%s is not a key management algorithm this library implements", joseerror.ErrUnsupportedAlgorithm, algorithmName(alg))
}

func checkKeyDeclarations(alg jwa.Algorithm, key map[string]any, operation string, class error) error {
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

	member, opsPresent := key["key_ops"]
	if !opsPresent {
		return nil
	}
	ops, ok := member.([]any)
	if !ok {
		return fmt.Errorf("%wthe jwk's key_ops must be an array", class)
	}
	permitted := false
	seen := map[string]bool{}
	for _, op := range ops {
		name, ok := op.(string)
		if !ok {
			return fmt.Errorf("%wthe jwk's key_ops must hold strings", class)
		}
		if seen[name] {
			return fmt.Errorf("%wthe jwk's key_ops lists %s more than once", class, jsonutils.QuoteBounded(name))
		}
		seen[name] = true
		if usePresent && signatureOperations[name] {
			return fmt.Errorf("%wthe jwk's use enc and key_ops %s are not consistent", class, jsonutils.QuoteBounded(name))
		}
		if name == operation {
			permitted = true
		}
	}
	if !permitted {
		return fmt.Errorf("%wthe jwk's key_ops do not include %s", class, operation)
	}
	return nil
}

func describe(value string, isString bool) string {
	if !isString {
		return "a value that is not a string"
	}
	return jsonutils.QuoteBounded(value)
}
