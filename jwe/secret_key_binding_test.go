package jwe

import (
	"crypto"
	"errors"
	"fmt"
	"slices"
	"strings"
	"testing"

	"github.com/MichaelFraser99/go-jose/joseerror"
	"github.com/MichaelFraser99/go-jose/jwa"
	"github.com/MichaelFraser99/go-jose/jwk"
	"github.com/MichaelFraser99/go-jose/jws"
	"github.com/MichaelFraser99/go-jose/model"
)

var secretSizes = map[jwa.Algorithm][]int{
	jwa.HS256:     {32, 48, 64},
	jwa.HS384:     {48, 64},
	jwa.HS512:     {64},
	jwa.A128KW:    {16},
	jwa.A192KW:    {24},
	jwa.A256KW:    {32},
	jwa.A128GCMKW: {16},
	jwa.A192GCMKW: {24},
	jwa.A256GCMKW: {32},
}

var hmacAlgorithms = []jwa.Algorithm{jwa.HS256, jwa.HS384, jwa.HS512}

func sizeFits(alg jwa.Algorithm, size int) bool {
	if slices.Contains(hmacAlgorithms, alg) {
		return size >= secretSizes[alg][0]
	}
	return size == secretSizes[alg][0]
}

func publicsOfSecret(t *testing.T, alg jwa.Algorithm, size int) map[string]crypto.PublicKey {
	t.Helper()
	secret := randomBytes(t, size)
	if slices.Contains(hmacAlgorithms, alg) {
		signer, err := jws.GetSigner(alg, &model.Opts{SecretKey: &secret})
		if err != nil {
			t.Fatal(err)
		}
		validator, err := jws.GetValidator(alg, signer.Public())
		if err != nil {
			t.Fatal(err)
		}
		return map[string]crypto.PublicKey{"signer": signer.Public(), "validator": validator.Public()}
	}
	encrypter, err := GetEncrypter(alg, secret)
	if err != nil {
		t.Fatal(err)
	}
	decrypter, err := GetDecrypter(alg, secret)
	if err != nil {
		t.Fatal(err)
	}
	return map[string]crypto.PublicKey{"encrypter": encrypter.Public(), "decrypter": decrypter.Public()}
}

type secretUse struct {
	name  string
	class error
	build func(alg jwa.Algorithm, key crypto.PublicKey) (any, error)
}

func usesOf(alg jwa.Algorithm) []secretUse {
	if slices.Contains(hmacAlgorithms, alg) {
		return []secretUse{{"GetValidator", joseerror.ErrInvalidPublicKey, func(alg jwa.Algorithm, key crypto.PublicKey) (any, error) { return jws.GetValidator(alg, key) }}}
	}
	return []secretUse{
		{"GetEncrypter", joseerror.ErrInvalidPublicKey, func(alg jwa.Algorithm, key crypto.PublicKey) (any, error) { return GetEncrypter(alg, key) }},
		{"GetDecrypter", joseerror.ErrInvalidPrivateKey, func(alg jwa.Algorithm, key crypto.PublicKey) (any, error) { return GetDecrypter(alg, key) }},
	}
}

func TestSecretKey_IsAcceptedOnlyByTheAlgorithmThatMadeIt(t *testing.T) {
	for made, sizes := range secretSizes {
		for _, size := range sizes {
			for used := range secretSizes {
				if !sizeFits(used, size) {
					continue
				}
				for _, use := range usesOf(used) {
					t.Run(fmt.Sprintf("%d-octet %s secret to %s %s", size, made, use.name, used), func(t *testing.T) {
						for from, public := range publicsOfSecret(t, made, size) {
							holder, err := use.build(used, public)
							if used == made {
								if err != nil {
									t.Errorf("[RFC 8725 3.1] the Public of a %s %s must serve %s, got %v", made, from, used, err)
								}
								continue
							}
							if !errors.Is(err, use.class) || holder != nil || !strings.Contains(err.Error(), "RFC 8725 section 3.1") {
								t.Errorf("[RFC 8725 3.1] each key is used with exactly one algorithm, so the Public of a %s %s must be refused for %s with %v, got %v", made, from, used, use.class, err)
							}
						}
					})
				}
			}
		}
	}
}

func TestSecretKey_ARawByteSliceIsBoundToNoAlgorithmAndServesAny(t *testing.T) {
	secret := randomBytes(t, 32)
	if _, err := GetEncrypter(jwa.A256KW, secret); err != nil {
		t.Errorf("[RFC 7518 4.4] a []byte of 32 octets is an A256KW key, got %v", err)
	}
	if _, err := GetDecrypter(jwa.A256GCMKW, secret); err != nil {
		t.Errorf("[RFC 7518 4.7] a []byte of 32 octets is an A256GCMKW key, got %v", err)
	}
}

func TestPrivateJwk_ASecretKeyCarriesTheAlgorithmThatMadeIt(t *testing.T) {
	secret := randomBytes(t, 32)
	signer, err := jws.GetSigner(jwa.HS256, &model.Opts{SecretKey: &secret})
	if err != nil {
		t.Fatal(err)
	}
	written, err := jwk.PrivateJwk(signer.Public())
	if err != nil {
		t.Fatal(err)
	}
	if (*written)["alg"] != "HS256" {
		t.Errorf("[RFC 7517 4.4] the jwk of a secret made for HS256 must name HS256 in alg, got %v", *written)
	}
	if _, err := jws.GetSignerFromJwk(jwa.HS256, *written, nil); err != nil {
		t.Errorf("[RFC 7517 4.4] the jwk must build an HS256 signer again, got %v", err)
	}
	if _, err := GetEncrypterFromJwk(jwa.A256KW, *written, nil); !errors.Is(err, joseerror.ErrInvalidPublicKey) {
		t.Errorf("[RFC 8725 3.1] the jwk names HS256, so it must be refused for A256KW, got %v", err)
	}
}
