package jws_test

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/mldsa"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"strings"
	"testing"

	"github.com/MichaelFraser99/go-jose/jwa"
	"github.com/MichaelFraser99/go-jose/jws"
	"github.com/MichaelFraser99/go-jose/model"
)

var formatVerbs = []string{"%v", "%+v", "%#v", "%s", "%q", "%x", "%X", "%d"}

func keyIn(printed string, key []byte) string {
	forms := map[string]string{
		"decimal":   strings.Trim(fmt.Sprintf("%v", key), "[]"),
		"hex":       hex.EncodeToString(key),
		"HEX":       strings.ToUpper(hex.EncodeToString(key)),
		"raw":       string(key),
		"base64url": base64.RawURLEncoding.EncodeToString(key),
		"base64":    base64.StdEncoding.EncodeToString(key),
	}
	for name, form := range forms {
		if strings.Contains(printed, form) {
			return name
		}
	}
	return ""
}

func TestFormat_ASignerOrHMACValidatorNeverPrintsItsKey(t *testing.T) {
	secrets := map[jwa.Algorithm][]byte{jwa.HS256: make([]byte, 32), jwa.HS384: make([]byte, 48), jwa.HS512: make([]byte, 64)}
	for _, secret := range secrets {
		if _, err := rand.Read(secret); err != nil {
			t.Fatal(err)
		}
	}
	type holder struct {
		name  string
		names string
		value any
		key   []byte
	}
	var holders []holder
	for alg, secret := range secrets {
		signer, err := jws.GetSigner(alg, &model.Opts{SecretKey: &secret})
		if err != nil {
			t.Fatal(err)
		}
		validator, err := jws.GetValidator(alg, signer.Public())
		if err != nil {
			t.Fatal(err)
		}
		holders = append(holders,
			holder{alg.String() + " signer", alg.String(), signer, secret},
			holder{alg.String() + " validator", alg.String(), validator, secret},
			holder{alg.String() + " signer.Public()", "HMAC", signer.Public(), secret},
		)
	}
	_, edKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	edSigner, err := jws.GetSignerFromPrivateKey(jwa.Ed25519, edKey)
	if err != nil {
		t.Fatal(err)
	}
	holders = append(holders, holder{"Ed25519 signer", "Ed25519", edSigner, edKey.Seed()})
	for alg, curve := range map[jwa.Algorithm]elliptic.Curve{jwa.ES256: elliptic.P256(), jwa.ES384: elliptic.P384(), jwa.ES512: elliptic.P521()} {
		key, err := ecdsa.GenerateKey(curve, rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		signer, err := jws.GetSignerFromPrivateKey(alg, key)
		if err != nil {
			t.Fatal(err)
		}
		d, err := key.Bytes()
		if err != nil {
			t.Fatal(err)
		}
		holders = append(holders, holder{alg.String() + " signer", alg.String(), signer, d[1:]})
	}
	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	for _, alg := range []jwa.Algorithm{jwa.RS256, jwa.RS384, jwa.RS512, jwa.PS256, jwa.PS384, jwa.PS512} {
		signer, err := jws.GetSignerFromPrivateKey(alg, rsaKey)
		if err != nil {
			t.Fatal(err)
		}
		holders = append(holders, holder{alg.String() + " signer", alg.String(), signer, rsaKey.D.Bytes()})
	}
	for alg, params := range map[jwa.Algorithm]mldsa.Parameters{jwa.MLDSA44: mldsa.MLDSA44(), jwa.MLDSA65: mldsa.MLDSA65(), jwa.MLDSA87: mldsa.MLDSA87()} {
		key, err := mldsa.GenerateKey(params)
		if err != nil {
			t.Fatal(err)
		}
		signer, err := jws.GetSignerFromPrivateKey(alg, key)
		if err != nil {
			t.Fatal(err)
		}
		holders = append(holders, holder{alg.String() + " signer", alg.String(), signer, key.Bytes()})
	}

	for _, h := range holders {
		for _, verb := range formatVerbs {
			t.Run(h.name+" "+verb, func(t *testing.T) {
				printed := fmt.Sprintf(verb, h.value)
				if form := keyIn(printed, h.key); form != "" {
					t.Errorf("[README Signers] printing a %s with %s must not show its key, but it shows it in %s form: %s", h.name, verb, form, printed)
				}
				if !strings.Contains(printed, h.names) {
					t.Errorf("[README Signers] printing a %s with %s must name %s, got %s", h.name, verb, h.names, printed)
				}
			})
		}
	}
}
