package jwe

import (
	"context"
	"crypto"
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"errors"
	"testing"

	"github.com/MichaelFraser99/go-jose/joseerror"
	"github.com/MichaelFraser99/go-jose/jwa"
	"github.com/MichaelFraser99/go-jose/jwk"
	"github.com/MichaelFraser99/go-jose/model"
)

func TestECDHES_RoundTripsOnEveryCurve(t *testing.T) {
	type curve struct {
		name    string
		public  crypto.PublicKey
		private crypto.PrivateKey
	}
	var curves []curve
	for _, c := range []ecdh.Curve{ecdh.P256(), ecdh.P384(), ecdh.P521(), ecdh.X25519()} {
		key, err := c.GenerateKey(rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		curves = append(curves, curve{name: "ecdh " + curveName(c), public: key.PublicKey(), private: key})
	}
	for _, c := range []elliptic.Curve{elliptic.P256(), elliptic.P384(), elliptic.P521()} {
		key, err := ecdsa.GenerateKey(c, rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		curves = append(curves, curve{name: "ecdsa " + c.Params().Name, public: &key.PublicKey, private: key})
	}
	for _, c := range curves {
		for _, alg := range keyAgreement {
			for _, enc := range allEncryptions {
				t.Run(c.name+"/"+alg.String()+"/"+enc.String(), func(t *testing.T) {
					encrypter, err := GetEncrypter(alg, c.public)
					if err != nil {
						t.Fatal(err)
					}
					decrypter, err := GetDecrypter(alg, c.private)
					if err != nil {
						t.Fatal(err)
					}
					token, err := Encrypt(encrypter, enc, []byte("agreed"), map[string]any{"apu": "QWxpY2U", "apv": "Qm9i"})
					if err != nil {
						t.Fatal(err)
					}
					head, plaintext, used, err := Decrypt(context.Background(), token, []model.Decrypter{decrypter}, nil)
					if err != nil || string(plaintext) != "agreed" || used != decrypter {
						t.Fatalf("[RFC 7518 4.6] want the plaintext back, got %q and %v", plaintext, err)
					}
					if _, ok := head["epk"].(map[string]any); !ok || head["apu"] != "QWxpY2U" || head["apv"] != "Qm9i" {
						t.Errorf("[RFC 7518 4.6.1] the header carries epk, apu and apv, got %v", head)
					}
					parts := decodedParts(t, token)
					if want := map[bool]int{true: 0, false: cekSizes[enc] + 8}[alg == jwa.ECDHES]; len(parts[1]) != want {
						t.Errorf("[RFC 7518 4.6] want an encrypted key of %d octets, got %d", want, len(parts[1]))
					}
				})
			}
		}
	}
}

func curveName(c ecdh.Curve) string {
	return map[ecdh.Curve]string{ecdh.P256(): "P-256", ecdh.P384(): "P-384", ecdh.P521(): "P-521", ecdh.X25519(): "X25519"}[c]
}

func epkOf(t *testing.T, public crypto.PublicKey) map[string]any {
	t.Helper()
	member, err := jwk.PublicJwk(public)
	if err != nil {
		t.Fatal(err)
	}
	epk := *member
	delete(epk, "kid")
	return epk
}

func TestDecrypt_ChecksTheEphemeralPublicKey(t *testing.T) {
	recipient, err := ecdh.P256().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	decrypter, err := GetDecrypter(jwa.ECDHES, recipient)
	if err != nil {
		t.Fatal(err)
	}
	p384, err := ecdh.P384().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	edPublic, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	onCurve := epkOf(t, recipient.PublicKey())
	withD := epkOf(t, recipient.PublicKey())
	withD["d"] = "AAAA"
	offCurve := epkOf(t, recipient.PublicKey())
	y := []byte(offCurve["y"].(string))
	y[0] = map[bool]byte{true: 'B', false: 'A'}[y[0] == 'A']
	offCurve["y"] = string(y)
	tests := []struct {
		name      string
		head      map[string]any
		want      error
		malformed bool
		clause    string
	}{
		{name: "no epk", head: map[string]any{}, want: joseerror.ErrMissingClaim, malformed: true, clause: "RFC 7518 4.6.1.1"},
		{name: "an epk that is not an object", head: map[string]any{"epk": "key"}, want: joseerror.ErrMalformedClaim, malformed: true, clause: "RFC 7518 4.6.1.1"},
		{name: "an epk carrying a private member", head: map[string]any{"epk": withD}, want: joseerror.ErrMalformedClaim, malformed: true, clause: "RFC 7518 4.6.1.1"},
		{name: "an epk whose point is not on its curve", head: map[string]any{"epk": offCurve}, want: joseerror.ErrMalformedClaim, malformed: true, clause: "RFC 8725 3.4"},
		{name: "an RSA epk", head: map[string]any{"epk": epkOf(t, &rsaKey.PublicKey)}, want: joseerror.ErrMalformedClaim, malformed: true, clause: "RFC 7518 4.6"},
		{name: "an Ed25519 epk", head: map[string]any{"epk": epkOf(t, edPublic)}, want: joseerror.ErrMalformedClaim, malformed: true, clause: "RFC 8037 3.2"},
		{name: "an apu equal to the apv", head: map[string]any{"epk": onCurve, "apu": "QQ", "apv": "QQ"}, want: joseerror.ErrMalformedClaim, malformed: true, clause: "RFC 7518 4.6.2"},
		{name: "an apv that is not base64url", head: map[string]any{"epk": onCurve, "apv": "Qm9i="}, want: joseerror.ErrMalformedClaim, malformed: true, clause: "RFC 7518 4.6.1.3"},
		{name: "an apu that is not a string", head: map[string]any{"epk": onCurve, "apu": 7}, want: joseerror.ErrMalformedClaim, malformed: true, clause: "RFC 7518 4.6.1.2"},
		{name: "an epk of an unknown kty", head: map[string]any{"epk": map[string]any{"kty": "FOO"}}, want: joseerror.ErrMalformedClaim, malformed: true, clause: "RFC 7518 4.6"},
		{name: "an epk with no kty", head: map[string]any{"epk": map[string]any{"crv": "P-256"}}, want: joseerror.ErrMalformedClaim, malformed: true, clause: "RFC 7518 4.6"},
		{name: "an oct epk", head: map[string]any{"epk": map[string]any{"kty": "oct", "k": "AAAA"}}, want: joseerror.ErrMalformedClaim, malformed: true, clause: "RFC 7518 4.6"},
		{name: "an AKP epk", head: map[string]any{"epk": map[string]any{"kty": "AKP", "alg": "nope", "pub": "AAAA"}}, want: joseerror.ErrMalformedClaim, malformed: true, clause: "RFC 7518 4.6"},
		{name: "an Ed448 epk", head: map[string]any{"epk": map[string]any{"kty": "OKP", "crv": "Ed448", "x": base64.RawURLEncoding.EncodeToString(make([]byte, 57))}}, want: joseerror.ErrMalformedClaim, malformed: true, clause: "RFC 8037 3.2"},
		{name: "an X448 epk", head: map[string]any{"epk": map[string]any{"kty": "OKP", "crv": "X448", "x": base64.RawURLEncoding.EncodeToString(make([]byte, 56))}}, want: joseerror.ErrUnsupportedAlgorithm, clause: "RFC 8037 3.2"},
		{name: "an epk on a curve this library does not implement", head: map[string]any{"epk": map[string]any{"kty": "EC", "crv": "secp256k1", "x": "AAAA", "y": "AAAA"}}, want: joseerror.ErrUnsupportedAlgorithm, clause: "RFC 7518 6.2.1.1"},
		{name: "a valid epk on another curve", head: map[string]any{"epk": epkOf(t, p384.PublicKey())}, want: joseerror.ErrDecryptionFailed, clause: "RFC 8725 3.4"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tt.head["alg"], tt.head["enc"] = "ECDH-ES", "A128GCM"
			_, plaintext, used, err := Decrypt(context.Background(), headerToken(t, tt.head), []model.Decrypter{decrypter}, nil)
			if !errors.Is(err, tt.want) || plaintext != nil || used != nil {
				t.Fatalf("[%s] want %v, got %v", tt.clause, tt.want, err)
			}
			if errors.Is(err, joseerror.ErrMalformedToken) != tt.malformed {
				t.Errorf("[%s] want ErrMalformedToken %v, got %v", tt.clause, tt.malformed, err)
			}
		})
	}
}

func TestDecrypt_AnEmptyApuIsTheEmptyPartyUInfo(t *testing.T) {
	pair := pairFor(t, jwa.ECDHESA128KW, jwa.A128GCM)
	token, err := Encrypt(pair.encrypter, jwa.A128GCM, []byte("p"), map[string]any{"apu": ""})
	if err != nil {
		t.Fatal(err)
	}
	if _, _, _, err := Decrypt(context.Background(), token, []model.Decrypter{pair.decrypter}, nil); err != nil {
		t.Errorf("[RFC 7518 4.6.1.2] the base64url encoding of no octets is the empty string, got %v", err)
	}
}

func TestEncrypt_RefusesAnEphemeralKeyOrPartyInfoItCannotHonour(t *testing.T) {
	encrypter := pairFor(t, jwa.ECDHES, jwa.A128GCM).encrypter
	for name, head := range map[string]map[string]any{
		"an epk given by the caller":   {"epk": map[string]any{"kty": "EC"}},
		"an apu equal to the apv":      {"apu": "QQ", "apv": "QQ"},
		"an apu that is not base64url": {"apu": "!!"},
	} {
		t.Run(name, func(t *testing.T) {
			if token, err := Encrypt(encrypter, jwa.A128GCM, []byte("p"), head); !errors.Is(err, joseerror.ErrMalformedClaim) || token != "" {
				t.Errorf("[RFC 7518 4.6] want ErrMalformedClaim and no token, got %v", err)
			}
		})
	}
}

func TestGetEncrypterAndGetDecrypterFromJwk_BuildECDHESKeys(t *testing.T) {
	ecKey, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	xKey, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	for name, keys := range map[string][2]any{"an EC P-384 jwk": {&ecKey.PublicKey, ecKey}, "an OKP X25519 jwk": {xKey.PublicKey(), xKey}} {
		t.Run(name, func(t *testing.T) {
			publicJwk, err := jwk.PublicJwk(keys[0])
			if err != nil {
				t.Fatal(err)
			}
			privateJwk, err := jwk.PrivateJwk(keys[1])
			if err != nil {
				t.Fatal(err)
			}
			encrypter, err := GetEncrypterFromJwk(jwa.ECDHESA256KW, with(*publicJwk, map[string]any{"use": "enc", "key_ops": []any{}}))
			if err != nil {
				t.Fatalf("[RFC 7517 4.3] no key_ops value names a public key used for key agreement, so an empty one must be accepted, got %v", err)
			}
			for _, ops := range [][]any{{"deriveKey"}, {"deriveBits"}, {"deriveKey", "deriveBits"}} {
				decrypter, err := GetDecrypterFromJwk(jwa.ECDHESA256KW, with(*privateJwk, map[string]any{"key_ops": ops}))
				if err != nil {
					t.Fatalf("[RFC 7517 4.3] key_ops %v names key agreement, got %v", ops, err)
				}
				token, err := Encrypt(encrypter, jwa.A256GCM, []byte("p"), nil)
				if err != nil {
					t.Fatal(err)
				}
				if _, _, _, err := Decrypt(context.Background(), token, []model.Decrypter{decrypter}, nil); err != nil {
					t.Fatal(err)
				}
			}
			if d, err := GetDecrypterFromJwk(jwa.ECDHES, with(*privateJwk, map[string]any{"key_ops": []any{"unwrapKey"}})); !errors.Is(err, joseerror.ErrInvalidPrivateKey) || d != nil {
				t.Errorf("[RFC 7517 4.3] a decrypter's key_ops must name deriveKey or deriveBits, got %v", err)
			}
			if e, err := GetEncrypterFromJwk(jwa.ECDHES, with(*publicJwk, map[string]any{"use": "enc", "key_ops": []any{"sign"}})); !errors.Is(err, joseerror.ErrInvalidPublicKey) || e != nil {
				t.Errorf("[RFC 7517 4.3] use enc and key_ops sign are not consistent, got %v", err)
			}
			for _, ops := range [][]any{{"verify"}, {"sign"}, {"deriveKey", "verify"}} {
				if e, err := GetEncrypterFromJwk(jwa.ECDHES, with(*publicJwk, map[string]any{"key_ops": ops})); !errors.Is(err, joseerror.ErrInvalidPublicKey) || e != nil {
					t.Errorf("[RFC 7517 4.3] key_ops %v names a signature operation, so the key is not for key agreement, got %v", ops, err)
				}
			}
			if e, err := GetEncrypterFromJwk(jwa.ECDHES, with(*publicJwk, map[string]any{"alg": "ECDH-ES+A128KW"})); !errors.Is(err, joseerror.ErrInvalidPublicKey) || e != nil {
				t.Errorf("[RFC 8725 3.1] a jwk naming another alg must be refused, got %v", err)
			}
		})
	}
	edPublic, edPrivate, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	edPublicJwk, err := jwk.PublicJwk(edPublic)
	if err != nil {
		t.Fatal(err)
	}
	edPrivateJwk, err := jwk.PrivateJwk(&edPrivate)
	if err != nil {
		t.Fatal(err)
	}
	if e, err := GetEncrypterFromJwk(jwa.ECDHES, *edPublicJwk); !errors.Is(err, joseerror.ErrInvalidPublicKey) || e != nil {
		t.Errorf("[RFC 8037 3.2] an Ed25519 key cannot agree a key, got %v", err)
	}
	if d, err := GetDecrypterFromJwk(jwa.ECDHES, *edPrivateJwk); !errors.Is(err, joseerror.ErrInvalidPrivateKey) || d != nil {
		t.Errorf("[RFC 8037 3.2] an Ed25519 key cannot agree a key, got %v", err)
	}
}
