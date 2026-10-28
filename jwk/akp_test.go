package jwk

import (
	"bytes"
	"crypto/mldsa"
	"encoding/base64"
	"errors"
	"maps"
	"reflect"
	"testing"

	"github.com/MichaelFraser99/go-jose/internal/testvectors"
	"github.com/MichaelFraser99/go-jose/joseerror"
)

func rfc9964(t *testing.T) []testvectors.MLDSAExample {
	t.Helper()
	examples, err := testvectors.RFC9964()
	if err != nil {
		t.Fatal(err)
	}
	return examples
}

func publicOnly(jwk map[string]any) map[string]any {
	public := maps.Clone(jwk)
	delete(public, "priv")
	return public
}

func TestAKP_TheRFC9964ExampleJwksReadAndWriteBackExactly(t *testing.T) {
	for _, ex := range rfc9964(t) {
		t.Run(ex.Alg, func(t *testing.T) {
			private, err := PrivateFromJwk(ex.PrivateJwk)
			if err != nil {
				t.Fatalf("[RFC 9964 A.1] the example private jwk must be read, got %v", err)
			}
			key, ok := private.(*mldsa.PrivateKey)
			if !ok || !bytes.Equal(key.Bytes(), ex.Seed) {
				t.Fatalf("[RFC 9964 4] the private key must be the example's seed, got %T", private)
			}
			written, err := PrivateJwk(key)
			if err != nil {
				t.Fatal(err)
			}
			if !reflect.DeepEqual(*written, ex.PrivateJwk) {
				t.Errorf("[RFC 9964 A.1] PrivateJwk must give the example jwk, kid included\n got %v\nwant %v", *written, ex.PrivateJwk)
			}

			public, err := PublicFromJwk(publicOnly(ex.PrivateJwk))
			if err != nil {
				t.Fatalf("[RFC 9964 3] the example's public jwk must be read, got %v", err)
			}
			if !bytes.Equal(public.(*mldsa.PublicKey).Bytes(), ex.PublicKey) {
				t.Error("[RFC 9964 5] the public key must be the example's encoding")
			}
			writtenPublic, err := PublicJwk(public)
			if err != nil {
				t.Fatal(err)
			}
			if !reflect.DeepEqual(*writtenPublic, publicOnly(ex.PrivateJwk)) {
				t.Errorf("[RFC 9964 3] PublicJwk must give the example jwk without priv\n got %v", *writtenPublic)
			}
			if _, present := (*writtenPublic)["priv"]; present {
				t.Error("[RFC 9964 3] priv MUST NOT be present in a public key")
			}
		})
	}
}

func TestThumbprint_OfEachRFC9964ExampleIsItsKid(t *testing.T) {
	for _, ex := range rfc9964(t) {
		t.Run(ex.Alg, func(t *testing.T) {
			for name, jwk := range map[string]map[string]any{"private": ex.PrivateJwk, "public": publicOnly(ex.PrivateJwk)} {
				got, err := Thumbprint(jwk)
				if err != nil || got != ex.PrivateJwk["kid"] {
					t.Errorf("[RFC 9964 6] the thumbprint of the %s example jwk over alg, kty and pub must be its kid %v, got %q and %v", name, ex.PrivateJwk["kid"], got, err)
				}
			}
		})
	}
}

func TestPublicFromJwk_ReadsThePublicKeyOfAPrivateAKPJwk(t *testing.T) {
	ex := rfc9964(t)[0]
	public, err := PublicFromJwk(ex.PrivateJwk)
	if err != nil || !bytes.Equal(public.(*mldsa.PublicKey).Bytes(), ex.PublicKey) {
		t.Errorf("[RFC 7517 8.1] a private jwk also carries the public members, so its public key is read as for EC and RSA, got %v", err)
	}
}

func TestAKPJwk_RefusesAKeyItCannotUse(t *testing.T) {
	examples := rfc9964(t)
	ex := examples[0]
	with := func(member string, value any) map[string]any {
		jwk := maps.Clone(ex.PrivateJwk)
		if value == nil {
			delete(jwk, member)
		} else {
			jwk[member] = value
		}
		return jwk
	}
	b64 := base64.RawURLEncoding.EncodeToString
	pub := ex.PublicKey
	seed := ex.Seed

	shared := map[string]struct {
		jwk                  map[string]any
		wantPublic, wantPriv error
		clause               string
	}{
		"no alg":                           {with("alg", nil), joseerror.ErrInvalidPublicKey, joseerror.ErrInvalidPrivateKey, "RFC 9964 3"},
		"a numeric alg":                    {with("alg", 44), joseerror.ErrInvalidPublicKey, joseerror.ErrInvalidPrivateKey, "RFC 9964 3"},
		"an alg that is not ML-DSA":        {with("alg", "SLH-DSA-SHA2-128s"), joseerror.ErrUnsupportedAlgorithm, joseerror.ErrUnsupportedAlgorithm, "RFC 9964 5"},
		"HashML-DSA":                       {with("alg", "HashML-DSA-44"), joseerror.ErrUnsupportedAlgorithm, joseerror.ErrUnsupportedAlgorithm, "RFC 9964 7.2"},
		"a lowercase alg":                  {with("alg", "ml-dsa-44"), joseerror.ErrUnsupportedAlgorithm, joseerror.ErrUnsupportedAlgorithm, "RFC 7515 4.1.1"},
		"no pub":                           {with("pub", nil), joseerror.ErrInvalidPublicKey, joseerror.ErrInvalidPrivateKey, "RFC 9964 3"},
		"an empty pub":                     {with("pub", ""), joseerror.ErrInvalidPublicKey, joseerror.ErrInvalidPrivateKey, "RFC 9964 5"},
		"a pub one byte short":             {with("pub", b64(pub[:len(pub)-1])), joseerror.ErrInvalidPublicKey, joseerror.ErrInvalidPrivateKey, "RFC 9964 5"},
		"a pub one byte over":              {with("pub", b64(append(bytes.Clone(pub), 0))), joseerror.ErrInvalidPublicKey, joseerror.ErrInvalidPrivateKey, "RFC 9964 5"},
		"an ML-DSA-65 pub named ML-DSA-44": {with("pub", b64(examples[1].PublicKey)), joseerror.ErrInvalidPublicKey, joseerror.ErrInvalidPrivateKey, "RFC 9964 5"},
		"a padded pub":                     {with("pub", base64.URLEncoding.EncodeToString(pub)), joseerror.ErrInvalidPublicKey, joseerror.ErrInvalidPrivateKey, "RFC 7515 2"},
		"a pub in standard base64":         {with("pub", base64.RawStdEncoding.EncodeToString(bytes.Repeat([]byte{0xfb, 0xff}, len(pub)/2))), joseerror.ErrInvalidPublicKey, joseerror.ErrInvalidPrivateKey, "RFC 7515 2"},
	}
	for name, tc := range shared {
		t.Run("public: "+name, func(t *testing.T) {
			key, err := PublicFromJwk(publicOnly(tc.jwk))
			if !errors.Is(err, tc.wantPublic) || key != nil {
				t.Errorf("[%s] want %v and no key, got %v and %v", tc.clause, tc.wantPublic, key, err)
			}
		})
		t.Run("private: "+name, func(t *testing.T) {
			key, err := PrivateFromJwk(tc.jwk)
			if !errors.Is(err, tc.wantPriv) || key != nil {
				t.Errorf("[%s] want %v and no key, got %v and %v", tc.clause, tc.wantPriv, key, err)
			}
		})
	}

	privateOnly := map[string]struct {
		jwk    map[string]any
		clause string
	}{
		"no priv":                  {with("priv", nil), "RFC 9964 4"},
		"an empty priv":            {with("priv", ""), "RFC 9964 4"},
		"a priv one byte short":    {with("priv", b64(seed[:31])), "RFC 9964 7.3"},
		"a priv one byte over":     {with("priv", b64(append(bytes.Clone(seed), 0))), "RFC 9964 7.3"},
		"an expanded private key":  {with("priv", b64(make([]byte, 2560))), "RFC 9964 4"},
		"a pub that is not priv's": {with("pub", b64(flipLast(pub))), "RFC 9964 7.4"},
		"a pub of another seed":    {with("priv", b64(bytes.Repeat([]byte{1}, 32))), "RFC 9964 7.4"},
	}
	for name, tc := range privateOnly {
		t.Run("private: "+name, func(t *testing.T) {
			key, err := PrivateFromJwk(tc.jwk)
			if !errors.Is(err, joseerror.ErrInvalidPrivateKey) || key != nil {
				t.Errorf("[%s] want ErrInvalidPrivateKey and no key, got %v and %v", tc.clause, key, err)
			}
		})
	}
}

func flipLast(b []byte) []byte {
	flipped := bytes.Clone(b)
	flipped[len(flipped)-1] ^= 1
	return flipped
}

func TestAKPProducers_RefuseAKeyTheyCannotEncode(t *testing.T) {
	examples := rfc9964(t)
	for name, key := range map[string]*mldsa.PublicKey{"nil": nil, "zero-value": {}} {
		t.Run("public "+name, func(t *testing.T) {
			jwk, err := PublicJwk(key)
			if !errors.Is(err, joseerror.ErrInvalidPublicKey) || jwk != nil {
				t.Errorf("[RFC 9964 3] a %s ML-DSA public key has no pub to encode, so it must be refused with ErrInvalidPublicKey, got %v and %v", name, jwk, err)
			}
		})
	}
	for name, key := range map[string]*mldsa.PrivateKey{"nil": nil, "zero-value": {}} {
		t.Run("private "+name, func(t *testing.T) {
			jwk, err := PrivateJwk(key)
			if !errors.Is(err, joseerror.ErrInvalidPrivateKey) || jwk != nil {
				t.Errorf("[RFC 9964 4] a %s ML-DSA private key has no seed to encode, so it must be refused with ErrInvalidPrivateKey, got %v and %v", name, jwk, err)
			}
		})
	}
	for _, ex := range examples {
		params := map[string]mldsa.Parameters{"ML-DSA-44": mldsa.MLDSA44(), "ML-DSA-65": mldsa.MLDSA65(), "ML-DSA-87": mldsa.MLDSA87()}[ex.Alg]
		generated, err := mldsa.GenerateKey(params)
		if err != nil {
			t.Fatal(err)
		}
		jwk, err := PrivateJwk(generated)
		if err != nil || (*jwk)["alg"] != ex.Alg {
			t.Errorf("[RFC 9964 3] a generated %s key must be written with alg %s, got %v and %v", ex.Alg, ex.Alg, jwk, err)
		}
	}
}
