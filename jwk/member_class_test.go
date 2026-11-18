package jwk

import (
	"crypto"
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/mldsa"
	"crypto/rand"
	"crypto/rsa"
	"errors"
	"maps"
	"strings"
	"testing"

	"github.com/MichaelFraser99/go-jose/joseerror"
)

func TestFromJwk_EveryRefusedMemberMatchesTheClassOfTheKeyRead(t *testing.T) {
	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	ecKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	_, edKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	xKey, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	mlKey, err := mldsa.GenerateKey(mldsa.MLDSA44())
	if err != nil {
		t.Fatal(err)
	}
	privateJwkOf := func(key crypto.PrivateKey) map[string]any {
		written, err := PrivateJwk(key)
		if err != nil {
			t.Fatal(err)
		}
		return *written
	}

	type reader struct {
		name    string
		class   error
		read    func(map[string]any) error
		members []string
	}
	private := func(members ...string) reader {
		return reader{"PrivateFromJwk", joseerror.ErrInvalidPrivateKey, func(m map[string]any) error { _, err := PrivateFromJwk(m); return err }, members}
	}
	public := func(members ...string) reader {
		return reader{"PublicFromJwk", joseerror.ErrInvalidPublicKey, func(m map[string]any) error { _, err := PublicFromJwk(m); return err }, members}
	}
	keys := []struct {
		name    string
		jwk     map[string]any
		readers []reader
	}{
		{"EC", privateJwkOf(ecKey), []reader{private("kty", "crv", "x", "y", "d"), public("kty", "crv", "x", "y")}},
		{"RSA", privateJwkOf(rsaKey), []reader{private("kty", "n", "e", "d", "p", "q", "dp", "dq", "qi"), public("kty", "n", "e")}},
		{"Ed25519", privateJwkOf(edKey), []reader{private("kty", "crv", "x", "d"), public("kty", "crv", "x")}},
		{"X25519", privateJwkOf(xKey), []reader{private("kty", "crv", "x", "d"), public("kty", "crv", "x")}},
		{"AKP", privateJwkOf(mlKey), []reader{private("kty", "alg", "pub", "priv"), public("kty", "alg", "pub")}},
		{"oct", privateJwkOf(make([]byte, 32)), []reader{private("kty", "k")}},
	}
	identifiers := map[string]bool{"kty": true, "crv": true, "alg": true}
	faults := []struct {
		name   string
		apply  func(map[string]any, string)
		member error
		text   bool
	}{
		{"absent", func(m map[string]any, name string) { delete(m, name) }, joseerror.ErrMissingClaim, false},
		{"a number", func(m map[string]any, name string) { m[name] = 7 }, joseerror.ErrMalformedClaim, false},
		{"an object", func(m map[string]any, name string) { m[name] = map[string]any{} }, joseerror.ErrMalformedClaim, false},
		{"null", func(m map[string]any, name string) { m[name] = nil }, joseerror.ErrMalformedClaim, false},
		{"not base64url", func(m map[string]any, name string) { m[name] = "!!!" }, joseerror.ErrMalformedClaim, true},
		{"empty", func(m map[string]any, name string) { m[name] = "" }, nil, true},
		{"another value", func(m map[string]any, name string) { m[name] = "AA" }, nil, true},
	}
	for _, key := range keys {
		for _, r := range key.readers {
			for _, member := range r.members {
				for _, fault := range faults {
					if key.name == "oct" && member == "k" && fault.name == "another value" {
						continue
					}
					t.Run(key.name+"/"+r.name+"/"+member+" "+fault.name, func(t *testing.T) {
						jwk := maps.Clone(key.jwk)
						fault.apply(jwk, member)
						err := r.read(jwk)
						if err == nil {
							t.Fatalf("[RFC 7517 section 6] a %s jwk whose %q is %s must be refused", key.name, member, fault.name)
						}
						if identifiers[member] && fault.text {
							if !errors.Is(err, joseerror.ErrUnsupportedAlgorithm) {
								t.Errorf("[README Key sets] a %q this library does not read must be refused with ErrUnsupportedAlgorithm, got %v", member, err)
							}
							if errors.Is(err, joseerror.ErrInvalidPublicKey) || errors.Is(err, joseerror.ErrInvalidPrivateKey) {
								t.Errorf("[README Key sets] a %q this library does not read is not a fault in the key, so it must not match a key class, got %v", member, err)
							}
							return
						}
						if !errors.Is(err, r.class) {
							t.Errorf("[README Errors] %s must refuse a %s jwk whose %q is %s with %v, got %v", r.name, key.name, member, fault.name, r.class, err)
						}
						_, publicErr := PublicFromJwk(jwk)
						wantPublic := r.name == "PrivateFromJwk" && publicErr != nil && jwk["kty"] != "oct"
						if errors.Is(err, joseerror.ErrInvalidPublicKey) != (r.class == joseerror.ErrInvalidPublicKey || wantPublic) {
							t.Errorf("[README Key sets] %s on a %s jwk whose %q is %s must match ErrInvalidPublicKey exactly when PublicFromJwk refuses that jwk (%v), got %v", r.name, key.name, member, fault.name, publicErr, err)
						}
						if r.name == "PublicFromJwk" && errors.Is(err, joseerror.ErrInvalidPrivateKey) {
							t.Errorf("[README Key sets] PublicFromJwk must not refuse with ErrInvalidPrivateKey, got %v", err)
						}
						if fault.member != nil && !errors.Is(err, fault.member) {
							t.Errorf("[RFC 7517 section 6] a %q that is %s must match %v, got %v", member, fault.name, fault.member, err)
						}
					})
				}
			}
		}
	}
}

func TestPrivateFromJwk_AnRSAJwkWithSomeButNotAllOfItsPrimeMembersNamesTheOneItLacks(t *testing.T) {
	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	written, err := PrivateJwk(rsaKey)
	if err != nil {
		t.Fatal(err)
	}
	optional := []string{"p", "q", "dp", "dq", "qi"}
	for _, kept := range optional {
		t.Run("only "+kept, func(t *testing.T) {
			jwk := maps.Clone(*written)
			for _, name := range optional {
				if name != kept {
					delete(jwk, name)
				}
			}
			_, err := PrivateFromJwk(jwk)
			if !errors.Is(err, joseerror.ErrInvalidPrivateKey) || !errors.Is(err, joseerror.ErrMissingClaim) {
				t.Fatalf("[RFC 7518 6.3.2] a jwk carrying %q must carry all of %v, so it must be refused with ErrInvalidPrivateKey and ErrMissingClaim, got %v", kept, optional, err)
			}
			lacked := "p"
			if kept == "p" {
				lacked = "q"
			}
			if !strings.HasSuffix(err.Error(), "lacks '"+lacked+"'") {
				t.Errorf("[RFC 7518 6.3.2] the error must name %q, the first member the jwk lacks, got %v", lacked, err)
			}
		})
	}
}
