package jwk

import (
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/mldsa"
	"crypto/rand"
	"crypto/rsa"
	"errors"
	"slices"
	"testing"

	"github.com/MichaelFraser99/go-jose/internal/algorithms/common"
	"github.com/MichaelFraser99/go-jose/joseerror"
	"github.com/MichaelFraser99/go-jose/model"
)

func mustMember(t *testing.T, jwk map[string]any, err error) map[string]any {
	t.Helper()
	if err != nil {
		t.Fatal(err)
	}
	delete(jwk, "kid")
	return jwk
}

func ecMember(t *testing.T, curve elliptic.Curve) map[string]any {
	t.Helper()
	key, err := ecdsa.GenerateKey(curve, rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	jwk, err := common.JwkFromECDSAPublicKey(&key.PublicKey)
	return mustMember(t, jwk, err)
}

func mldsaMember(t *testing.T, params mldsa.Parameters) map[string]any {
	t.Helper()
	key, err := mldsa.GenerateKey(params)
	if err != nil {
		t.Fatal(err)
	}
	jwk, err := common.JwkFromMLDSAPublicKey(key.PublicKey())
	return mustMember(t, jwk, err)
}

func TestSelectKeys_AMemberIsSelectedOnlyForAnAlgItsKeyTypeServes(t *testing.T) {
	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	rsaJwk, err := common.JwkFromRSAPublicKey(&rsaKey.PublicKey)
	edPublic, _, err2 := ed25519.GenerateKey(rand.Reader)
	if err2 != nil {
		t.Fatal(err2)
	}
	edJwk, edErr := common.JwkFromEdDSAPublicKey(&edPublic)
	xKey, err3 := ecdh.X25519().GenerateKey(rand.Reader)
	if err3 != nil {
		t.Fatal(err3)
	}
	xJwk, xErr := common.JwkFromECDHPublicKey(xKey.PublicKey())

	members := map[string]map[string]any{
		"EC P-256":    ecMember(t, elliptic.P256()),
		"EC P-384":    ecMember(t, elliptic.P384()),
		"EC P-521":    ecMember(t, elliptic.P521()),
		"RSA":         mustMember(t, rsaJwk, err),
		"OKP Ed25519": mustMember(t, edJwk, edErr),
		"OKP X25519":  mustMember(t, xJwk, xErr),
		"oct":         {"kty": "oct", "k": "c2VjcmV0LXNlY3JldC1zZWNyZXQtc2VjcmV0LXNlY3JldC0"},
		"AKP 44":      mldsaMember(t, mldsa.MLDSA44()),
		"AKP 65":      mldsaMember(t, mldsa.MLDSA65()),
		"AKP 87":      mldsaMember(t, mldsa.MLDSA87()),
	}
	serves := map[string][]string{
		"ES256":     {"EC P-256"},
		"ES384":     {"EC P-384"},
		"ES512":     {"EC P-521"},
		"RS256":     {"RSA"},
		"RS384":     {"RSA"},
		"RS512":     {"RSA"},
		"PS256":     {"RSA"},
		"PS384":     {"RSA"},
		"PS512":     {"RSA"},
		"HS256":     nil,
		"HS384":     nil,
		"HS512":     nil,
		"EdDSA":     {"OKP Ed25519"},
		"Ed25519":   {"OKP Ed25519"},
		"ML-DSA-44": {"AKP 44"},
		"ML-DSA-65": {"AKP 65"},
		"ML-DSA-87": {"AKP 87"},
	}
	clause := map[string]string{
		"ES256": "RFC 7518 3.4", "ES384": "RFC 7518 3.4", "ES512": "RFC 7518 3.4",
		"RS256": "RFC 7518 3.3", "RS384": "RFC 7518 3.3", "RS512": "RFC 7518 3.3",
		"PS256": "RFC 7518 3.5", "PS384": "RFC 7518 3.5", "PS512": "RFC 7518 3.5",
		"HS256": "RFC 7518 6.4", "HS384": "RFC 7518 6.4", "HS512": "RFC 7518 6.4",
		"EdDSA": "RFC 8037 3.1", "Ed25519": "RFC 9864 2.2",
		"ML-DSA-44": "RFC 9964 3", "ML-DSA-65": "RFC 9964 3", "ML-DSA-87": "RFC 9964 3",
	}

	for alg, servers := range serves {
		for name, member := range members {
			t.Run(alg+" with "+name, func(t *testing.T) {
				selected := SelectKeys(model.Jwks{Keys: []map[string]any{member}}, nil, alg, false, false)
				if want := slices.Contains(servers, name); want != (len(selected) == 1) {
					t.Errorf("[%s] a %s member serving %s: want selected %v, got %d keys", clause[alg], name, alg, want, len(selected))
				}
			})
		}
	}
}

func TestCheckMember_AKeyTypeThatCannotServeTheAlgIsNotAMatch(t *testing.T) {
	tests := map[string]struct {
		jwk    map[string]any
		alg    string
		clause string
	}{
		"an RSA jwk for ES256":          {jwk: map[string]any{"kty": "RSA"}, alg: "ES256", clause: "RFC 7518 3.4"},
		"an EC P-384 jwk for ES256":     {jwk: map[string]any{"kty": "EC", "crv": "P-384"}, alg: "ES256", clause: "RFC 7518 3.4"},
		"an EC jwk for RS256":           {jwk: map[string]any{"kty": "EC", "crv": "P-256"}, alg: "RS256", clause: "RFC 7518 3.3"},
		"an RSA jwk for HS256":          {jwk: map[string]any{"kty": "RSA"}, alg: "HS256", clause: "RFC 7518 3.2"},
		"an OKP X25519 jwk for EdDSA":   {jwk: map[string]any{"kty": "OKP", "crv": "X25519"}, alg: "EdDSA", clause: "RFC 8037 3.1"},
		"an OKP X25519 jwk for Ed25519": {jwk: map[string]any{"kty": "OKP", "crv": "X25519"}, alg: "Ed25519", clause: "RFC 9864 2.2"},
		"an AKP jwk for PS256":          {jwk: map[string]any{"kty": "AKP"}, alg: "PS256", clause: "RFC 7518 3.5"},
		"an OKP Ed25519 jwk for ES256":  {jwk: map[string]any{"kty": "OKP", "crv": "Ed25519"}, alg: "ES256", clause: "RFC 7518 3.4"},
	}
	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			if err := checkMember(tc.jwk, nil, tc.alg, false, false); !errors.Is(err, joseerror.ErrNoKeyIdentifierMatch) {
				t.Errorf("[%s] a key of this type cannot serve %s, so it is not a match, got %v", tc.clause, tc.alg, err)
			}
		})
	}
}

func TestCheckMember_AKeyTypeOrCurveThisLibraryDoesNotReadIsLeftToTheReader(t *testing.T) {
	tests := map[string]struct {
		jwk map[string]any
		alg string
	}{
		"no kty":            {jwk: map[string]any{}, alg: "ES256"},
		"a kty of a number": {jwk: map[string]any{"kty": 7}, alg: "ES256"},
		"an unknown kty":    {jwk: map[string]any{"kty": "XYZ"}, alg: "ES256"},
		"an unknown EC crv": {jwk: map[string]any{"kty": "EC", "crv": "P-192"}, alg: "ES256"},
		"an EC crv number":  {jwk: map[string]any{"kty": "EC", "crv": 1}, alg: "ES256"},
		"no EC crv":         {jwk: map[string]any{"kty": "EC"}, alg: "ES256"},
		"OKP Ed448":         {jwk: map[string]any{"kty": "OKP", "crv": "Ed448"}, alg: "EdDSA"},
		"an unknown alg":    {jwk: map[string]any{"kty": "RSA"}, alg: "XYZ"},
	}
	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			if err := checkMember(tc.jwk, nil, tc.alg, false, false); err != nil {
				t.Errorf("[RFC 7517 5] a member this library cannot read is reported by the reader, not as a mismatch, got %v", err)
			}
		})
	}
}
