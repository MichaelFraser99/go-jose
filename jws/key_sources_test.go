package jws

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"math/big"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/MichaelFraser99/go-jose/internal/algorithms/common"
	"github.com/MichaelFraser99/go-jose/jwa"
	"github.com/MichaelFraser99/go-jose/model"
)

func p256(t *testing.T) *ecdsa.PrivateKey {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return key
}

func certificate(t *testing.T, subject string, key *ecdsa.PrivateKey, issuer *x509.Certificate, issuerKey *ecdsa.PrivateKey) *x509.Certificate {
	t.Helper()
	template := &x509.Certificate{
		SerialNumber:          big.NewInt(time.Now().UnixNano()),
		Subject:               pkix.Name{CommonName: subject},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		IsCA:                  issuer == nil,
		BasicConstraintsValid: true,
	}
	if issuer == nil {
		issuer, issuerKey = template, key
	}
	der, err := x509.CreateCertificate(rand.Reader, template, issuer, &key.PublicKey, issuerKey)
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return parsed
}

func es256Token(t *testing.T, key *ecdsa.PrivateKey, head map[string]any) string {
	t.Helper()
	head["alg"] = "ES256"
	headBytes, err := json.Marshal(head)
	if err != nil {
		t.Fatal(err)
	}
	signer, err := GetSignerFromPrivateKey(jwa.ES256, key)
	if err != nil {
		t.Fatal(err)
	}
	input := base64.RawURLEncoding.EncodeToString(headBytes) + "." + base64.RawURLEncoding.EncodeToString([]byte(`{"sub":"test"}`))
	signature, err := signer.Sign(rand.Reader, []byte(input), nil)
	if err != nil {
		t.Fatal(err)
	}
	return input + "." + base64.RawURLEncoding.EncodeToString(signature)
}

func TestVerifyCompactSerialization_EachHeaderKeySourceNeedsItsOwnAnchor(t *testing.T) {
	rootKey, leafKey, attackerKey := p256(t), p256(t), p256(t)
	root := certificate(t, "root", rootKey, nil, nil)
	leaf := certificate(t, "leaf", leafKey, root, rootKey)
	roots := x509.NewCertPool()
	roots.AddCert(root)

	x5cToken := es256Token(t, leafKey, map[string]any{"x5c": []string{base64.StdEncoding.EncodeToString(leaf.Raw)}})
	jwkToken := es256Token(t, attackerKey, map[string]any{"jwk": common.JwkFromECDSAPublicKey(&attackerKey.PublicKey)})

	tests := map[string]struct {
		token     string
		opts      *model.JoseOptions
		verifies  bool
		reference string
	}{
		"x5c with roots and nothing else": {
			token: x5cToken, opts: &model.JoseOptions{X509Roots: roots}, verifies: true,
			reference: "RFC 7515 4.1.6",
		},
		"x5c opted in but with no roots": {
			token: x5cToken, opts: &model.JoseOptions{UseTokenProvidedKeys: true},
			reference: "RFC 7515 4.1.6",
		},
		"a self-asserted jwk when the caller configured roots for x5c": {
			token: jwkToken, opts: &model.JoseOptions{X509Roots: roots},
			reference: "RFC 7515 10.3",
		},
		"a self-asserted jwk once the caller opts in": {
			token: jwkToken, opts: &model.JoseOptions{UseTokenProvidedKeys: true}, verifies: true,
			reference: "JoseOptions.UseTokenProvidedKeys",
		},
	}

	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			_, _, err := VerifyCompactSerialization(test.token, nil, test.opts)
			if test.verifies && err != nil {
				t.Errorf("[%s] expected the token to verify, got %v", test.reference, err)
			}
			if !test.verifies && err == nil {
				t.Errorf("[%s] configuring the anchor for one source must not admit another, so this token must not verify", test.reference)
			}
		})
	}
}

func TestVerifyCompactSerialization_AnX5uIsUsedWithRootsAndAClientAlone(t *testing.T) {
	rootKey, leafKey := p256(t), p256(t)
	root := certificate(t, "root", rootKey, nil, nil)
	leaf := certificate(t, "leaf", leafKey, root, rootKey)
	roots := x509.NewCertPool()
	roots.AddCert(root)

	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		if _, err := w.Write(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: leaf.Raw})); err != nil {
			return
		}
	}))
	defer server.Close()

	token := es256Token(t, leafKey, map[string]any{"x5u": server.URL})
	if _, _, err := VerifyCompactSerialization(token, nil, &model.JoseOptions{X509Roots: roots, HttpClient: server.Client()}); err != nil {
		t.Errorf("[RFC 7515 4.1.5] a chain that validates against the configured roots authenticates the key, so x5u needs no further opt-in, got %v", err)
	}
}

func TestVerifyCompactSerialization_OnceOptedInEitherTheCallersKeyOrAHeaderKeyMayVerify(t *testing.T) {
	callersKey, headerKey := p256(t), p256(t)
	retriever := func() ([]crypto.PublicKey, error) { return []crypto.PublicKey{&callersKey.PublicKey}, nil }
	head := func() map[string]any {
		return map[string]any{"jwk": common.JwkFromECDSAPublicKey(&headerKey.PublicKey)}
	}

	tests := map[string]*ecdsa.PrivateKey{
		"signed by the caller's key": callersKey,
		"signed by the header's key": headerKey,
	}

	for name, signingKey := range tests {
		t.Run(name, func(t *testing.T) {
			token := es256Token(t, signingKey, head())
			if _, _, err := VerifyCompactSerialization(token, retriever, &model.JoseOptions{UseTokenProvidedKeys: true}); err != nil {
				t.Errorf("[JoseOptions.UseTokenProvidedKeys] a caller who opts in with a retriever accepts either source, got %v", err)
			}
		})
	}
}
