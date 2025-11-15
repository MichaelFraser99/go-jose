package header

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/MichaelFraser99/go-jose/internal/algorithms/common"
	"github.com/MichaelFraser99/go-jose/internal/jose/x5"
	"github.com/MichaelFraser99/go-jose/model"
	"math/big"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestValidateHeader(t *testing.T) {
	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("Failed to generate test rsaKey: %s", err)
	}
	rsaJwk := common.JwkFromRSAPublicKey(rsaKey.Public().(*rsa.PublicKey))
	psJwk := common.JwkFromRSAPublicKey(rsaKey.Public().(*rsa.PublicKey))
	psJwk["alg"] = "PS256"

	certificates, certificateKeys, err := generateCertificateChain(t, 5)
	if err != nil {
		t.Fatalf("Failed to generate test certificate chain: %s", err)
	}

	var encodedCertificates []string
	for _, cert := range certificates {
		encodedCertificates = append(encodedCertificates, base64.StdEncoding.EncodeToString(cert))
	}

	var jwkKeysArray []crypto.PublicKey
	keySet := model.Jwks{}

	for i := 0; i < 5; i++ {
		var entry map[string]any
		if i%2 == 0 {
			k, err := rsa.GenerateKey(rand.Reader, 2048)
			if err != nil {
				t.Fatalf("Failed to generate test rsa rsaKey: %s", err)
			}
			jwkKeysArray = append(jwkKeysArray, k.Public())
			entry = common.JwkFromRSAPublicKey(k.Public().(*rsa.PublicKey))
		} else {
			k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
			if err != nil {
				t.Fatalf("Failed to generate test ec rsaKey: %s", err)
			}
			jwkKeysArray = append(jwkKeysArray, k.Public())
			entry = common.JwkFromECDSAPublicKey(k.Public().(*ecdsa.PublicKey))
		}

		keySet.Keys = append(keySet.Keys, entry)
	}
	jwkKeysArray = append(jwkKeysArray, rsaKey.Public())
	jwkKeysArray = append(jwkKeysArray, rsaKey.Public()) //twice - once for RS and once for PS entry
	keySet.Keys = append(keySet.Keys, rsaJwk)
	keySet.Keys = append(keySet.Keys, psJwk)

	m := http.NewServeMux()
	m.HandleFunc("/jwks", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Add("Content-Type", "application/json+jwk")
		jsonKeyset, err := json.Marshal(keySet)
		if err != nil {
			t.Fatalf("Failed to marshal keyset: %s", err)
		}
		_, err = w.Write(jsonKeyset)
		if err != nil {
			t.Fatalf("Failed to write response: %s", err)
		}
	})
	m.HandleFunc("/certs", func(w http.ResponseWriter, r *http.Request) {
		for i := range certificates {
			_, err := w.Write(certificates[len(certificates)-i-1])
			if err != nil {
				t.Fatalf("Failed to write response: %s", err)
			}
		}
	})
	testServer := httptest.NewTLSServer(m)

	certPool := x509.NewCertPool()
	certPool.AddCert(testServer.Certificate())

	trustingClient := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				RootCAs: certPool,
			},
		},
	}

	tests := map[string]struct {
		protectedHeader map[string]any
		client          *http.Client
		retrievedKeys   [][]crypto.PublicKey
		errMsg          string
		errTypes        []error
	}{
		"happy path - jwk": {
			protectedHeader: map[string]any{
				"alg": "RS256",
				"jwk": rsaJwk,
			},
			retrievedKeys: [][]crypto.PublicKey{
				{rsaKey.Public()},
			},
		},
		"happy path - jku": {
			protectedHeader: map[string]any{
				"alg": "RS256",
				"jku": fmt.Sprintf("%s/jwks", testServer.URL),
			},
			client: trustingClient,
			retrievedKeys: [][]crypto.PublicKey{
				jwkKeysArray,
			},
		},
		"happy path - jku with specified kid": {
			protectedHeader: map[string]any{
				"alg": "RS256",
				"kid": rsaJwk["kid"],
				"jku": fmt.Sprintf("%s/jwks", testServer.URL),
			},
			client: trustingClient,
			retrievedKeys: [][]crypto.PublicKey{
				{rsaKey.Public(), rsaKey.Public()}, //twice because we include one for RS and one for PS
			},
		},
		"happy path - jku with kid and specified alg": {
			protectedHeader: map[string]any{
				"alg": "PS256",
				"kid": psJwk["kid"],
				"jku": fmt.Sprintf("%s/jwks", testServer.URL),
			},
			client: trustingClient,
			retrievedKeys: [][]crypto.PublicKey{
				{rsaKey.Public()}, //once as we include the alg claim specifically in the PS jwk
			},
		},
		"happy path - jwk & jku": {
			protectedHeader: map[string]any{
				"alg": "RS256",
				"jwk": rsaJwk,
				"jku": fmt.Sprintf("%s/jwks", testServer.URL),
			},
			client: trustingClient,
			retrievedKeys: [][]crypto.PublicKey{
				{rsaKey.Public()},
				jwkKeysArray,
			},
		},
		"happy path - x5c just signing certificate": {
			protectedHeader: map[string]any{
				"alg": "RS256",
				"x5c": []string{encodedCertificates[0]},
			},
			retrievedKeys: [][]crypto.PublicKey{
				{certificateKeys[0]},
			},
		},
		"happy path - x5c with x5t": {
			protectedHeader: map[string]any{
				"alg": "RS256",
				"x5c": []string{encodedCertificates[0]},
				"x5t": x5.CalculateX5t(certificates[0]),
			},
			retrievedKeys: [][]crypto.PublicKey{
				{certificateKeys[0]},
			},
		},
		"happy path - x5c with x5ts256": {
			protectedHeader: map[string]any{
				"alg":      "RS256",
				"x5c":      []string{encodedCertificates[0]},
				"x5t#S256": x5.CalculateX5tS256(certificates[0]),
			},
			retrievedKeys: [][]crypto.PublicKey{
				{certificateKeys[0]},
			},
		},
		"happy path - x5c with x5t and x5ts256": {
			protectedHeader: map[string]any{
				"alg":      "RS256",
				"x5c":      []string{encodedCertificates[0]},
				"x5t":      x5.CalculateX5t(certificates[0]),
				"x5t#S256": x5.CalculateX5tS256(certificates[0]),
			},
			retrievedKeys: [][]crypto.PublicKey{
				{certificateKeys[0]},
			},
		},
		"happy path - x5c signing and intermediates": {
			protectedHeader: map[string]any{
				"alg": "RS256",
				"x5c": []string{encodedCertificates[2], encodedCertificates[1], encodedCertificates[0]},
			},
			retrievedKeys: [][]crypto.PublicKey{
				{certificateKeys[2]},
			},
		},
		"happy path - x5c full chain": {
			protectedHeader: map[string]any{
				"alg": "RS256",
				"x5c": []string{encodedCertificates[4], encodedCertificates[3], encodedCertificates[2], encodedCertificates[1], encodedCertificates[0]},
			},
			retrievedKeys: [][]crypto.PublicKey{
				{certificateKeys[4]},
			},
		},
		"happy path - x5u full chain": {
			protectedHeader: map[string]any{
				"alg": "RS256",
				"x5u": fmt.Sprintf("%s/certs", testServer.URL),
			},
			client: trustingClient,
			retrievedKeys: [][]crypto.PublicKey{
				{certificateKeys[4]},
			},
		},
		"happy path - all": {
			protectedHeader: map[string]any{
				"alg":      "RS256",
				"jwk":      rsaJwk,
				"jku":      fmt.Sprintf("%s/jwks", testServer.URL),
				"x5c":      []string{encodedCertificates[4]},
				"x5u":      fmt.Sprintf("%s/certs", testServer.URL),
				"x5t":      x5.CalculateX5t(certificates[4]),
				"x5t#S256": x5.CalculateX5tS256(certificates[4]),
			},
			client: trustingClient,
			retrievedKeys: [][]crypto.PublicKey{
				{rsaKey.Public()},
				{certificateKeys[4]},
				jwkKeysArray,
				{certificateKeys[4]},
			},
		},
	}

	for testName, test := range tests {
		t.Run(testName, func(t *testing.T) {
			retrievers, err := ValidateHeader(test.protectedHeader, test.client, model.JWS) //todo extract mode and test for both
			if err != nil {
				if test.errMsg == "" {
					t.Fatalf("unexpected error: %v", err)
				}
				if test.errMsg != err.Error() {
					t.Fatalf("expected error text %s, got %s", test.errMsg, err.Error())
				}
				for _, errType := range test.errTypes {
					if !errors.Is(err, errType) {
						t.Fatalf("thrown error does not have all types expected")
					}
				}
			} else {
				if test.errMsg != "" {
					t.Fatalf("expected error %s, got nil", test.errMsg)
				}
				if len(retrievers) != len(test.retrievedKeys) {
					t.Fatalf("expected %d retrievers, got %d", len(test.retrievedKeys), len(retrievers))
				}
				for i, retriever := range retrievers {
					keys, err := retriever()
					if err != nil {
						t.Fatalf("unexpected error calling retriever index %d: %s", i, err)
					}
					if len(keys) != len(test.retrievedKeys[i]) {
						t.Fatalf("expected %d keys, got %d index: %d", len(test.retrievedKeys[i]), len(keys), i)
					}
					for ii, k := range keys {
						if castK, ok := k.(*rsa.PublicKey); ok {
							if !castK.Equal(test.retrievedKeys[i][ii]) {
								t.Errorf("unexpected element returned in keyset, got: %v, expected: %v", *castK, test.retrievedKeys[i][ii])
							}
						} else if castK, ok := k.(*ecdsa.PublicKey); ok {
							if !castK.Equal(test.retrievedKeys[i][ii]) {
								t.Errorf("unexpected element returned in keyset, got: %v, expected: %v", *castK, test.retrievedKeys[i][ii])
							}
						} else {
							t.Fatalf("element returned is not a value RSA or EC public rsaKey")
						}
					}
				}
			}
		})
	}
}

func generateCertificateChain(t *testing.T, numCerts int) ([][]byte, []crypto.PublicKey, error) {
	t.Helper()
	var keys []crypto.PublicKey
	rootKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("failed to generate root key: %v", err)
	}
	keys = append(keys, rootKey.Public())

	rootDistinguishedName := pkix.Name{
		Country:            []string{"GB"},
		Organization:       []string{"My Organization"},
		OrganizationalUnit: []string{"My Organizational Unit"},
		Locality:           []string{"My Locality"},
		Province:           []string{"My Province"},
		StreetAddress:      []string{"My Street Address"},
		PostalCode:         []string{"My Postal Code"},
		SerialNumber:       "My Serial Number",
		CommonName:         "My Common Name",
		Names:              nil,
		ExtraNames:         nil,
	}

	rootTemplate := x509.Certificate{
		SerialNumber:          big.NewInt(2019),
		Subject:               rootDistinguishedName,
		NotBefore:             time.Now(),
		NotAfter:              time.Now().AddDate(10, 0, 0),
		IsCA:                  true,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
	}

	rootBytes, err := x509.CreateCertificate(rand.Reader, &rootTemplate, &rootTemplate, rootKey.Public(), rootKey)
	if err != nil {
		t.Fatalf("failed to create root certificate: %v", err)
	}

	parentKey := rootKey
	parent := rootTemplate
	var intermediates [][]byte
	for i := 1; i < numCerts; i++ {
		certKey, err := rsa.GenerateKey(rand.Reader, 2048)
		if err != nil {
			t.Fatalf("failed to generate intermediate %d key: %v", i, err)
		}
		keys = append(keys, certKey.Public())

		certDistinguishedName := pkix.Name{
			Country:            []string{"GB"},
			Organization:       []string{fmt.Sprintf("My Organization %d", i)},
			OrganizationalUnit: []string{fmt.Sprintf("My Organizational Unit Intermediate %d", i)},
			Locality:           []string{fmt.Sprintf("My Locality %d", i)},
			Province:           []string{fmt.Sprintf("My Province %d", i)},
			StreetAddress:      []string{fmt.Sprintf("My Street Address %d", i)},
			PostalCode:         []string{fmt.Sprintf("My Postal Code %d", i)},
			SerialNumber:       fmt.Sprintf("My Serial Number %d", i),
			CommonName:         fmt.Sprintf("My Common Name %d", i),
			Names:              nil,
			ExtraNames:         nil,
		}

		certTemplate := x509.Certificate{
			SerialNumber:          big.NewInt(int64(2019 + i)),
			Subject:               certDistinguishedName,
			NotBefore:             time.Now(),
			NotAfter:              time.Now().AddDate(1, 0, 0),
			IsCA:                  i != numCerts-1,
			ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},
			KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
			BasicConstraintsValid: true,
		}

		certBytes, err := x509.CreateCertificate(rand.Reader, &certTemplate, &parent, certKey.Public(), parentKey)
		if err != nil {
			t.Fatalf("failed to create intermediate %d certificate: %v", i, err)
		}
		intermediates = append(intermediates, certBytes)
		parent = certTemplate
		parentKey = certKey
	}

	return append([][]byte{rootBytes}, intermediates...), keys, nil
}
