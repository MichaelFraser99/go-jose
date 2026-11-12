package x5

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"math/big"
	"strings"
	"testing"
	"time"

	"github.com/MichaelFraser99/go-jose/joseerror"
)

func boundedChainCertificate(t *testing.T, subject, issuer string, signer *ecdsa.PrivateKey, public *ecdsa.PublicKey, ca bool) *x509.Certificate {
	template := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: subject},
		Issuer:                pkix.Name{CommonName: issuer},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		BasicConstraintsValid: true,
		IsCA:                  ca,
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
	}
	parent := template
	if !ca {
		parent = &x509.Certificate{Subject: pkix.Name{CommonName: issuer}}
	}
	der, err := x509.CreateCertificate(rand.Reader, template, parent, public, signer)
	if err != nil {
		t.Fatal(err)
	}
	certificate, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return certificate
}

func TestValidateCertificateChain_AChainThatDoesNotValidateEchoesNoUnboundedPeerText(t *testing.T) {
	newKey := func() *ecdsa.PrivateKey {
		key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		return key
	}
	issuerKey, impostorKey, leafKey, rootKey := newKey(), newKey(), newKey(), newKey()
	hugeName := strings.Repeat("A", 100_000) + " injected"
	leaf := boundedChainCertificate(t, "leaf", hugeName, issuerKey, &leafKey.PublicKey, false)
	impostor := boundedChainCertificate(t, hugeName, hugeName, impostorKey, &impostorKey.PublicKey, true)
	roots := x509.NewCertPool()
	roots.AddCert(boundedChainCertificate(t, "root", "root", rootKey, &rootKey.PublicKey, true))

	err := validateCertificateChain([]*x509.Certificate{leaf, impostor}, roots, nil)
	if !errors.Is(err, joseerror.ErrNoKeyIdentifierMatch) {
		t.Fatalf("[RFC 7515 4.1.6] the chain does not validate against the trust anchors, so want ErrNoKeyIdentifierMatch, got %v", err)
	}
	if len(err.Error()) > 512 || strings.Contains(err.Error(), " ") {
		t.Errorf("[RFC 7515 4.1.6] a peer chooses the certificates of the chain, so the error must quote their names bounded, got %d bytes", len(err.Error()))
	}
}
