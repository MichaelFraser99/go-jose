package jws_test

import (
	"crypto/rand"
	"crypto/rsa"
	"errors"
	"math/big"
	"strings"
	"testing"

	"github.com/MichaelFraser99/go-jose/joseerror"
	"github.com/MichaelFraser99/go-jose/jwa"
	"github.com/MichaelFraser99/go-jose/jws"
)

func TestGetSignerFromPrivateKey_RefusesAPrimeThatIsNotLessThanTheModulus(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	huge := new(big.Int).Lsh(big.NewInt(1), 49152)
	huge.Sub(huge, big.NewInt(1))
	forged := &rsa.PrivateKey{PublicKey: key.PublicKey, D: key.D, Primes: []*big.Int{huge, key.Primes[1]}}
	signer, err := jws.GetSignerFromPrivateKey(jwa.RS256, forged)
	if signer != nil || !errors.Is(err, joseerror.ErrInvalidPrivateKey) {
		t.Fatalf("[RFC 8017 3.2] a prime that is not less than n must be refused with ErrInvalidPrivateKey and no signer, got %v, %v", signer, err)
	}
	if !strings.Contains(err.Error(), "less than n") {
		t.Errorf("[RFC 8017 3.2] the refusal must name the bound a prime breaks, before any primality check, got %v", err)
	}
}
