package jwk

import (
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"errors"
	"maps"
	"math/big"
	"strings"
	"testing"

	"github.com/MichaelFraser99/go-jose/joseerror"
)

func TestPrivateFromJwk_RefusesAPrimeThatIsNotLessThanTheModulus(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	written, err := PrivateJwk(key)
	if err != nil {
		t.Fatal(err)
	}
	huge := new(big.Int).Lsh(big.NewInt(1), 49152)
	huge.Sub(huge, big.NewInt(1))
	encode := func(n *big.Int) string { return base64.RawURLEncoding.EncodeToString(n.Bytes()) }
	tests := map[string]struct {
		member string
		value  *big.Int
	}{
		"a p of 49152 bits":   {"p", huge},
		"a q of 49152 bits":   {"q", huge},
		"a p equal to n":      {"p", key.N},
		"a q equal to n":      {"q", key.N},
		"a p one more than n": {"p", new(big.Int).Add(key.N, big.NewInt(1))},
	}
	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			jwk := maps.Clone(*written)
			jwk[tc.member] = encode(tc.value)
			_, err := PrivateFromJwk(jwk)
			if !errors.Is(err, joseerror.ErrInvalidPrivateKey) {
				t.Fatalf("[RFC 8017 3.2] n is the product of the primes, so a prime that is not less than n must be refused with ErrInvalidPrivateKey, got %v", err)
			}
			if !strings.Contains(err.Error(), "less than n") {
				t.Errorf("[RFC 8017 3.2] the refusal must name the bound a prime breaks, before any primality check, got %v", err)
			}
		})
	}
}
