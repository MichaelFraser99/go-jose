package common

import (
	"crypto/rsa"
	"math/big"
	"testing"
)

func FuzzCompleteRSAPrivateKey_ReturnsOnlyAKeyThatValidates(f *testing.F) {
	f.Add([]byte{1}, []byte{3}, []byte{5}, []byte{7}, false)
	f.Add([]byte{0xff}, []byte{0}, []byte{1}, []byte{1}, true)
	f.Fuzz(func(t *testing.T, nTail, d, p, q []byte, withPrimes bool) {
		nBytes := make([]byte, MinimumRSAModulusBits/8)
		nBytes[0] = 0x80
		copy(nBytes[len(nBytes)-min(len(nTail), len(nBytes)-1):], nTail)
		key := &rsa.PrivateKey{PublicKey: rsa.PublicKey{N: new(big.Int).SetBytes(nBytes), E: 65537}, D: new(big.Int).SetBytes(d)}
		if withPrimes {
			key.Primes = []*big.Int{new(big.Int).SetBytes(p), new(big.Int).SetBytes(q)}
		}
		completed, err := CompleteRSAPrivateKey(key)
		if err != nil {
			if completed != nil {
				t.Fatalf("[RFC 8017 3.2] a refused key must not be returned, got %v", err)
			}
			return
		}
		if err := completed.Validate(); err != nil {
			t.Fatalf("[RFC 8017 3.2] a key returned must be one key, got %v", err)
		}
	})
}
