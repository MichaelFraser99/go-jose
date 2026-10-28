// Package keycopy copies the key types whose fields a caller can change after
// handing a key to a signer or validator.
package keycopy

import (
	"crypto/ecdsa"
	"crypto/rsa"
	"math/big"
)

// ECDSAPublicKey returns a copy of publicKey that shares no memory with it.
func ECDSAPublicKey(publicKey *ecdsa.PublicKey) *ecdsa.PublicKey {
	return &ecdsa.PublicKey{
		Curve: publicKey.Curve,
		X:     new(big.Int).Set(publicKey.X), //nolint:staticcheck
		Y:     new(big.Int).Set(publicKey.Y), //nolint:staticcheck
	}
}

// ECDSAPrivateKey returns a copy of privateKey that shares no memory with it.
func ECDSAPrivateKey(privateKey *ecdsa.PrivateKey) *ecdsa.PrivateKey {
	return &ecdsa.PrivateKey{
		PublicKey: *ECDSAPublicKey(&privateKey.PublicKey),
		D:         new(big.Int).Set(privateKey.D), //nolint:staticcheck
	}
}

// RSAPublicKey returns a copy of publicKey that shares no memory with it.
func RSAPublicKey(publicKey *rsa.PublicKey) *rsa.PublicKey {
	return &rsa.PublicKey{
		N: new(big.Int).Set(publicKey.N),
		E: publicKey.E,
	}
}

// RSAPrivateKey returns a copy of privateKey that shares no memory with it.
// The copy's precomputed values are derived again from its own primes.
func RSAPrivateKey(privateKey *rsa.PrivateKey) *rsa.PrivateKey {
	primes := make([]*big.Int, len(privateKey.Primes))
	for i, prime := range privateKey.Primes {
		if prime != nil {
			primes[i] = new(big.Int).Set(prime)
		}
	}
	key := &rsa.PrivateKey{
		PublicKey: *RSAPublicKey(&privateKey.PublicKey),
		D:         new(big.Int).Set(privateKey.D),
		Primes:    primes,
	}
	key.Precompute()
	return key
}
