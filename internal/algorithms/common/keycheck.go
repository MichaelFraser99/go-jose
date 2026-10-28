package common

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rsa"
	"fmt"
	"math/big"

	jose_errors "github.com/MichaelFraser99/go-jose/joseerror"
)

// MinimumRSAModulusBits is the smallest modulus the RS and PS algorithms
// accept: RFC 7518 sections 3.3 and 3.5 make a key of 2048 bits or larger a MUST.
const MinimumRSAModulusBits = 2048

// MaximumRSAModulusBits is the largest modulus the RS and PS algorithms
// accept. It bounds the work a peer-chosen key can demand of a verifier, and
// matches the default cap crypto/tls applies to a peer's RSA key.
const MaximumRSAModulusBits = 8192

// MaximumRSAPublicExponent is the largest public exponent the RS and PS
// algorithms accept, the same bound crypto/rsa applies.
const MaximumRSAPublicExponent = 1<<31 - 1

// CheckRSAPublicKey refuses, with the error class given, an RSA public key a
// signature cannot be checked with, whose modulus lies outside
// [MinimumRSAModulusBits, MaximumRSAModulusBits], or whose exponent is not an
// odd integer in [3, MaximumRSAPublicExponent]. RFC 8017 section 3.1 puts e
// between 3 and n - 1 with GCD(e, lambda(n)) = 1, and lambda(n) is even.
func CheckRSAPublicKey(publicKey *rsa.PublicKey, class error) error {
	if err := checkRSAPublicKey(publicKey, class); err != nil {
		return err
	}
	if bits := publicKey.N.BitLen(); bits < MinimumRSAModulusBits || bits > MaximumRSAModulusBits {
		return fmt.Errorf("%wan RSA modulus of %d to %d bits is required, got %d", class, MinimumRSAModulusBits, MaximumRSAModulusBits, bits)
	}
	return nil
}

// CheckRSAPrivateKey refuses an RSA private key whose public half
// CheckRSAPublicKey refuses, or whose private members are not the private key
// of that public half, as PrivateFromJwk judges them. RFC 7518 section 6.3.2
// makes "d" the only required private member, so a key without primes is
// accepted when its d inverts e.
func CheckRSAPrivateKey(privateKey *rsa.PrivateKey) error {
	if privateKey == nil {
		return fmt.Errorf("%wan RSA key needs a positive modulus and exponent", jose_errors.ErrInvalidPrivateKey)
	}
	if err := CheckRSAPublicKey(&privateKey.PublicKey, jose_errors.ErrInvalidPrivateKey); err != nil {
		return err
	}
	return checkRSAPrivateKey(privateKey)
}

func checkRSAPublicKey(publicKey *rsa.PublicKey, class error) error {
	if publicKey == nil || publicKey.N == nil || publicKey.N.Sign() <= 0 {
		return fmt.Errorf("%wan RSA key needs a positive modulus", class)
	}
	if e := publicKey.E; e < 3 || e%2 == 0 || e > MaximumRSAPublicExponent {
		return fmt.Errorf("%wan RSA public exponent is odd and in [3, %d], got %d", class, MaximumRSAPublicExponent, e)
	}
	return nil
}

func checkRSAPrivateKey(privateKey *rsa.PrivateKey) error {
	if privateKey.D == nil || privateKey.D.Sign() <= 0 || privateKey.D.Cmp(privateKey.N) >= 0 {
		return fmt.Errorf("%wthe d of an RSA private key is a positive integer less than n", jose_errors.ErrInvalidPrivateKey)
	}
	if len(privateKey.Primes) == 0 {
		if bits := privateKey.N.BitLen(); bits > MaximumRSAModulusBits {
			return fmt.Errorf("%wthe d of an RSA private key with no primes is checked only up to a %d-bit modulus, got %d", jose_errors.ErrInvalidPrivateKey, MaximumRSAModulusBits, bits)
		}
		return checkRSAPrivateExponent(privateKey)
	}
	for _, prime := range privateKey.Primes {
		if prime == nil || prime.Sign() <= 0 {
			return fmt.Errorf("%wthe primes of an RSA private key must be positive", jose_errors.ErrInvalidPrivateKey)
		}
	}
	candidate := rsa.PrivateKey{PublicKey: privateKey.PublicKey, D: privateKey.D, Primes: privateKey.Primes}
	if err := candidate.Validate(); err != nil {
		return fmt.Errorf("%wthe members of an RSA private key are not one key: %w", jose_errors.ErrInvalidPrivateKey, err)
	}
	return nil
}

// CheckECDSAPublicKey refuses, with the error class given, an ECDSA public key
// that is not a point on curve. RFC 7518 section 3.1 defines each ES algorithm
// by its curve.
func CheckECDSAPublicKey(publicKey *ecdsa.PublicKey, curve elliptic.Curve, class error) error {
	if err := checkECDSAPublicKey(publicKey, class, "curve should be "+curve.Params().Name+", was a curve this library does not support"); err != nil {
		return err
	}
	if publicKey.Curve != curve {
		return fmt.Errorf("%wcurve should be %s, was %s", class, curve.Params().Name, publicKey.Curve.Params().Name)
	}
	return nil
}

// CheckECDSAPrivateKey refuses an ECDSA private key whose public half
// CheckECDSAPublicKey refuses, or whose scalar d is not in [1, n-1].
func CheckECDSAPrivateKey(privateKey *ecdsa.PrivateKey, curve elliptic.Curve) error {
	if privateKey == nil {
		return fmt.Errorf("%wan ECDSA key needs a curve and a point", jose_errors.ErrInvalidPrivateKey)
	}
	if err := CheckECDSAPublicKey(&privateKey.PublicKey, curve, jose_errors.ErrInvalidPrivateKey); err != nil {
		return err
	}
	_, err := checkECDSAPrivateScalar(privateKey)
	return err
}

func checkECDSAPrivateScalar(privateKey *ecdsa.PrivateKey) ([]byte, error) {
	if privateKey.D == nil { //nolint:staticcheck
		return nil, fmt.Errorf("%wan ECDSA private key needs its scalar d", jose_errors.ErrInvalidPrivateKey)
	}
	scalar, err := privateKey.Bytes()
	if err != nil {
		return nil, fmt.Errorf("%wan ECDSA private key's scalar d is in [1, n-1]: %w", jose_errors.ErrInvalidPrivateKey, err)
	}
	if _, err := ecdsaPrivateKeyOfPoint(scalar, &privateKey.PublicKey); err != nil {
		return nil, err
	}
	return scalar, nil
}

func ecdsaPrivateKeyOfPoint(scalar []byte, publicKey *ecdsa.PublicKey) (*ecdsa.PrivateKey, error) {
	privateKey, err := ecdsa.ParseRawPrivateKey(publicKey.Curve, scalar)
	if err != nil {
		return nil, fmt.Errorf("%wthe scalar d of a %s key is %d octets in [1, n-1]: %w", jose_errors.ErrInvalidPrivateKey, publicKey.Params().Name, (publicKey.Params().N.BitLen()+7)/8, err)
	}
	if !privateKey.PublicKey.Equal(publicKey) {
		return nil, fmt.Errorf("%wthe point of an EC key is not the public point of its scalar d", jose_errors.ErrInvalidPrivateKey)
	}
	return privateKey, nil
}

var (
	ed25519FieldPrime         = new(big.Int).Sub(new(big.Int).Lsh(big.NewInt(1), 255), big.NewInt(19))
	ed25519FieldPrimeMinusOne = new(big.Int).Sub(ed25519FieldPrime, big.NewInt(1))
)

// CheckEd25519PublicKey refuses, with the error class given, an Ed25519 public
// key that is not 32 octets or not the canonical encoding of a point. RFC 8032
// section 5.1.3 fails decoding when y is p or more, and when x is 0 but its
// sign bit is set. x is 0 only where y is 1 or p-1.
func CheckEd25519PublicKey(publicKey []byte, class error) error {
	if len(publicKey) != ed25519.PublicKeySize {
		return fmt.Errorf("%wan Ed25519 public key is %d octets, got %d", class, ed25519.PublicKeySize, len(publicKey))
	}
	bigEndian := make([]byte, ed25519.PublicKeySize)
	for i, octet := range publicKey {
		bigEndian[ed25519.PublicKeySize-1-i] = octet
	}
	signBit := bigEndian[0]&0x80 != 0
	bigEndian[0] &= 0x7f
	y := new(big.Int).SetBytes(bigEndian)
	if y.Cmp(ed25519FieldPrime) >= 0 {
		return fmt.Errorf("%wthe y of an Ed25519 public key must be less than 2^255-19", class)
	}
	if signBit && (y.Cmp(big.NewInt(1)) == 0 || y.Cmp(ed25519FieldPrimeMinusOne) == 0) {
		return fmt.Errorf("%wan Ed25519 public key whose x is 0 must have its sign bit clear", class)
	}
	return nil
}

// CheckEd25519PrivateKey refuses an Ed25519 private key that is not a 32-octet
// seed followed by the public key RFC 8032 section 5.1.5 derives from it.
func CheckEd25519PrivateKey(privateKey []byte) error {
	if len(privateKey) != ed25519.PrivateKeySize {
		return fmt.Errorf("%wan Ed25519 private key is %d octets, got %d", jose_errors.ErrInvalidPrivateKey, ed25519.PrivateKeySize, len(privateKey))
	}
	derived := ed25519.NewKeyFromSeed(privateKey[:ed25519.SeedSize])
	if !bytes.Equal(derived[ed25519.SeedSize:], privateKey[ed25519.SeedSize:]) {
		return fmt.Errorf("%wthe public key of an Ed25519 private key is not the one its seed derives", jose_errors.ErrInvalidPrivateKey)
	}
	return nil
}
