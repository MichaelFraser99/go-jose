package common

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rsa"
	"fmt"

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
	if e := publicKey.E; e < 3 || e%2 == 0 || e > MaximumRSAPublicExponent {
		return fmt.Errorf("%wan RSA public exponent is odd and in [3, %d], got %d", class, MaximumRSAPublicExponent, e)
	}
	if bits := publicKey.N.BitLen(); bits < MinimumRSAModulusBits || bits > MaximumRSAModulusBits {
		return fmt.Errorf("%wan RSA modulus of %d to %d bits is required, got %d", class, MinimumRSAModulusBits, MaximumRSAModulusBits, bits)
	}
	return nil
}

// CheckRSAPrivateKey refuses an RSA private key whose public half
// CheckRSAPublicKey refuses, or whose d is not in [1, n-1]. RFC 7518 section
// 6.3.2 makes "d" the only required private member, so a key without primes
// is accepted.
func CheckRSAPrivateKey(privateKey *rsa.PrivateKey) error {
	if privateKey == nil {
		return fmt.Errorf("%wan RSA key needs a positive modulus and exponent", jose_errors.ErrInvalidPrivateKey)
	}
	if err := CheckRSAPublicKey(&privateKey.PublicKey, jose_errors.ErrInvalidPrivateKey); err != nil {
		return err
	}
	if privateKey.D == nil || privateKey.D.Sign() <= 0 || privateKey.D.Cmp(privateKey.N) >= 0 {
		return fmt.Errorf("%wan RSA private key needs d with 0 < d < n", jose_errors.ErrInvalidPrivateKey)
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
	if privateKey.D == nil { //nolint:staticcheck
		return fmt.Errorf("%wan ECDSA private key's scalar d is in [1, n-1]", jose_errors.ErrInvalidPrivateKey)
	}
	if _, err := privateKey.Bytes(); err != nil {
		return fmt.Errorf("%wan ECDSA private key's scalar d is in [1, n-1]: %w", jose_errors.ErrInvalidPrivateKey, err)
	}
	return nil
}
