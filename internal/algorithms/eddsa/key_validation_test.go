package eddsa

import (
	"bytes"
	"crypto/ecdh"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"math/big"
	"slices"
	"testing"

	"github.com/MichaelFraser99/go-jose/joseerror"
)

var (
	curvePrime = new(big.Int).Sub(new(big.Int).Lsh(big.NewInt(1), 255), big.NewInt(19))
	curveD     = new(big.Int).Mod(new(big.Int).Mul(big.NewInt(-121665), new(big.Int).ModInverse(big.NewInt(121666), curvePrime)), curvePrime)
)

func littleEndian(t *testing.T, encoded string) *big.Int {
	t.Helper()
	b := mustHex(t, encoded)
	slices.Reverse(b)
	return new(big.Int).SetBytes(b)
}

func xSquared(y *big.Int) *big.Int {
	one := big.NewInt(1)
	ySquared := new(big.Int).Exp(y, big.NewInt(2), curvePrime)
	numerator := new(big.Int).Sub(ySquared, one)
	denominator := new(big.Int).Add(new(big.Int).Mul(curveD, ySquared), one)
	return numerator.Mul(numerator, denominator.ModInverse(denominator.Mod(denominator, curvePrime), curvePrime)).Mod(numerator, curvePrime)
}

func encode(y *big.Int, sign bool) ed25519.PublicKey {
	b := make([]byte, ed25519.PublicKeySize)
	y.FillBytes(b)
	slices.Reverse(b)
	if sign {
		b[31] |= 0x80
	}
	return b
}

func TestPublic_ReturnsACopyOfTheKey(t *testing.T) {
	signer, err := NewSignerFromPrivateKey(rfc8037Key(t))
	if err != nil {
		t.Fatal(err)
	}
	validator, err := NewValidator(ed25519.PublicKey(mustHex(t, rfc8037Public)))
	if err != nil {
		t.Fatal(err)
	}
	for name, public := range map[string]func() ed25519.PublicKey{
		"signer":    func() ed25519.PublicKey { return signer.Public().(ed25519.PublicKey) },
		"validator": func() ed25519.PublicKey { return validator.Public().(ed25519.PublicKey) },
	} {
		t.Run(name, func(t *testing.T) {
			public()[0] ^= 1
			if !bytes.Equal(public(), mustHex(t, rfc8037Public)) {
				t.Errorf("[RFC 8037 A.1] changing the key Public returned must not change the key it reports, got %x", public())
			}
		})
	}
	valid, err := validator.ValidateSignature([]byte(rfc8037SigningInput), mustHex(t, rfc8037Signature))
	if err != nil || !valid {
		t.Errorf("[RFC 8037 A.5] changing the key Public returned must not change what the validator verifies with, got %v and %v", valid, err)
	}
	signature, err := signer.Sign(rand.Reader, []byte(rfc8037SigningInput), nil)
	if err != nil || !bytes.Equal(signature, mustHex(t, rfc8037Signature)) {
		t.Errorf("[RFC 8037 A.4] changing the key Public returned must not change what the signer signs with, got %x and %v", signature, err)
	}
}

func TestNewValidator_RefusesAYCoordinateOfAtLeastP(t *testing.T) {
	tests := map[string]ed25519.PublicKey{
		"y = p":                          encode(curvePrime, false),
		"y = p with the sign bit set":    encode(curvePrime, true),
		"y = p + 1, the neutral y + p":   encode(new(big.Int).Add(curvePrime, big.NewInt(1)), false),
		"y = p + 9":                      encode(new(big.Int).Add(curvePrime, big.NewInt(9)), false),
		"y = 2^255 - 1, the largest y":   encode(new(big.Int).Add(curvePrime, big.NewInt(18)), false),
		"y = 2^255 - 1 and the sign bit": encode(new(big.Int).Add(curvePrime, big.NewInt(18)), true),
	}
	for name, key := range tests {
		t.Run(name, func(t *testing.T) {
			validator, err := NewValidator(key)
			if !errors.Is(err, joseerror.ErrInvalidPublicKey) || validator != nil {
				t.Errorf("[RFC 8032 5.1.3] decoding fails when y >= p, so %x must be refused with ErrInvalidPublicKey, got %v", []byte(key), err)
			}
		})
	}
}

func TestNewValidator_AcceptsTheLargestCanonicalYOfAPointNotOfSmallOrder(t *testing.T) {
	y := new(big.Int).Sub(curvePrime, big.NewInt(1))
	for ; xSquared(y).Sign() == 0 || big.Jacobi(xSquared(y), curvePrime) != 1; y.Sub(y, big.NewInt(1)) {
	}
	for _, sign := range []bool{false, true} {
		if _, err := NewValidator(encode(y, sign)); err != nil {
			t.Errorf("[RFC 8032 5.1.3] y = p - %s is below p and on the curve with x != 0, so it must be accepted, got %v", new(big.Int).Sub(curvePrime, y), err)
		}
	}
}

func TestNewValidator_RefusesEveryPointOfSmallOrder(t *testing.T) {
	for encoded := range smallOrderYCoordinates {
		for _, sign := range []bool{false, true} {
			key := encode(littleEndian(t, encoded), sign)
			t.Run(hex.EncodeToString(key), func(t *testing.T) {
				validator, err := NewValidator(key)
				if !errors.Is(err, joseerror.ErrInvalidPublicKey) || validator != nil {
					t.Errorf("[NIST SP 800-186 D.1.3.2] full public key validation refuses a point Q with nQ != (0,1), so this point of small order must be refused with ErrInvalidPublicKey, got %v", err)
				}
			})
		}
	}
}

func TestNewValidator_RefusesTheNeutralElementEveryMessageVerifiesUnder(t *testing.T) {
	neutral := encode(big.NewInt(1), false)
	forged := append(bytes.Clone(neutral), make([]byte, 32)...)
	for _, message := range []string{"", rfc8037SigningInput, "any message at all"} {
		if !ed25519.Verify(neutral, []byte(message), forged) {
			t.Fatalf("[RFC 8032 5.1.7] the premise is that [0]B = (0,1) + [k](0,1) holds for every k, so crypto/ed25519 accepts R = (0,1), S = 0 for %q", message)
		}
	}
	validator, err := NewValidator(neutral)
	if !errors.Is(err, joseerror.ErrInvalidPublicKey) || validator != nil {
		t.Errorf("[NIST SP 800-186 D.1.3.2] full public key validation refuses Q = (0,1), got %v", err)
	}
}

func TestSmallOrderYCoordinates_AreTheYOfEveryPointOfOrderDividingEight(t *testing.T) {
	x25519 := ecdh.X25519()
	scalar, err := x25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	one := big.NewInt(1)
	points := 0
	for encoded := range smallOrderYCoordinates {
		y := littleEndian(t, encoded)
		if y.Cmp(curvePrime) >= 0 || mustHex(t, encoded)[31]&0x80 != 0 {
			t.Fatalf("[RFC 8032 5.1.2] %s must be a canonical y with the sign bit clear", encoded)
		}
		switch x2 := xSquared(y); {
		case x2.Sign() == 0:
			points++
		case big.Jacobi(x2, curvePrime) == 1:
			points += 2
		default:
			t.Fatalf("[RFC 8032 5.1.3] y = %s must be the y of a point on edwards25519", y)
		}
		if y.Cmp(one) == 0 {
			continue
		}
		oneMinusY := new(big.Int).Mod(new(big.Int).Sub(one, y), curvePrime)
		u := new(big.Int).Mod(new(big.Int).Mul(new(big.Int).Add(one, y), new(big.Int).ModInverse(oneMinusY, curvePrime)), curvePrime)
		uBytes := make([]byte, 32)
		u.FillBytes(uBytes)
		slices.Reverse(uBytes)
		peer, err := x25519.NewPublicKey(uBytes)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := scalar.ECDH(peer); err == nil {
			t.Errorf("[RFC 7748 4.1, 6.1] y = %s maps to u = %s, and crypto/ecdh refuses only a u of small order, so it must refuse this one", y, u)
		}
	}
	if points != 8 {
		t.Errorf("[RFC 7748 4.1] edwards25519 has cofactor 8 and prime L, so exactly 8 points have order dividing 8; the listed y give %d", points)
	}
}

func TestSign_RefusesAnEd25519Context(t *testing.T) {
	signer, err := NewSignerFromPrivateKey(rfc8037Key(t))
	if err != nil {
		t.Fatal(err)
	}
	signature, err := signer.Sign(rand.Reader, []byte(rfc8037SigningInput), &ed25519.Options{Context: "context"})
	if !errors.Is(err, joseerror.ErrSigningError) || signature != nil {
		t.Errorf("[RFC 8032 5.1] Ed25519 has an empty dom2, and a context would ask crypto/ed25519 for Ed25519ctx, so it must be refused with ErrSigningError, got %x and %v", signature, err)
	}
	signature, err = signer.Sign(rand.Reader, []byte(rfc8037SigningInput), &ed25519.Options{})
	if err != nil || !bytes.Equal(signature, mustHex(t, rfc8037Signature)) {
		t.Errorf("[RFC 8037 A.4] options with no hash and no context ask for pure Ed25519, so the example signature must result, got %x and %v", signature, err)
	}
}
