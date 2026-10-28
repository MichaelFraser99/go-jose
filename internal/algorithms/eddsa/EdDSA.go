package eddsa

import (
	"bytes"
	"crypto"
	"crypto/ed25519"
	"crypto/rand"
	"fmt"
	"io"

	"github.com/MichaelFraser99/go-jose/joseerror"
	"github.com/MichaelFraser99/go-jose/jwa"
)

type Signer struct {
	privateKey ed25519.PrivateKey
}

type Validator struct {
	publicKey ed25519.PublicKey
}

func NewSigner() (*Signer, error) {
	_, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("%wfailed to generate key: %s", joseerror.ErrSigningError, err.Error())
	}
	return &Signer{
		privateKey: privateKey,
	}, nil
}

func NewSignerFromPrivateKey(privateKey crypto.PrivateKey) (*Signer, error) {
	var key ed25519.PrivateKey
	switch k := privateKey.(type) {
	case ed25519.PrivateKey:
		key = k
	case *ed25519.PrivateKey:
		if k != nil {
			key = *k
		}
	default:
		return nil, fmt.Errorf("%wshould be instance of ed25519.PrivateKey", joseerror.ErrInvalidPrivateKey)
	}
	if len(key) != ed25519.PrivateKeySize {
		return nil, fmt.Errorf("%wan Ed25519 private key is %d bytes, got %d", joseerror.ErrInvalidPrivateKey, ed25519.PrivateKeySize, len(key))
	}
	derived := ed25519.NewKeyFromSeed(key.Seed())
	if !bytes.Equal(derived[ed25519.SeedSize:], key[ed25519.SeedSize:]) {
		return nil, fmt.Errorf("%wthe public half of an Ed25519 private key is not derived from its seed", joseerror.ErrInvalidPrivateKey)
	}
	return &Signer{
		privateKey: derived,
	}, nil
}

func NewValidator(publicKey crypto.PublicKey) (*Validator, error) {
	var key ed25519.PublicKey
	switch k := publicKey.(type) {
	case ed25519.PublicKey:
		key = k
	case *ed25519.PublicKey:
		if k != nil {
			key = *k
		}
	default:
		return nil, fmt.Errorf("%wshould be instance of ed25519.PublicKey", joseerror.ErrInvalidPublicKey)
	}
	if len(key) != ed25519.PublicKeySize {
		return nil, fmt.Errorf("%wan Ed25519 public key is %d bytes, got %d", joseerror.ErrInvalidPublicKey, ed25519.PublicKeySize, len(key))
	}
	return &Validator{
		publicKey: bytes.Clone(key),
	}, nil
}

func (signer *Signer) Alg() jwa.Algorithm {
	return jwa.Ed25519
}

func (signer *Signer) Public() crypto.PublicKey {
	return signer.privateKey.Public()
}

func (signer *Signer) Sign(_ io.Reader, digest []byte, opts crypto.SignerOpts) (signature []byte, err error) {
	if opts != nil && opts.HashFunc() != 0 {
		return nil, fmt.Errorf("%wEd25519 is pure EdDSA and has no pre-hashed mode, so the signing input must be passed whole", joseerror.ErrSigningError)
	}
	return ed25519.Sign(signer.privateKey, digest), nil
}

func (validator *Validator) ValidateSignature(digest, signature []byte) (bool, error) {
	return ed25519.Verify(validator.publicKey, digest, signature), nil
}

func (validator *Validator) Public() crypto.PublicKey {
	return validator.publicKey
}

// SameAlgorithm reports whether a jwk's "alg" member names the algorithm alg
// names. EdDSA with Ed25519, the one curve this library supports, and Ed25519
// name the same algorithm, so RFC 8725 section 3.1 holds when the two are
// matched with each other.
func SameAlgorithm(member, alg string) bool {
	if member == alg {
		return true
	}
	return isEd25519Identifier(member) && isEd25519Identifier(alg)
}

func isEd25519Identifier(name string) bool {
	return name == jwa.EdDSA.String() || name == jwa.Ed25519.String()
}
