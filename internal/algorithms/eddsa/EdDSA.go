package eddsa

import (
	"bytes"
	"crypto"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"io"
	"slices"

	"github.com/MichaelFraser99/go-jose/internal/algorithms/common"
	"github.com/MichaelFraser99/go-jose/joseerror"
	"github.com/MichaelFraser99/go-jose/jwa"
)

var smallOrderYCoordinates = map[string]bool{
	"0000000000000000000000000000000000000000000000000000000000000000": true,
	"0100000000000000000000000000000000000000000000000000000000000000": true,
	"ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f": true,
	"26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc05": true,
	"c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac037a": true,
}

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

// NewValidator builds a validator for a 32-octet Ed25519 public key. It
// refuses a key whose y is not below p, which RFC 8032 section 5.1.3 says
// fails to decode, and a key of small order, which NIST SP 800-186 appendix
// D.1.3.2 full public key validation refuses.
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
	if err := checkPoint(key); err != nil {
		return nil, err
	}
	return &Validator{
		publicKey: bytes.Clone(key),
	}, nil
}

func checkPoint(key ed25519.PublicKey) error {
	encodedY := bytes.Clone(key)
	encodedY[ed25519.PublicKeySize-1] &= 0x7f
	if smallOrderYCoordinates[hex.EncodeToString(encodedY)] {
		return fmt.Errorf("%wan Ed25519 public key of small order verifies forged signatures, so full public key validation refuses it", joseerror.ErrInvalidPublicKey)
	}
	return common.CheckEd25519PublicKey(key, joseerror.ErrInvalidPublicKey)
}

func (signer *Signer) Alg() jwa.Algorithm {
	return jwa.Ed25519
}

func (signer *Signer) Public() crypto.PublicKey {
	return signer.privateKey.Public()
}

// Sign signs the signing input with pure Ed25519. RFC 8032 section 5.1 gives
// Ed25519 no pre-hash and no context, so a hash or an *ed25519.Options
// context is refused.
func (signer *Signer) Sign(_ io.Reader, digest []byte, opts crypto.SignerOpts) (signature []byte, err error) {
	if opts != nil && opts.HashFunc() != 0 {
		return nil, fmt.Errorf("%wEd25519 is pure EdDSA and has no pre-hashed mode, so the signing input must be passed whole", joseerror.ErrSigningError)
	}
	if o, ok := opts.(*ed25519.Options); ok && o.Context != "" {
		return nil, fmt.Errorf("%wEd25519 is pure EdDSA and has no context, which would make it Ed25519ctx", joseerror.ErrSigningError)
	}
	return ed25519.Sign(signer.privateKey, digest), nil
}

func (validator *Validator) ValidateSignature(digest, signature []byte) (bool, error) {
	return ed25519.Verify(validator.publicKey, digest, signature), nil
}

func (validator *Validator) Public() crypto.PublicKey {
	return slices.Clone(validator.publicKey)
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
