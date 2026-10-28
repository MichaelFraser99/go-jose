package hs256

import (
	"crypto"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"fmt"
	"github.com/MichaelFraser99/go-jose/internal/algorithms/common"
	"github.com/MichaelFraser99/go-jose/joseerror"
	"github.com/MichaelFraser99/go-jose/jwa"
	"github.com/MichaelFraser99/go-jose/model"
	"io"
	"slices"
)

var (
	_ model.Signer    = &Signer{}
	_ model.Validator = &Validator{}
)

type Signer struct {
	alg    jwa.Algorithm
	secret common.SecretKey
}

type Validator struct {
	alg    jwa.Algorithm
	secret common.SecretKey
}

func (v Validator) ValidateSignature(digest, signature []byte) (bool, error) {
	mac := common.ProduceMac(hmac.New(sha256.New, v.secret), digest)
	return hmac.Equal(signature, mac), nil
}

func (v Validator) Public() crypto.PublicKey {
	return slices.Clone(v.secret)
}

// MinimumSecretBytes is the smallest secret HS256 may be keyed with: RFC 7518
// section 3.2 requires at least the hash output size.
const MinimumSecretBytes = 32

func NewSigner(secretKey *[]byte) (*Signer, error) {
	var secret []byte
	if secretKey != nil {
		secret = *secretKey
	} else {
		secret = make([]byte, 256)
		_, err := rand.Read(secret)
		if err != nil {
			return nil, fmt.Errorf("error generating secret key value: %w", err)
		}
	}

	if len(secret) < MinimumSecretBytes {
		return nil, fmt.Errorf("%wa secret of at least %d bytes is required for HS256, got %d", joseerror.ErrInvalidPrivateKey, MinimumSecretBytes, len(secret))
	}

	return &Signer{
		alg:    jwa.HS256,
		secret: slices.Clone(secret),
	}, nil
}

func NewValidator(publicKey crypto.PublicKey) (*Validator, error) {
	if publicKey == nil {
		return nil, fmt.Errorf("%wnil public key provided", joseerror.ErrInvalidPublicKey)
	} else if _, ok := publicKey.(common.SecretKey); !ok {
		return nil, fmt.Errorf("%wthe key for an hmac algorithm is the value returned by Signer.Public, got %T", joseerror.ErrInvalidPublicKey, publicKey)
	}
	secret := []byte(publicKey.(common.SecretKey))
	if len(secret) < MinimumSecretBytes {
		return nil, fmt.Errorf("%wa secret of at least %d bytes is required for HS256, got %d", joseerror.ErrInvalidPublicKey, MinimumSecretBytes, len(secret))
	}

	return &Validator{
		alg:    jwa.HS256,
		secret: slices.Clone(secret),
	}, nil
}

func (signer *Signer) Alg() jwa.Algorithm {
	return signer.alg
}

func (signer *Signer) Public() crypto.PublicKey {
	return slices.Clone(signer.secret)
}

// Sign macs the signing input whole.
//
// There is no pre-hashed mode for an hmac algorithm: HMAC is itself the keyed
// hash, so there is no internal hashing step for a caller to skip. A non-zero
// opts.HashFunc is refused rather than ignored, because macing an already
// hashed digest yields a signature no validator accepts.
func (signer *Signer) Sign(rand io.Reader, digest []byte, opts crypto.SignerOpts) (signature []byte, err error) {
	if opts != nil && opts.HashFunc() != 0 {
		return nil, fmt.Errorf("%wan hmac algorithm has no pre-hashed mode, so the signing input must be passed whole", joseerror.ErrSigningError)
	}
	return common.ProduceMac(hmac.New(sha256.New, signer.secret), digest), nil
}
