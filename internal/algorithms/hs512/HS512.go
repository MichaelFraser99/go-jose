package hs512

import (
	"crypto"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha512"
	"fmt"
	"github.com/MichaelFraser99/go-jose/internal/algorithms/common"
	"github.com/MichaelFraser99/go-jose/joseerror"
	"github.com/MichaelFraser99/go-jose/jwa"
	"github.com/MichaelFraser99/go-jose/model"
	"io"
)

var (
	_ model.Signer    = &Signer{}
	_ model.Validator = &Validator{}
)

type Signer struct {
	alg    jwa.Algorithm
	secret *common.SecretKey
}

type Validator struct {
	alg    jwa.Algorithm
	secret *common.SecretKey
}

func (v Validator) ValidateSignature(digest, signature []byte) (bool, error) {
	mac := common.ProduceMac(hmac.New(sha512.New, common.SecretBytes(*v.secret)), digest)
	return hmac.Equal(signature, mac), nil
}

func (v Validator) Public() crypto.PublicKey {
	return common.CloneSecret(*v.secret)
}

// Format prints the algorithm of the validator, never its key, for every verb.
func (v Validator) Format(f fmt.State, _ rune) {
	common.FormatKeyHolder(f, v.alg, "validator")
}

// MinimumSecretBytes is the smallest secret HS512 may be keyed with: RFC 7518
// section 3.2 requires at least the hash output size.
const MinimumSecretBytes = 64

func NewSigner(secretKey *[]byte) (*Signer, error) {
	var secret []byte
	if secretKey != nil {
		secret = *secretKey
	} else {
		secret = make([]byte, 512)
		_, err := rand.Read(secret)
		if err != nil {
			return nil, fmt.Errorf("error generating secret key value: %w", err)
		}
	}

	if len(secret) < MinimumSecretBytes {
		return nil, fmt.Errorf("%wa secret of at least %d bytes is required for HS512, got %d", joseerror.ErrInvalidPrivateKey, MinimumSecretBytes, len(secret))
	}

	return &Signer{
		alg:    jwa.HS512,
		secret: common.SealSecret(jwa.HS512, secret),
	}, nil
}

func NewValidator(publicKey crypto.PublicKey) (*Validator, error) {
	if publicKey == nil {
		return nil, fmt.Errorf("%wnil public key provided", joseerror.ErrInvalidPublicKey)
	}
	key, ok := publicKey.(common.SecretKey)
	if !ok {
		return nil, fmt.Errorf("%wthe key for an hmac algorithm is the value returned by Signer.Public, got %T", joseerror.ErrInvalidPublicKey, publicKey)
	}
	secret, err := common.SecretFor(key, jwa.HS512, joseerror.ErrInvalidPublicKey)
	if err != nil {
		return nil, err
	}
	if len(secret) < MinimumSecretBytes {
		return nil, fmt.Errorf("%wa secret of at least %d bytes is required for HS512, got %d", joseerror.ErrInvalidPublicKey, MinimumSecretBytes, len(secret))
	}

	return &Validator{
		alg:    jwa.HS512,
		secret: common.SealSecret(jwa.HS512, secret),
	}, nil
}

func (signer *Signer) Alg() jwa.Algorithm {
	return signer.alg
}

// Format prints the algorithm of the signer, never its key, for every verb.
func (signer Signer) Format(f fmt.State, _ rune) {
	common.FormatKeyHolder(f, signer.Alg(), "signer")
}

func (signer *Signer) Public() crypto.PublicKey {
	return common.CloneSecret(*signer.secret)
}

// Sign macs the signing input whole. An hmac algorithm has no pre-hashed mode,
// because HMAC is itself the keyed hash, so a non-zero opts.HashFunc is refused.
func (signer *Signer) Sign(rand io.Reader, digest []byte, opts crypto.SignerOpts) (signature []byte, err error) {
	if opts != nil && opts.HashFunc() != 0 {
		return nil, fmt.Errorf("%wan hmac algorithm has no pre-hashed mode, so the signing input must be passed whole", joseerror.ErrSigningError)
	}
	return common.ProduceMac(hmac.New(sha512.New, common.SecretBytes(*signer.secret)), digest), nil
}
