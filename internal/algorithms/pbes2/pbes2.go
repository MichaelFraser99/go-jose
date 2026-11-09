// Package pbes2 implements the PBES2-HS256+A128KW, PBES2-HS384+A192KW and
// PBES2-HS512+A256KW key management algorithms of RFC 7518 section 4.8: a key
// encryption key is derived from a password with PBKDF2, and the CEK is wrapped
// under it with AES Key Wrap.
package pbes2

import (
	"crypto"
	"crypto/pbkdf2"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"hash"
	"io"
	"math"
	"slices"
	"strconv"

	"github.com/MichaelFraser99/go-jose/internal/algorithms/aeskw"
	"github.com/MichaelFraser99/go-jose/internal/algorithms/contentenc"
	"github.com/MichaelFraser99/go-jose/internal/jose/jsonutils"
	"github.com/MichaelFraser99/go-jose/joseerror"
	"github.com/MichaelFraser99/go-jose/jwa"
	"github.com/MichaelFraser99/go-jose/model"
)

// DefaultCount is the PBKDF2 iteration count an Encrypter uses when none is
// given: the 600,000 that draft-ietf-oauth-rfc8725bis section 3.13 cites from
// OWASP for HMAC SHA-256.
const DefaultCount = 600_000

// RecommendedCount is the minimum iteration count RFC 7518 section 4.8.1.2
// recommends.
const RecommendedCount = 1000

// MinimumSaltSize is the fewest octets of Salt Input that RFC 7518 section
// 4.8.1.1 allows.
const MinimumSaltSize = 8

// SaltSize is the octet length of the Salt Input an Encrypter generates.
const SaltSize = 16

// ErrUnwrap is the error Decrypt returns for any failure.
var ErrUnwrap = errors.New("PBES2 key unwrap failed")

type parameters struct {
	hash    func() hash.Hash
	keySize int
}

var algorithms = map[jwa.Algorithm]parameters{
	jwa.PBES2HS256A128KW: {sha256.New, 16},
	jwa.PBES2HS384A192KW: {sha512.New384, 24},
	jwa.PBES2HS512A256KW: {sha512.New, 32},
}

type Encrypter struct {
	alg      jwa.Algorithm
	password []byte
	count    int
}

type Decrypter struct {
	alg      jwa.Algorithm
	password []byte
}

func checkPassword(alg jwa.Algorithm, password []byte, class error) error {
	if _, ok := algorithms[alg]; !ok {
		return fmt.Errorf("%w'%s' is not a PBES2 algorithm", joseerror.ErrUnsupportedAlgorithm, alg)
	}
	if len(password) == 0 {
		return fmt.Errorf("%w%s requires a password of at least one octet", class, alg)
	}
	return nil
}

// NewEncrypter returns an Encrypter for alg that derives a key from password
// with count PBKDF2 iterations, or DefaultCount when count is 0. A negative
// count is refused, since RFC 7518 section 4.8.1.2 requires a positive one. A
// count below RecommendedCount is accepted, as the section only recommends
// that minimum. password must not be empty, and is copied.
func NewEncrypter(alg jwa.Algorithm, password []byte, count int) (*Encrypter, error) {
	if err := checkPassword(alg, password, joseerror.ErrInvalidPublicKey); err != nil {
		return nil, err
	}
	if count == 0 {
		count = DefaultCount
	}
	if count < 0 {
		return nil, fmt.Errorf("%w%s requires a positive iteration count (RFC 7518 section 4.8.1.2), got %d", joseerror.ErrInvalidPublicKey, alg, count)
	}
	return &Encrypter{alg: alg, password: slices.Clone(password), count: count}, nil
}

// NewDecrypter returns a Decrypter for alg that derives a key from password
// with the "p2s" and "p2c" of each JWE. password must not be empty, and is
// copied.
func NewDecrypter(alg jwa.Algorithm, password []byte) (*Decrypter, error) {
	if err := checkPassword(alg, password, joseerror.ErrInvalidPrivateKey); err != nil {
		return nil, err
	}
	return &Decrypter{alg: alg, password: slices.Clone(password)}, nil
}

func deriveKey(alg jwa.Algorithm, password, saltInput []byte, count int) ([]byte, error) {
	params := algorithms[alg]
	salt := append(append([]byte(alg.String()), 0), saltInput...)
	return pbkdf2.Key(params.hash, string(password), salt, count, params.keySize)
}

func (encrypter *Encrypter) Alg() jwa.Algorithm {
	return encrypter.alg
}

func (encrypter *Encrypter) Public() crypto.PublicKey {
	return slices.Clone(encrypter.password)
}

// WrapKey generates a random CEK of the length enc requires and a random Salt
// Input of SaltSize octets, derives the key encryption key (RFC 7518 section
// 4.8), wraps the CEK under it with AES Key Wrap, and writes the Salt Input and
// count to header as "p2s" and "p2c". A header that already holds either is
// refused with ErrMalformedClaim, since section 4.8.1.1 requires a new Salt
// Input for every encryption.
func (encrypter *Encrypter) WrapKey(rand io.Reader, enc jwa.Encryption, header map[string]any) (cek, encryptedKey []byte, err error) {
	for _, name := range []string{"p2s", "p2c"} {
		if _, present := header[name]; present {
			return nil, nil, fmt.Errorf("%wthe '%s' header is chosen by the %s encrypter and cannot be given", joseerror.ErrMalformedClaim, name, encrypter.alg)
		}
	}
	size := contentenc.KeySize(enc)
	if size == 0 {
		return nil, nil, fmt.Errorf("%w%s is not a content encryption algorithm this library implements", joseerror.ErrUnsupportedAlgorithm, contentenc.Name(enc))
	}
	saltInput := make([]byte, SaltSize)
	if _, err := io.ReadFull(rand, saltInput); err != nil {
		return nil, nil, fmt.Errorf("%wgenerating a PBES2 salt input: %s", joseerror.ErrEncryptionError, err.Error())
	}
	cek = make([]byte, size)
	if _, err := io.ReadFull(rand, cek); err != nil {
		return nil, nil, fmt.Errorf("%wgenerating a content encryption key: %s", joseerror.ErrEncryptionError, err.Error())
	}
	kek, err := deriveKey(encrypter.alg, encrypter.password, saltInput, encrypter.count)
	if err != nil {
		return nil, nil, fmt.Errorf("%wderiving the key encryption key: %s", joseerror.ErrEncryptionError, err.Error())
	}
	encryptedKey, err = aeskw.Wrap(kek, cek)
	if err != nil {
		return nil, nil, fmt.Errorf("%wwrapping the content encryption key: %s", joseerror.ErrEncryptionError, err.Error())
	}
	header["p2s"] = base64.RawURLEncoding.EncodeToString(saltInput)
	header["p2c"] = encrypter.count
	return cek, encryptedKey, nil
}

func (decrypter *Decrypter) Alg() jwa.Algorithm {
	return decrypter.alg
}

func (decrypter *Decrypter) Public() crypto.PublicKey {
	return slices.Clone(decrypter.password)
}

// Decrypt derives the key encryption key from the password and the "p2s" and
// "p2c" of the header in opts, a model.DecrypterOpts, and unwraps msg, the JWE
// Encrypted Key, with AES Key Wrap. It runs as many iterations as "p2c" names,
// so bound "p2c" before calling it. Any failure is ErrUnwrap.
func (decrypter *Decrypter) Decrypt(_ io.Reader, msg []byte, opts crypto.DecrypterOpts) ([]byte, error) {
	decrypterOpts, ok := opts.(model.DecrypterOpts)
	if !ok {
		return nil, ErrUnwrap
	}
	saltInput, count, err := Parameters(decrypterOpts.Header)
	if err != nil {
		return nil, ErrUnwrap
	}
	kek, err := deriveKey(decrypter.alg, decrypter.password, saltInput, count)
	if err != nil {
		return nil, ErrUnwrap
	}
	cek, err := aeskw.Unwrap(kek, msg)
	if err != nil {
		return nil, ErrUnwrap
	}
	return cek, nil
}

// Parameters returns the Salt Input and iteration count of header. "p2s" must be
// present and be a base64url string of at least MinimumSaltSize octets (RFC
// 7518 section 4.8.1.1), and "p2c" must be present and be a positive JSON
// integer (section 4.8.1.2). An absent member is ErrMissingClaim and any other
// fault ErrMalformedClaim. A count too large for an int is returned as
// math.MaxInt.
func Parameters(header map[string]any) (saltInput []byte, count int, err error) {
	saltInput, err = jsonutils.ExtractAndDecodeBase64urlString(header, "p2s")
	if err != nil {
		return nil, 0, err
	}
	if len(saltInput) < MinimumSaltSize {
		return nil, 0, fmt.Errorf("%wthe 'p2s' header must be at least %d octets (RFC 7518 section 4.8.1.1), got %d", joseerror.ErrMalformedClaim, MinimumSaltSize, len(saltInput))
	}
	raw, present := header["p2c"]
	if !present {
		return nil, 0, fmt.Errorf("%wthe 'p2c' header is required for PBES2 (RFC 7518 section 4.8.1.2)", joseerror.ErrMissingClaim)
	}
	count, ok := positiveInteger(raw)
	if !ok {
		return nil, 0, fmt.Errorf("%wthe 'p2c' header must be a positive JSON integer (RFC 7518 section 4.8.1.2)", joseerror.ErrMalformedClaim)
	}
	return saltInput, count, nil
}

func positiveInteger(raw any) (int, bool) {
	var value float64
	switch v := raw.(type) {
	case float64:
		value = v
	case json.Number:
		parsed, err := strconv.ParseFloat(string(v), 64)
		if err != nil && !errors.Is(err, strconv.ErrRange) {
			return 0, false
		}
		value = parsed
	case int:
		value = float64(v)
	default:
		return 0, false
	}
	if math.IsNaN(value) || value < 1 || value != math.Trunc(value) {
		return 0, false
	}
	if value >= math.MaxInt {
		return math.MaxInt, true
	}
	return int(value), true
}
