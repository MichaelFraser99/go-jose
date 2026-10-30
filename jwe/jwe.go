// Package jwe encrypts and decrypts the JWE Compact Serialization of RFC 7516.
package jwe

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"maps"
	"slices"
	"strings"

	"github.com/MichaelFraser99/go-jose/internal/algorithms/common"
	"github.com/MichaelFraser99/go-jose/internal/algorithms/contentenc"
	"github.com/MichaelFraser99/go-jose/internal/jose/header"
	"github.com/MichaelFraser99/go-jose/internal/jose/jsonutils"
	"github.com/MichaelFraser99/go-jose/joseerror"
	"github.com/MichaelFraser99/go-jose/jwa"
	"github.com/MichaelFraser99/go-jose/model"
)

const defaultMaxKeysTried = 100

// Encrypt encrypts plaintext to the recipient encrypter names, with enc, and
// returns the JWE Compact Serialization, following RFC 7516 section 5.1.
//
// head holds any further JWE Protected Header parameters and is not modified.
// An "alg" or "enc" in head must name the algorithm in use, else
// ErrUnsupportedAlgorithm. A "zip" is refused with ErrUnsupportedAlgorithm: RFC
// 8725 section 3.6 advises against compressing before encryption. The header
// emitted must have the shapes Decrypt accepts, else ErrMalformedClaim or
// ErrMissingCriticalClaim. The AAD is the base64url-encoded header (section 5.1
// step 14), and the Initialization Vector is random.
func Encrypt(encrypter model.Encrypter, enc jwa.Encryption, plaintext []byte, head map[string]any) (string, error) {
	return encrypt(rand.Reader, encrypter, enc, plaintext, head)
}

func encrypt(random io.Reader, encrypter model.Encrypter, enc jwa.Encryption, plaintext []byte, head map[string]any) (string, error) {
	if common.IsNil(encrypter) {
		return "", fmt.Errorf("%wan encrypter is required, got none", joseerror.ErrInvalidPublicKey)
	}
	alg := encrypter.Alg()
	if !slices.Contains(header.KeyManagementAlgorithms, alg) {
		return "", fmt.Errorf("%w'%s' is not a key management algorithm this library implements", joseerror.ErrUnsupportedAlgorithm, alg)
	}
	if contentenc.KeySize(enc) == 0 {
		return "", fmt.Errorf("%w'%s' is not a content encryption algorithm this library implements", joseerror.ErrUnsupportedAlgorithm, enc)
	}

	h := maps.Clone(head)
	if h == nil {
		h = map[string]any{}
	}
	for name, value := range map[string]string{"alg": alg.String(), "enc": enc.String()} {
		if named, found := h[name]; found && named != value {
			return "", fmt.Errorf("%wthe '%s' header must be the string %q", joseerror.ErrUnsupportedAlgorithm, name, value)
		}
	}
	if _, found := h["zip"]; found {
		return "", fmt.Errorf("%wthis library does not compress: RFC 8725 section 3.6 advises against compression before encryption", joseerror.ErrUnsupportedAlgorithm)
	}
	h["alg"] = alg.String()
	h["enc"] = enc.String()

	cek, encryptedKey, err := encrypter.WrapKey(random, enc, h)
	if err != nil {
		return "", err
	}
	if h["alg"] != alg.String() || h["enc"] != enc.String() {
		return "", fmt.Errorf("%wthe encrypter rewrote the 'alg' or 'enc' header", joseerror.ErrEncryptionError)
	}
	if _, found := h["zip"]; found {
		return "", fmt.Errorf("%wthe encrypter added a 'zip' header to plaintext that was not compressed", joseerror.ErrEncryptionError)
	}
	if alg == jwa.Dir && len(encryptedKey) != 0 {
		return "", fmt.Errorf("%wthe JWE Encrypted Key of a dir JWE is empty (RFC 7516 section 5.1 step 5)", joseerror.ErrEncryptionError)
	}

	headBytes, err := json.Marshal(h)
	if err != nil {
		return "", fmt.Errorf("%wthe header cannot be encoded as JSON: %s", joseerror.ErrMalformedClaim, err.Error())
	}
	if err := checkProducerHeader(headBytes); err != nil {
		return "", err
	}
	encodedHead := base64.RawURLEncoding.EncodeToString(headBytes)

	aead, err := contentenc.New(enc, cek)
	if err != nil {
		return "", fmt.Errorf("%w%s", joseerror.ErrEncryptionError, err.Error())
	}
	iv := make([]byte, aead.NonceSize())
	if _, err := io.ReadFull(random, iv); err != nil {
		return "", fmt.Errorf("%wgenerating an initialization vector: %s", joseerror.ErrEncryptionError, err.Error())
	}
	sealed := aead.Seal(nil, iv, plaintext, []byte(encodedHead))
	ciphertext, tag := sealed[:len(sealed)-aead.Overhead()], sealed[len(sealed)-aead.Overhead():]

	return strings.Join([]string{
		encodedHead,
		base64.RawURLEncoding.EncodeToString(encryptedKey),
		base64.RawURLEncoding.EncodeToString(iv),
		base64.RawURLEncoding.EncodeToString(ciphertext),
		base64.RawURLEncoding.EncodeToString(tag),
	}, "."), nil
}

func checkProducerHeader(headBytes []byte) error {
	decoder := json.NewDecoder(bytes.NewReader(headBytes))
	decoder.UseNumber()
	var emitted map[string]any
	_ = decoder.Decode(&emitted)
	return header.CheckJWEHeaderShape(emitted)
}

// Decrypt decrypts a JWE Compact Serialization, following RFC 7516 section 5.2,
// and returns its JWE Protected Header, its plaintext, and the decrypter that
// decrypted it. An empty plaintext is an empty, non-nil slice.
//
// A token of other than five parts, or with a part that is not base64url, is
// refused with ErrMalformedToken (section 7.1). A fault in the header is
// ErrMalformedToken wrapping the reason:
//
//   - "alg" must name a key management algorithm this library implements and
//     "enc" a content encryption algorithm it implements (sections 4.1.1 and
//     4.1.2), each within JoseOptions.AllowedKeyManagementAlgorithms and
//     AllowedContentEncryptionAlgorithms when set, else ErrUnsupportedAlgorithm.
//   - "zip" is ErrUnsupportedAlgorithm: section 4.1.3 requires it to be
//     processed, and this library does not decompress.
//   - "crit" follows RFC 7515 section 4.1.11, as section 4.1.13 requires, and
//     may name no parameter RFC 7516 or RFC 7518 defines for JWE.
//   - The parameters shared with RFC 7515 have the shapes jws.Verify requires,
//     and AcceptedTypes, RequireKeyIdentifier and UnderstoodCriticalHeaders apply
//     as they do there. "b64" (RFC 7797) is a JWS parameter and is not read.
//
// The Initialization Vector and Authentication Tag must be the lengths enc
// defines. The JWE Encrypted Key of a dir JWE must be empty, and that of an
// A128KW, A192KW or A256KW JWE must be 8 octets longer than enc's key (section
// 5.2 step 10, RFC 3394 section 2.2.1). Any other length is ErrMalformedToken.
//
// Only the decrypters passed are tried. A "jku", "jwk", "x5u" or "x5c" in the
// header names the recipient's public key, which cannot decrypt, so none is
// fetched or read. Each decrypter whose Alg is the token's alg is tried in turn, up to
// JoseOptions.MaxKeysTried (100 when unset); more is ErrTooManyKeys. A decrypter
// that fails, or returns a CEK of the wrong length, is given a random CEK in its
// place, as RFC 7516 section 11.5 advises, so every failure to decrypt is the
// one ErrDecryptionFailed. A nil ctx or decrypter is ErrInvalidOptions. ctx is
// checked before each decrypter is tried, and its error returned once it ends.
// Each decrypter is given its own copy of the header and the encrypted key.
//
// Decrypt does not compare the header's "kid" with the decrypter that
// succeeded. With a shared key, such as A256KW or dir, the key is what
// identifies the sender, and any holder of any key passed can set "kid" to
// another's. To know which sender a token came from, use the decrypter Decrypt
// returns, not the "kid".
func Decrypt(ctx context.Context, compactSerialization string, decrypters []model.Decrypter, opts *model.JoseOptions) (protectedHeader map[string]any, plaintext []byte, decrypter model.Decrypter, err error) {
	if ctx == nil {
		return nil, nil, nil, fmt.Errorf("%wthe context passed is nil", joseerror.ErrInvalidOptions)
	}
	for _, candidate := range decrypters {
		if common.IsNil(candidate) {
			return nil, nil, nil, fmt.Errorf("%wa decrypter passed is nil", joseerror.ErrInvalidOptions)
		}
	}

	components := strings.SplitN(compactSerialization, ".", 6)
	if len(components) != 5 {
		return nil, nil, nil, fmt.Errorf("%wa JWE Compact Serialization has exactly five parts", joseerror.ErrMalformedToken)
	}
	protectedHeader, err = jsonutils.DecodeBase64urlMap(components[0])
	if err != nil {
		return nil, nil, nil, fmt.Errorf("%werror processing protected header: %v", joseerror.ErrMalformedToken, err)
	}
	alg, enc, err := header.ValidateJWEHeader(protectedHeader, opts)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("%werror validating header: %w", joseerror.ErrMalformedToken, err)
	}

	var parts [4][]byte
	for i, name := range []string{"encrypted key", "initialization vector", "ciphertext", "authentication tag"} {
		parts[i], err = jsonutils.DecodeBase64url(components[i+1])
		if err != nil {
			return nil, nil, nil, fmt.Errorf("%werror decoding the %s: %v", joseerror.ErrMalformedToken, name, err)
		}
	}
	encryptedKey, iv, ciphertext, tag := parts[0], parts[1], parts[2], parts[3]

	size := contentenc.KeySize(enc)
	shape, err := contentenc.New(enc, make([]byte, size))
	if err != nil {
		return nil, nil, nil, fmt.Errorf("%w%s", joseerror.ErrDecryptionFailed, err.Error())
	}
	if len(iv) != shape.NonceSize() {
		return nil, nil, nil, fmt.Errorf("%w%s requires an initialization vector of %d octets, got %d", joseerror.ErrMalformedToken, enc, shape.NonceSize(), len(iv))
	}
	if len(tag) != shape.Overhead() {
		return nil, nil, nil, fmt.Errorf("%w%s requires an authentication tag of %d octets, got %d", joseerror.ErrMalformedToken, enc, shape.Overhead(), len(tag))
	}
	if want, fixed := encryptedKeySize(alg, size); fixed && len(encryptedKey) != want {
		return nil, nil, nil, fmt.Errorf("%wa %s JWE with %s has an encrypted key of %d octets, got %d (RFC 7516 section 5.2 step 10)", joseerror.ErrMalformedToken, alg, enc, want, len(encryptedKey))
	}

	var candidates []model.Decrypter
	for _, candidate := range decrypters {
		if candidate.Alg() == alg {
			candidates = append(candidates, candidate)
		}
	}
	if len(candidates) == 0 {
		return nil, nil, nil, fmt.Errorf("%wno decrypter given implements %s", joseerror.ErrDecryptionFailed, alg)
	}
	maxKeysTried := defaultMaxKeysTried
	if opts != nil && opts.MaxKeysTried > 0 {
		maxKeysTried = opts.MaxKeysTried
	}
	if len(candidates) > maxKeysTried {
		return nil, nil, nil, fmt.Errorf("%w%d decrypters implement %s, more than the %d MaxKeysTried allows", joseerror.ErrTooManyKeys, len(candidates), alg, maxKeysTried)
	}

	aad := []byte(components[0])
	sealed := append(slices.Clip(ciphertext), tag...)
	for _, candidate := range candidates {
		if err := ctx.Err(); err != nil {
			return nil, nil, nil, err
		}
		cek := make([]byte, size)
		if _, err := io.ReadFull(rand.Reader, cek); err != nil {
			return nil, nil, nil, fmt.Errorf("%wgenerating a random content encryption key: %s", joseerror.ErrDecryptionFailed, err.Error())
		}
		ownHeader, _ := jsonutils.DecodeBase64urlMap(components[0])
		recovered, err := candidate.Decrypt(rand.Reader, slices.Clone(encryptedKey), model.DecrypterOpts{Header: ownHeader, Enc: enc})
		if err == nil && len(recovered) == size {
			copy(cek, recovered)
		}
		aead, err := contentenc.New(enc, cek)
		if err != nil {
			return nil, nil, nil, fmt.Errorf("%w%s", joseerror.ErrDecryptionFailed, err.Error())
		}
		if plaintext, err := aead.Open(make([]byte, 0, len(ciphertext)), iv, sealed, aad); err == nil {
			return protectedHeader, plaintext, candidate, nil
		}
	}
	return nil, nil, nil, fmt.Errorf("%wno decrypter given could decrypt the token", joseerror.ErrDecryptionFailed)
}

func encryptedKeySize(alg jwa.Algorithm, cekSize int) (int, bool) {
	switch alg {
	case jwa.A128KW, jwa.A192KW, jwa.A256KW:
		return cekSize + 8, true
	case jwa.Dir:
		return 0, true
	case jwa.RSAOAEP, jwa.RSAOAEP256, jwa.RSAOAEP384, jwa.RSAOAEP512:
	case jwa.ES256, jwa.ES384, jwa.ES512, jwa.RS256, jwa.RS384, jwa.RS512, jwa.PS256, jwa.PS384, jwa.PS512, jwa.HS256, jwa.HS384, jwa.HS512, jwa.EdDSA, jwa.Ed25519, jwa.MLDSA44, jwa.MLDSA65, jwa.MLDSA87, jwa.Unknown:
	}
	return 0, false
}
