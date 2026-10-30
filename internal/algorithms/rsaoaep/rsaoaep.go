// Package rsaoaep implements the RSA-OAEP key management algorithms: RSA-OAEP
// and RSA-OAEP-256 of RFC 7518 section 4.3, and RSA-OAEP-384 and RSA-OAEP-512,
// which the IANA "JSON Web Signature and Encryption Algorithms" registry defines
// the same way with SHA-384 and SHA-512. Each uses its hash for both OAEP and
// MGF1.
package rsaoaep

import (
	"crypto"
	"crypto/rsa"
	"fmt"
	"io"
	"reflect"

	"github.com/MichaelFraser99/go-jose/internal/algorithms/common"
	"github.com/MichaelFraser99/go-jose/internal/algorithms/contentenc"
	"github.com/MichaelFraser99/go-jose/internal/algorithms/keycopy"
	"github.com/MichaelFraser99/go-jose/joseerror"
	"github.com/MichaelFraser99/go-jose/jwa"
)

type Encrypter struct {
	alg       jwa.Algorithm
	hash      crypto.Hash
	publicKey *rsa.PublicKey
}

type Decrypter struct {
	alg       jwa.Algorithm
	hash      crypto.Hash
	key       crypto.Decrypter
	publicKey *rsa.PublicKey
}

var hashes = map[jwa.Algorithm]crypto.Hash{
	jwa.RSAOAEP:    crypto.SHA1,
	jwa.RSAOAEP256: crypto.SHA256,
	jwa.RSAOAEP384: crypto.SHA384,
	jwa.RSAOAEP512: crypto.SHA512,
}

func hashFor(alg jwa.Algorithm) (crypto.Hash, error) {
	hash, ok := hashes[alg]
	if !ok {
		return 0, fmt.Errorf("%w'%s' is not an RSA-OAEP algorithm", joseerror.ErrUnsupportedAlgorithm, alg)
	}
	return hash, nil
}

// NewEncrypter returns an Encrypter for alg that encrypts each new CEK to
// publicKey, an *rsa.PublicKey of 2048 bits or more (RFC 7518 section 4.3).
func NewEncrypter(alg jwa.Algorithm, publicKey crypto.PublicKey) (*Encrypter, error) {
	hash, err := hashFor(alg)
	if err != nil {
		return nil, err
	}
	rsaPublicKey, ok := publicKey.(*rsa.PublicKey)
	if !ok {
		return nil, fmt.Errorf("%wshould be instance of *rsa.PublicKey", joseerror.ErrInvalidPublicKey)
	}
	if err := common.CheckRSAPublicKey(rsaPublicKey, joseerror.ErrInvalidPublicKey); err != nil {
		return nil, err
	}
	return &Encrypter{alg: alg, hash: hash, publicKey: keycopy.RSAPublicKey(rsaPublicKey)}, nil
}

// NewDecrypter returns a Decrypter for alg. privateKey is an *rsa.PrivateKey, or
// any crypto.Decrypter whose Public is an *rsa.PublicKey and which accepts
// *rsa.OAEPOptions, such as a key held in a hardware module. Either way the
// modulus must be 2048 bits or more (RFC 7518 section 4.3).
func NewDecrypter(alg jwa.Algorithm, privateKey crypto.PrivateKey) (*Decrypter, error) {
	hash, err := hashFor(alg)
	if err != nil {
		return nil, err
	}
	switch key := privateKey.(type) {
	case *rsa.PrivateKey:
		completed, err := common.CompleteRSAPrivateKey(key)
		if err != nil {
			return nil, err
		}
		return &Decrypter{alg: alg, hash: hash, key: completed, publicKey: &completed.PublicKey}, nil
	case crypto.Decrypter:
		if value := reflect.ValueOf(key); value.Kind() == reflect.Pointer && value.IsNil() {
			return nil, fmt.Errorf("%wthe crypto.Decrypter for %s is a nil pointer", joseerror.ErrInvalidPrivateKey, alg)
		}
		rsaPublicKey, ok := key.Public().(*rsa.PublicKey)
		if !ok {
			return nil, fmt.Errorf("%wa crypto.Decrypter for %s must have an *rsa.PublicKey", joseerror.ErrInvalidPrivateKey, alg)
		}
		if err := common.CheckRSAPublicKey(rsaPublicKey, joseerror.ErrInvalidPrivateKey); err != nil {
			return nil, err
		}
		return &Decrypter{alg: alg, hash: hash, key: key, publicKey: keycopy.RSAPublicKey(rsaPublicKey)}, nil
	}
	return nil, fmt.Errorf("%wshould be instance of *rsa.PrivateKey or a crypto.Decrypter", joseerror.ErrInvalidPrivateKey)
}

func (encrypter *Encrypter) Alg() jwa.Algorithm {
	return encrypter.alg
}

func (encrypter *Encrypter) Public() crypto.PublicKey {
	return keycopy.RSAPublicKey(encrypter.publicKey)
}

// WrapKey generates a random CEK of the length enc requires and encrypts it with
// RSAES-OAEP (RFC 7518 section 4.3). It adds nothing to header.
func (encrypter *Encrypter) WrapKey(rand io.Reader, enc jwa.Encryption, header map[string]any) (cek, encryptedKey []byte, err error) {
	size := contentenc.KeySize(enc)
	if size == 0 {
		return nil, nil, fmt.Errorf("%w'%s' is not a content encryption algorithm this library implements", joseerror.ErrUnsupportedAlgorithm, enc)
	}
	cek = make([]byte, size)
	if _, err := io.ReadFull(rand, cek); err != nil {
		return nil, nil, fmt.Errorf("%wgenerating a content encryption key: %s", joseerror.ErrEncryptionError, err.Error())
	}
	encryptedKey, err = rsa.EncryptOAEP(encrypter.hash.New(), rand, encrypter.publicKey, cek, nil)
	if err != nil {
		return nil, nil, fmt.Errorf("%wencrypting the content encryption key: %s", joseerror.ErrEncryptionError, err.Error())
	}
	return cek, encryptedKey, nil
}

func (decrypter *Decrypter) Alg() jwa.Algorithm {
	return decrypter.alg
}

func (decrypter *Decrypter) Public() crypto.PublicKey {
	return keycopy.RSAPublicKey(decrypter.publicKey)
}

// Decrypt recovers the CEK from msg, the JWE Encrypted Key, with RSAES-OAEP
// under the hash alg names. opts is not read.
func (decrypter *Decrypter) Decrypt(rand io.Reader, msg []byte, _ crypto.DecrypterOpts) ([]byte, error) {
	return decrypter.key.Decrypt(rand, msg, &rsa.OAEPOptions{Hash: decrypter.hash, MGFHash: decrypter.hash})
}
