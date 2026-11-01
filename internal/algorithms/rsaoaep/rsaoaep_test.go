package rsaoaep

import (
	"bytes"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"errors"
	"io"
	"math/big"
	"testing"

	"github.com/MichaelFraser99/go-jose/joseerror"
	"github.com/MichaelFraser99/go-jose/jwa"
)

func TestNewEncrypterAndNewDecrypter_RefuseAnAlgorithmThatIsNotRSAOAEP(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	for _, alg := range []jwa.Algorithm{jwa.RS256, jwa.PS256, jwa.A128KW, jwa.Dir, jwa.Unknown, jwa.Algorithm(999)} {
		if e, err := NewEncrypter(alg, &key.PublicKey); !errors.Is(err, joseerror.ErrUnsupportedAlgorithm) || e != nil {
			t.Errorf("[RFC 7518 4.3] NewEncrypter(%s): want ErrUnsupportedAlgorithm, got %v", alg, err)
		}
		if d, err := NewDecrypter(alg, key); !errors.Is(err, joseerror.ErrUnsupportedAlgorithm) || d != nil {
			t.Errorf("[RFC 7518 4.3] NewDecrypter(%s): want ErrUnsupportedAlgorithm, got %v", alg, err)
		}
	}
}

func TestWrapKey_RefusesAnEncItDoesNotImplement(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	encrypter, err := NewEncrypter(jwa.RSAOAEP256, &key.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	if cek, encryptedKey, err := encrypter.WrapKey(rand.Reader, jwa.UnknownEncryption, map[string]any{}); !errors.Is(err, joseerror.ErrUnsupportedAlgorithm) || cek != nil || encryptedKey != nil {
		t.Errorf("want ErrUnsupportedAlgorithm, got %v", err)
	}
}

func TestPublic_ReturnsACopyOfTheKey(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	other, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	encrypter, err := NewEncrypter(jwa.RSAOAEP, &key.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	decrypter, err := NewDecrypter(jwa.RSAOAEP, key)
	if err != nil {
		t.Fatal(err)
	}
	if !key.PublicKey.Equal(encrypter.Public()) || !key.PublicKey.Equal(decrypter.Public()) {
		t.Fatal("Public must be the key's public half")
	}
	encrypter.Public().(*rsa.PublicKey).N.Set(other.N)
	decrypter.Public().(*rsa.PublicKey).N.Set(other.N)
	if !key.PublicKey.Equal(encrypter.Public()) || !key.PublicKey.Equal(decrypter.Public()) {
		t.Error("changing what Public returned must not change the key")
	}
	if encrypter.Alg() != jwa.RSAOAEP || decrypter.Alg() != jwa.RSAOAEP {
		t.Error("Alg must be the algorithm constructed with")
	}
}

type sharedPublicDecrypter struct {
	*rsa.PrivateKey
	public *rsa.PublicKey
}

func (s sharedPublicDecrypter) Public() crypto.PublicKey { return s.public }

func TestNewDecrypter_KeepsItsOwnCopyOfACryptoDecryptersPublicKey(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	other, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	shared := &rsa.PublicKey{N: new(big.Int).Set(key.N), E: key.E}
	decrypter, err := NewDecrypter(jwa.RSAOAEP, sharedPublicDecrypter{PrivateKey: key, public: shared})
	if err != nil {
		t.Fatal(err)
	}
	shared.N.Set(other.N)
	if !key.PublicKey.Equal(decrypter.Public()) {
		t.Error("changing the public key a crypto.Decrypter shares must not change the decrypter's")
	}
}

type pointerDecrypter struct {
	key *rsa.PrivateKey
}

func (p *pointerDecrypter) Public() crypto.PublicKey { return p.key.Public() }

func (p *pointerDecrypter) Decrypt(random io.Reader, msg []byte, opts crypto.DecrypterOpts) ([]byte, error) {
	return p.key.Decrypt(random, msg, opts)
}

func TestNewDecrypter_RefusesATypedNilCryptoDecrypter(t *testing.T) {
	var key *pointerDecrypter
	decrypter, err := NewDecrypter(jwa.RSAOAEP, key)
	if !errors.Is(err, joseerror.ErrInvalidPrivateKey) || decrypter != nil {
		t.Errorf("want ErrInvalidPrivateKey and no decrypter rather than a panic, got %v", err)
	}
}

func TestDecrypt_RefusesACiphertextNotAsLongAsTheModulus(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	encrypter, err := NewEncrypter(jwa.RSAOAEP, &key.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	decrypter, err := NewDecrypter(jwa.RSAOAEP, key)
	if err != nil {
		t.Fatal(err)
	}
	var cek, leadingZero []byte
	for range 20000 {
		c, encryptedKey, err := encrypter.WrapKey(rand.Reader, jwa.A128GCM, map[string]any{})
		if err != nil {
			t.Fatal(err)
		}
		if encryptedKey[0] == 0 {
			cek, leadingZero = c, encryptedKey
			break
		}
	}
	if leadingZero == nil {
		t.Fatal("no ciphertext with a leading zero octet in 20000 tries")
	}
	if got, err := decrypter.Decrypt(nil, leadingZero, nil); err != nil || !bytes.Equal(got, cek) {
		t.Fatalf("the full-length ciphertext must decrypt, got %v", err)
	}
	for name, msg := range map[string][]byte{
		"the leading zero octet stripped": leadingZero[1:],
		"an octet appended":               append(bytes.Clone(leadingZero), 0),
		"empty":                           nil,
	} {
		if got, err := decrypter.Decrypt(nil, msg, nil); !errors.Is(err, ErrCiphertextLength) || got != nil {
			t.Errorf("[RFC 8017 7.1.2 step 1] %s: a ciphertext must be exactly k octets, got %v", name, err)
		}
	}
}
