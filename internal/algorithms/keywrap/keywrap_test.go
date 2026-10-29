package keywrap

import (
	"crypto/rand"
	"errors"
	"testing"

	"github.com/MichaelFraser99/go-jose/joseerror"
	"github.com/MichaelFraser99/go-jose/jwa"
)

func TestNewEncrypterAndNewDecrypter_RefuseAnAlgorithmThatIsNotAESKeyWrap(t *testing.T) {
	for _, alg := range []jwa.Algorithm{jwa.RSAOAEP, jwa.Dir, jwa.HS256, jwa.Unknown, jwa.Algorithm(999)} {
		if e, err := NewEncrypter(alg, make([]byte, 16)); !errors.Is(err, joseerror.ErrUnsupportedAlgorithm) || e != nil {
			t.Errorf("[RFC 7518 4.4] NewEncrypter(%s): want ErrUnsupportedAlgorithm, got %v", alg, err)
		}
		if d, err := NewDecrypter(alg, make([]byte, 16)); !errors.Is(err, joseerror.ErrUnsupportedAlgorithm) || d != nil {
			t.Errorf("[RFC 7518 4.4] NewDecrypter(%s): want ErrUnsupportedAlgorithm, got %v", alg, err)
		}
	}
}

func TestWrapKey_RefusesAnEncItDoesNotImplement(t *testing.T) {
	encrypter, err := NewEncrypter(jwa.A128KW, make([]byte, 16))
	if err != nil {
		t.Fatal(err)
	}
	if cek, encryptedKey, err := encrypter.WrapKey(rand.Reader, jwa.Encryption(99), map[string]any{}); !errors.Is(err, joseerror.ErrUnsupportedAlgorithm) || cek != nil || encryptedKey != nil {
		t.Errorf("want ErrUnsupportedAlgorithm, got %v", err)
	}
}

func TestDecrypt_RefusesAWrappedKeyItCannotUnwrap(t *testing.T) {
	decrypter, err := NewDecrypter(jwa.A128KW, make([]byte, 16))
	if err != nil {
		t.Fatal(err)
	}
	for _, wrapped := range [][]byte{nil, make([]byte, 8), make([]byte, 24), make([]byte, 25)} {
		if cek, err := decrypter.Decrypt(nil, wrapped, nil); err == nil || cek != nil {
			t.Errorf("[RFC 3394 2.2.3] %d octets of zeros must not unwrap", len(wrapped))
		}
	}
	if decrypter.Alg() != jwa.A128KW {
		t.Error("Alg must be the algorithm constructed with")
	}
}
