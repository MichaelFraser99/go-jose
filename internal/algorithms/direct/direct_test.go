package direct

import (
	"bytes"
	"crypto/rand"
	"errors"
	"testing"

	"github.com/MichaelFraser99/go-jose/joseerror"
	"github.com/MichaelFraser99/go-jose/jwa"
)

func TestWrapKey_RefusesAnEncItDoesNotImplement(t *testing.T) {
	encrypter, err := NewEncrypter(make([]byte, 16))
	if err != nil {
		t.Fatal(err)
	}
	if cek, encryptedKey, err := encrypter.WrapKey(rand.Reader, jwa.UnknownEncryption, map[string]any{}); !errors.Is(err, joseerror.ErrUnsupportedAlgorithm) || cek != nil || encryptedKey != nil {
		t.Errorf("want ErrUnsupportedAlgorithm, got %v", err)
	}
}

func TestDecrypt_RefusesAnEncryptedKeyThatIsNotEmpty(t *testing.T) {
	key := []byte("0123456789abcdef")
	decrypter, err := NewDecrypter(key)
	if err != nil {
		t.Fatal(err)
	}
	if cek, err := decrypter.Decrypt(nil, []byte{0}, nil); !errors.Is(err, ErrEncryptedKey) || cek != nil {
		t.Errorf("[RFC 7516 5.2 step 10] want ErrEncryptedKey, got %v", err)
	}
	cek, err := decrypter.Decrypt(nil, nil, nil)
	if err != nil || !bytes.Equal(cek, key) {
		t.Errorf("[RFC 7518 4.5] want the shared key as the CEK, got %x and %v", cek, err)
	}
	cek[0] ^= 1
	if again, _ := decrypter.Decrypt(nil, nil, nil); !bytes.Equal(again, key) {
		t.Error("changing a returned CEK must not change the key")
	}
	if decrypter.Alg() != jwa.Dir {
		t.Error("Alg must be dir")
	}
}
