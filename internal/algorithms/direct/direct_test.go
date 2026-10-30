package direct

import (
	"bytes"
	"crypto/rand"
	"errors"
	"testing"

	"github.com/MichaelFraser99/go-jose/joseerror"
	"github.com/MichaelFraser99/go-jose/jwa"
	"github.com/MichaelFraser99/go-jose/model"
)

func TestWrapKey_RefusesAnEncOtherThanTheKeys(t *testing.T) {
	encrypter, err := NewEncrypter(Key{Key: make([]byte, 16), Enc: jwa.A128GCM})
	if err != nil {
		t.Fatal(err)
	}
	for _, enc := range []jwa.Encryption{jwa.UnknownEncryption, jwa.A256GCM, jwa.A128CBCHS256} {
		if cek, encryptedKey, err := encrypter.WrapKey(rand.Reader, enc, map[string]any{}); !errors.Is(err, joseerror.ErrInvalidPublicKey) || cek != nil || encryptedKey != nil {
			t.Errorf("[RFC 8725 3.1] want ErrInvalidPublicKey for %s, got %v", enc, err)
		}
	}
}

func TestDecrypt_RefusesWhatTheKeyIsNotFor(t *testing.T) {
	key := []byte("0123456789abcdef")
	decrypter, err := NewDecrypter(Key{Key: key, Enc: jwa.A128GCM})
	if err != nil {
		t.Fatal(err)
	}
	if cek, err := decrypter.Decrypt(nil, []byte{0}, model.DecrypterOpts{Enc: jwa.A128GCM}); !errors.Is(err, ErrEncryptedKey) || cek != nil {
		t.Errorf("[RFC 7516 5.2 step 10] want ErrEncryptedKey, got %v", err)
	}
	for name, opts := range map[string]any{"another enc": model.DecrypterOpts{Enc: jwa.A128CBCHS256}, "no opts": nil, "opts of another type": &model.DecrypterOpts{Enc: jwa.A128GCM}} {
		if cek, err := decrypter.Decrypt(nil, nil, opts); !errors.Is(err, ErrOtherEnc) || cek != nil {
			t.Errorf("[RFC 8725 3.1] %s: want ErrOtherEnc, got %v", name, err)
		}
	}
	cek, err := decrypter.Decrypt(nil, nil, model.DecrypterOpts{Enc: jwa.A128GCM})
	if err != nil || !bytes.Equal(cek, key) {
		t.Errorf("[RFC 7518 4.5] want the shared key as the CEK, got %x and %v", cek, err)
	}
	cek[0] ^= 1
	if again, _ := decrypter.Decrypt(nil, nil, model.DecrypterOpts{Enc: jwa.A128GCM}); !bytes.Equal(again, key) {
		t.Error("changing a returned CEK must not change the key")
	}
	if decrypter.Alg() != jwa.Dir {
		t.Error("Alg must be dir")
	}
}
