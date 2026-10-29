package contentenc

import (
	"errors"
	"testing"

	"github.com/MichaelFraser99/go-jose/joseerror"
	"github.com/MichaelFraser99/go-jose/jwa"
)

func TestNew_HasTheSizesRFC7518Defines(t *testing.T) {
	tests := []struct {
		enc             jwa.Encryption
		key, nonce, tag int
		clause          string
	}{
		{enc: jwa.A128CBCHS256, key: 32, nonce: 16, tag: 16, clause: "RFC 7518 5.2.3"},
		{enc: jwa.A192CBCHS384, key: 48, nonce: 16, tag: 24, clause: "RFC 7518 5.2.4"},
		{enc: jwa.A256CBCHS512, key: 64, nonce: 16, tag: 32, clause: "RFC 7518 5.2.5"},
		{enc: jwa.A128GCM, key: 16, nonce: 12, tag: 16, clause: "RFC 7518 5.3"},
		{enc: jwa.A192GCM, key: 24, nonce: 12, tag: 16, clause: "RFC 7518 5.3"},
		{enc: jwa.A256GCM, key: 32, nonce: 12, tag: 16, clause: "RFC 7518 5.3"},
	}
	for _, tt := range tests {
		t.Run(tt.enc.String(), func(t *testing.T) {
			if got := KeySize(tt.enc); got != tt.key {
				t.Errorf("[%s] KeySize is %d, want %d", tt.clause, got, tt.key)
			}
			aead, err := New(tt.enc, make([]byte, tt.key))
			if err != nil {
				t.Fatal(err)
			}
			if aead.NonceSize() != tt.nonce || aead.Overhead() != tt.tag {
				t.Errorf("[%s] want an IV of %d and a tag of %d, got %d and %d", tt.clause, tt.nonce, tt.tag, aead.NonceSize(), aead.Overhead())
			}
			for _, wrong := range []int{0, tt.key - 1, tt.key + 1, tt.key * 2} {
				if aead, err := New(tt.enc, make([]byte, wrong)); err == nil || aead != nil {
					t.Errorf("[%s] a %d-octet key must be refused", tt.clause, wrong)
				}
			}
		})
	}
}

func TestNew_RefusesAnEncItDoesNotImplement(t *testing.T) {
	for _, enc := range []jwa.Encryption{jwa.UnknownEncryption, jwa.Encryption(99), jwa.Encryption(-1)} {
		if KeySize(enc) != 0 {
			t.Errorf("KeySize(%d) must be 0", enc)
		}
		for _, size := range []int{0, 16, 32} {
			if aead, err := New(enc, make([]byte, size)); !errors.Is(err, joseerror.ErrUnsupportedAlgorithm) || aead != nil {
				t.Errorf("want ErrUnsupportedAlgorithm for enc %d, got %v", enc, err)
			}
		}
	}
}
