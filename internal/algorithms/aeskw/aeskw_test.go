package aeskw

import (
	"bytes"
	"crypto/aes"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"testing"
)

const (
	kek128 = "000102030405060708090A0B0C0D0E0F"
	kek192 = "000102030405060708090A0B0C0D0E0F1011121314151617"
	kek256 = "000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F"
	key128 = "00112233445566778899AABBCCDDEEFF"
	key192 = "00112233445566778899AABBCCDDEEFF0001020304050607"
	key256 = "00112233445566778899AABBCCDDEEFF000102030405060708090A0B0C0D0E0F"
)

var rfc3394 = map[string]struct{ kek, key, wrapped string }{
	"4.1": {kek128, key128, "1FA68B0A8112B447AEF34BD8FB5A7B829D3E862371D2CFE5"},
	"4.2": {kek192, key128, "96778B25AE6CA435F92B5B97C050AED2468AB8A17AD84E5D"},
	"4.3": {kek256, key128, "64E8C3F9CE0F5BA263E9777905818A2A93C8191E7D6E8AE7"},
	"4.4": {kek192, key192, "031D33264E15D33268F24EC260743EDCE1C6C7DDEE725A936BA814915C6762D2"},
	"4.5": {kek256, key192, "A8F9BC1612C68B3FF6E6F4FBE30E71E4769C8B80A32CB8958CD5D17D6B254DA1"},
	"4.6": {kek256, key256, "28C9F404C4B810F4CBCCB35CFB87F8263F5786E2D80ED326CBC7F0E71A99F43BFB988B9B7A02DD21"},
}

func mustHex(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func TestWrap_ReproducesRFC3394(t *testing.T) {
	for section, v := range rfc3394 {
		t.Run(section, func(t *testing.T) {
			got, err := Wrap(mustHex(t, v.kek), mustHex(t, v.key))
			if err != nil {
				t.Fatal(err)
			}
			if want := mustHex(t, v.wrapped); !bytes.Equal(got, want) {
				t.Errorf("[RFC 3394 %s] wrap must give the published ciphertext\n got %X\nwant %X", section, got, want)
			}
		})
	}
}

func TestUnwrap_RecoversRFC3394(t *testing.T) {
	for section, v := range rfc3394 {
		t.Run(section, func(t *testing.T) {
			got, err := Unwrap(mustHex(t, v.kek), mustHex(t, v.wrapped))
			if err != nil || !bytes.Equal(got, mustHex(t, v.key)) {
				t.Errorf("[RFC 3394 %s] unwrap must give the published key data, got %X and %v", section, got, err)
			}
		})
	}
}

func TestUnwrap_RefusesAnythingAlteredWithOneError(t *testing.T) {
	v := rfc3394["4.6"]
	wrapped := mustHex(t, v.wrapped)
	flip := func(i int) []byte {
		c := bytes.Clone(wrapped)
		c[i] ^= 1
		return c
	}
	otherKEK := mustHex(t, v.kek)
	otherKEK[0] ^= 1

	tests := map[string]struct{ kek, wrapped []byte }{
		"a bit flipped in the integrity block": {mustHex(t, v.kek), flip(0)},
		"a bit flipped in the last block":      {mustHex(t, v.kek), flip(len(wrapped) - 1)},
		"another KEK":                          {otherKEK, wrapped},
		"one block short":                      {mustHex(t, v.kek), wrapped[:len(wrapped)-8]},
		"not a whole number of blocks":         {mustHex(t, v.kek), wrapped[:len(wrapped)-1]},
		"only the integrity block and one":     {mustHex(t, v.kek), wrapped[:16]},
		"nothing":                              {mustHex(t, v.kek), nil},
		"a valid wrap with one octet appended": {mustHex(t, v.kek), append(bytes.Clone(wrapped), 0)},
		"a valid wrap of a single block":       {mustHex(t, v.kek), singleBlockWrap(t, mustHex(t, v.kek), mustHex(t, key128)[:8])},
	}
	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			got, err := Unwrap(tc.kek, tc.wrapped)
			if !errors.Is(err, ErrUnwrap) || got != nil {
				t.Errorf("[RFC 3394 2.2.3, RFC 7516 11.5] %s must be refused with the one ErrUnwrap and no key, got %X and %v", name, got, err)
			}
		})
	}
}

func TestWrap_RefusesKeyDataItCannotWrap(t *testing.T) {
	kek := mustHex(t, kek128)
	for name, key := range map[string][]byte{
		"empty":                   nil,
		"one block":               make([]byte, 8),
		"not a multiple of eight": make([]byte, 17),
	} {
		t.Run(name, func(t *testing.T) {
			got, err := Wrap(kek, key)
			if err == nil || got != nil {
				t.Errorf("[RFC 3394 2] key data is at least two 64-bit blocks, so %s must be refused, got %X", name, got)
			}
		})
	}
	for _, n := range []int{0, 15, 17, 33} {
		if got, err := Wrap(make([]byte, n), mustHex(t, key128)); err == nil || got != nil {
			t.Errorf("[RFC 3394 2] the KEK is an AES key of 16, 24 or 32 octets, so %d must be refused", n)
		}
		if got, err := Unwrap(make([]byte, n), mustHex(t, rfc3394["4.1"].wrapped)); !errors.Is(err, ErrUnwrap) || got != nil {
			t.Errorf("[RFC 3394 2] a %d-octet KEK must be refused with ErrUnwrap", n)
		}
	}
}

func TestWrap_DoesNotChangeItsInput(t *testing.T) {
	kek, key := mustHex(t, kek256), mustHex(t, key256)
	before := bytes.Clone(key)
	if _, err := Wrap(kek, key); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(key, before) {
		t.Error("Wrap must not write into the key data it was given")
	}
	wrapped := mustHex(t, rfc3394["4.6"].wrapped)
	wrappedBefore := bytes.Clone(wrapped)
	if _, err := Unwrap(kek, wrapped); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(wrapped, wrappedBefore) {
		t.Error("Unwrap must not write into the ciphertext it was given")
	}
}

func singleBlockWrap(t *testing.T, kek, block []byte) []byte {
	t.Helper()
	cipherBlock, err := aes.NewCipher(kek)
	if err != nil {
		t.Fatal(err)
	}
	a := bytes.Repeat([]byte{0xA6}, 8)
	r := bytes.Clone(block)
	buf := make([]byte, 16)
	for j := 0; j <= 5; j++ {
		copy(buf[:8], a)
		copy(buf[8:], r)
		cipherBlock.Encrypt(buf, buf)
		binary.BigEndian.PutUint64(a, binary.BigEndian.Uint64(buf[:8])^uint64(j+1))
		copy(r, buf[8:])
	}
	return append(a, r...)
}
