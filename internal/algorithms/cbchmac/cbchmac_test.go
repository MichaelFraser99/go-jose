package cbchmac

import (
	"bytes"
	"crypto/cipher"
	"encoding/hex"
	"errors"
	"testing"
)

type vector struct {
	key, plaintext, iv, aad, ciphertext, tag string
}

var rfc7518AppendixB = map[string]vector{
	"AES_128_CBC_HMAC_SHA_256": {key: "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f", plaintext: "41206369706865722073797374656d206d757374206e6f7420626520726571756972656420746f206265207365637265742c20616e64206974206d7573742062652061626c6520746f2066616c6c20696e746f207468652068616e6473206f662074686520656e656d7920776974686f757420696e636f6e76656e69656e6365", iv: "1af38c2dc2b96ffdd86694092341bc04", aad: "546865207365636f6e64207072696e6369706c65206f662041756775737465204b6572636b686f666673", ciphertext: "c80edfa32ddf39d5ef00c0b468834279a2e46a1b8049f792f76bfe54b903a9c9a94ac9b47ad2655c5f10f9aef71427e2fc6f9b3f399a221489f16362c703233609d45ac69864e3321cf82935ac4096c86e133314c54019e8ca7980dfa4b9cf1b384c486f3a54c51078158ee5d79de59fbd34d848b3d69550a67646344427ade54b8851ffb598f7f80074b9473c82e2db", tag: "652c3fa36b0a7c5b3219fab3a30bc1c4"},
	"AES_192_CBC_HMAC_SHA_384": {key: "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f", plaintext: "41206369706865722073797374656d206d757374206e6f7420626520726571756972656420746f206265207365637265742c20616e64206974206d7573742062652061626c6520746f2066616c6c20696e746f207468652068616e6473206f662074686520656e656d7920776974686f757420696e636f6e76656e69656e6365", iv: "1af38c2dc2b96ffdd86694092341bc04", aad: "546865207365636f6e64207072696e6369706c65206f662041756775737465204b6572636b686f666673", ciphertext: "ea65da6b59e61edb419be62d19712ae5d303eeb50052d0dfd6697f77224c8edb000d279bdc14c1072654bd30944230c657bed4ca0c9f4a8466f22b226d1746214bf8cfc2400add9f5126e479663fc90b3bed787a2f0ffcbf3904be2a641d5c2105bfe591bae23b1d7449e532eef60a9ac8bb6c6b01d35d49787bcd57ef484927f280adc91ac0c4e79c7b11efc60054e3", tag: "8490ac0e58949bfe51875d733f93ac2075168039ccc733d7"},
	"AES_256_CBC_HMAC_SHA_512": {key: "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f", plaintext: "41206369706865722073797374656d206d757374206e6f7420626520726571756972656420746f206265207365637265742c20616e64206974206d7573742062652061626c6520746f2066616c6c20696e746f207468652068616e6473206f662074686520656e656d7920776974686f757420696e636f6e76656e69656e6365", iv: "1af38c2dc2b96ffdd86694092341bc04", aad: "546865207365636f6e64207072696e6369706c65206f662041756775737465204b6572636b686f666673", ciphertext: "4affaaadb78c31c5da4b1b590d10ffbd3dd8d5d302423526912da037ecbcc7bd822c301dd67c373bccb584ad3e9279c2e6d12a1374b77f077553df829410446b36ebd97066296ae6427ea75c2e0846a11a09ccf5370dc80bfecbad28c73f09b3a3b75e662a2594410ae496b2e2e6609e31e6e02cc837f053d21f37ff4f51950bbe2638d09dd7a4930930806d0703b1f6", tag: "4dd3b4c088a7f45c216839645b2012bf2e6269a8c56a816dbc1b267761955bc5"},
}

func mustHex(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func TestSeal_ReproducesRFC7518AppendixB(t *testing.T) {
	for name, v := range rfc7518AppendixB {
		t.Run(name, func(t *testing.T) {
			aead, err := New(mustHex(t, v.key))
			if err != nil {
				t.Fatal(err)
			}
			want := append(mustHex(t, v.ciphertext), mustHex(t, v.tag)...)
			got := aead.Seal(nil, mustHex(t, v.iv), mustHex(t, v.plaintext), mustHex(t, v.aad))
			if !bytes.Equal(got, want) {
				t.Errorf("[RFC 7518 B] Seal must give E || T\n got %x\nwant %x", got, want)
			}
			if aead.NonceSize() != 16 || aead.Overhead() != len(mustHex(t, v.tag)) {
				t.Errorf("[RFC 7518 5.2.2.1] the IV is 16 octets and T is %d octets, got %d and %d", len(mustHex(t, v.tag)), aead.NonceSize(), aead.Overhead())
			}
		})
	}
}

func TestOpen_RecoversTheRFC7518AppendixBPlaintext(t *testing.T) {
	for name, v := range rfc7518AppendixB {
		t.Run(name, func(t *testing.T) {
			aead, err := New(mustHex(t, v.key))
			if err != nil {
				t.Fatal(err)
			}
			sealed := append(mustHex(t, v.ciphertext), mustHex(t, v.tag)...)
			got, err := aead.Open(nil, mustHex(t, v.iv), sealed, mustHex(t, v.aad))
			if err != nil || !bytes.Equal(got, mustHex(t, v.plaintext)) {
				t.Errorf("[RFC 7518 5.2.2.2] Open must return P, got %x and %v", got, err)
			}
		})
	}
}

func TestOpen_RefusesAnythingAlteredWithOneError(t *testing.T) {
	v := rfc7518AppendixB["AES_128_CBC_HMAC_SHA_256"]
	aead, err := New(mustHex(t, v.key))
	if err != nil {
		t.Fatal(err)
	}
	sealed := append(mustHex(t, v.ciphertext), mustHex(t, v.tag)...)
	flip := func(b []byte, i int) []byte {
		c := bytes.Clone(b)
		c[i] ^= 1
		return c
	}
	tagStart := len(mustHex(t, v.ciphertext))

	tests := map[string]struct {
		iv, sealed, aad []byte
	}{
		"a bit flipped in the ciphertext":   {mustHex(t, v.iv), flip(sealed, 0), mustHex(t, v.aad)},
		"a bit flipped in the tag":          {mustHex(t, v.iv), flip(sealed, tagStart), mustHex(t, v.aad)},
		"a bit flipped in the iv":           {flip(mustHex(t, v.iv), 0), sealed, mustHex(t, v.aad)},
		"a bit flipped in the aad":          {mustHex(t, v.iv), sealed, flip(mustHex(t, v.aad), 0)},
		"the aad dropped":                   {mustHex(t, v.iv), sealed, nil},
		"the tag truncated":                 {mustHex(t, v.iv), sealed[:len(sealed)-1], mustHex(t, v.aad)},
		"only a tag":                        {mustHex(t, v.iv), sealed[tagStart:], mustHex(t, v.aad)},
		"nothing at all":                    {mustHex(t, v.iv), nil, mustHex(t, v.aad)},
		"a ciphertext not a block multiple": {mustHex(t, v.iv), append(bytes.Clone(sealed[:tagStart-1]), sealed[tagStart:]...), mustHex(t, v.aad)},
	}
	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			got, err := aead.Open(nil, tc.iv, tc.sealed, tc.aad)
			if !errors.Is(err, ErrOpen) || got != nil {
				t.Errorf("[RFC 7518 5.2.2.2, RFC 7516 11.5] %s must be refused with the one ErrOpen and no plaintext, got %x and %v", name, got, err)
			}
		})
	}
}

func TestOpen_RefusesWhatOnlyTheKeyHolderCouldTagWithTheSameError(t *testing.T) {
	key := mustHex(t, rfc7518AppendixB["AES_128_CBC_HMAC_SHA_256"].key)
	aead, err := New(key)
	if err != nil {
		t.Fatal(err)
	}
	block, err := newBlock(key[16:])
	if err != nil {
		t.Fatal(err)
	}
	encrypt := func(iv, padded []byte) []byte {
		ciphertext := make([]byte, len(padded))
		cipher.NewCBCEncrypter(block, iv).CryptBlocks(ciphertext, padded)
		return ciphertext
	}
	iv := make([]byte, 16)
	withLast := func(last ...byte) []byte {
		b := bytes.Repeat([]byte{0x41}, 16)
		copy(b[16-len(last):], last)
		return b
	}

	tests := map[string]struct {
		iv, ciphertext []byte
	}{
		"a padding byte above the block size": {iv, encrypt(iv, withLast(0x11))},
		"a padding byte that is not padding":  {iv, encrypt(iv, withLast(0x41))},
		"a padding byte of zero":              {iv, encrypt(iv, withLast(0x00))},
		"padding bytes that disagree":         {iv, encrypt(iv, withLast(0x41, 0x02))},
		"an empty ciphertext":                 {iv, nil},
		"an iv of twelve octets":              {make([]byte, 12), encrypt(iv, withLast(0x10))},
	}
	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			tag := authenticate(key[:16], sha256Hash, 16, nil, tc.iv, tc.ciphertext)
			got, err := aead.Open(nil, tc.iv, append(bytes.Clone(tc.ciphertext), tag...), nil)
			if !errors.Is(err, ErrOpen) || got != nil {
				t.Errorf("[RFC 7518 5.2.2.2, RFC 7516 11.5] %s under a valid tag must give the same ErrOpen as a bad tag, so nothing past the tag is an oracle, got %x and %v", name, got, err)
			}
		})
	}
}

func TestNew_RefusesAKeyOfAnotherLength(t *testing.T) {
	for _, n := range []int{0, 16, 24, 31, 33, 47, 49, 63, 65, 128} {
		aead, err := New(make([]byte, n))
		if err == nil || aead != nil {
			t.Errorf("[RFC 7518 5.2.3-5.2.5] a CBC-HMAC key is 32, 48 or 64 octets, so %d octets must be refused, got %v", n, err)
		}
	}
}

func TestSeal_RefusesAnIVOfAnotherLength(t *testing.T) {
	aead, err := New(make([]byte, 32))
	if err != nil {
		t.Fatal(err)
	}
	for _, n := range []int{0, 12, 15, 17} {
		func() {
			defer func() {
				if recover() == nil {
					t.Errorf("[crypto/cipher AEAD] Seal panics on a nonce of the wrong length, as every cipher.AEAD does, but did not for %d octets", n)
				}
			}()
			aead.Seal(nil, make([]byte, n), []byte("p"), nil)
		}()
		if got, err := aead.Open(nil, make([]byte, n), make([]byte, 32), nil); !errors.Is(err, ErrOpen) || got != nil {
			t.Errorf("[RFC 7518 5.2.2.2] Open must refuse a %d-octet IV with ErrOpen rather than panic, got %v", n, err)
		}
	}
}
