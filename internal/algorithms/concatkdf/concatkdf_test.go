package concatkdf

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"testing"
)

var rfc7518AppendixCZ = []byte{158, 86, 217, 29, 129, 113, 53, 211, 114, 131, 66, 131, 191, 132, 38, 156, 251, 49, 110, 163, 218, 128, 106, 72, 246, 218, 167, 121, 140, 254, 144, 196}

func TestDerive_ReproducesRFC7518AppendixC(t *testing.T) {
	got := Derive(rfc7518AppendixCZ, 128, []byte("A128GCM"), []byte("Alice"), []byte("Bob"))
	if want := "VqqN6vgjbSBcIijNcacQGg"; base64.RawURLEncoding.EncodeToString(got) != want {
		t.Errorf("[RFC 7518 C] the derived key must be %s, got %s", want, base64.RawURLEncoding.EncodeToString(got))
	}
}

func TestOtherInfo_IsTheRFC7518AppendixCOctets(t *testing.T) {
	want := []byte{0, 0, 0, 7, 65, 49, 50, 56, 71, 67, 77, 0, 0, 0, 5, 65, 108, 105, 99, 101, 0, 0, 0, 3, 66, 111, 98, 0, 0, 0, 128}
	if got := otherInfo(128, []byte("A128GCM"), []byte("Alice"), []byte("Bob")); !bytes.Equal(got, want) {
		t.Errorf("[RFC 7518 C] OtherInfo must be the published octets\n got %v\nwant %v", got, want)
	}
}

func TestDerive_AKeyLongerThanOneHashTakesTheNextRound(t *testing.T) {
	info := otherInfo(512, []byte("A256CBC-HS512"), nil, nil)
	round := func(n byte) []byte {
		h := sha256.Sum256(append(append([]byte{0, 0, 0, n}, rfc7518AppendixCZ...), info...))
		return h[:]
	}
	want := append(round(1), round(2)...)
	if got := Derive(rfc7518AppendixCZ, 512, []byte("A256CBC-HS512"), nil, nil); !bytes.Equal(got, want) {
		t.Errorf("[NIST SP 800-56A 5.8.1.1] a 512-bit key is hash rounds 1 and 2 concatenated\n got %x\nwant %x", got, want)
	}
}

func TestDerive_TruncatesToTheKeyLength(t *testing.T) {
	for _, bits := range []int{128, 192, 256, 384, 512} {
		if got := Derive(rfc7518AppendixCZ, bits, []byte("x"), nil, nil); len(got) != bits/8 {
			t.Errorf("[NIST SP 800-56A 5.8.1.1] keydatalen %d gives %d octets, got %d", bits, bits/8, len(got))
		}
	}
	short := Derive(rfc7518AppendixCZ, 192, []byte("A192KW"), nil, nil)
	long := Derive(rfc7518AppendixCZ, 256, []byte("A192KW"), nil, nil)
	if bytes.Equal(short, long[:24]) {
		t.Error("[RFC 7518 4.6.2] keydatalen is in SuppPubInfo, so a 192-bit key is not a prefix of a 256-bit one")
	}
}
