package common

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"testing"
)

func TestProduceMac_TakesAHasherNothingHasWrittenTo(t *testing.T) {
	secret := []byte("a-secret-for-the-contract")
	digest := []byte("the signing input")

	want := func() []byte {
		h := hmac.New(sha256.New, secret)
		h.Write(digest)
		return h.Sum(nil)
	}()

	tests := map[string]func() []byte{
		"a hasher built for this call": func() []byte {
			return ProduceMac(hmac.New(sha256.New, secret), digest)
		},
		"a second hasher built for a second call": func() []byte {
			ProduceMac(hmac.New(sha256.New, secret), digest)
			return ProduceMac(hmac.New(sha256.New, secret), digest)
		},
	}

	for name, produce := range tests {
		t.Run(name, func(t *testing.T) {
			if got := produce(); !bytes.Equal(got, want) {
				t.Errorf("[RFC 2104] ProduceMac is the mac of its digest under the hasher's key, got %x, want %x", got, want)
			}
		})
	}
}

func TestProduceMac_AccumulatesWhenOneHasherIsReused(t *testing.T) {
	secret := []byte("a-secret-for-the-contract")
	digest := []byte("the signing input")

	reused := hmac.New(sha256.New, secret)
	first := ProduceMac(reused, digest)
	second := ProduceMac(reused, digest)

	if bytes.Equal(first, second) {
		t.Fatalf("[RFC 2104] ProduceMac does not reset its hasher, so reusing one must not silently produce the same mac twice")
	}

	accumulated := func() []byte {
		h := hmac.New(sha256.New, secret)
		h.Write(digest)
		h.Write(digest)
		return h.Sum(nil)
	}()
	if !bytes.Equal(second, accumulated) {
		t.Errorf("a reused hasher macs the concatenation of what it was given, so the second call must equal the mac over the input twice, got %x, want %x", second, accumulated)
	}
}
