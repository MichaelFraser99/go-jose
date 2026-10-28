package common

import (
	"bytes"
	"crypto"
	"crypto/hmac"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/hex"
	"hash"
	"testing"
)

func TestProduceMac_TakesAHasherNothingHasWrittenTo(t *testing.T) {
	secret := bytes.Repeat([]byte("k"), 64)
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
	secret := bytes.Repeat([]byte("k"), 64)
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

func TestSecretKey_EqualIsReachableFromWhatPublicReturns(t *testing.T) {
	secret := bytes.Repeat([]byte("k"), 64)

	tests := map[string]struct {
		reference string
		other     crypto.PublicKey
		equal     bool
	}{
		"the same bytes as a value":          {reference: "crypto.PublicKey", other: SecretKey(bytes.Clone(secret)), equal: true},
		"the same bytes as a pointer":        {reference: "crypto.PublicKey", other: ptr(SecretKey(bytes.Clone(secret))), equal: true},
		"different bytes":                    {reference: "crypto.PublicKey", other: SecretKey(bytes.Repeat([]byte("j"), 64))},
		"a different length":                 {reference: "crypto.PublicKey", other: SecretKey(bytes.Repeat([]byte("k"), 63))},
		"an empty secret":                    {reference: "crypto.PublicKey", other: SecretKey([]byte{})},
		"something that is not a secret key": {reference: "crypto.PublicKey", other: "not a key"},
		"a nil pointer to a secret key":      {reference: "crypto.PublicKey", other: (*SecretKey)(nil)},
		"an untyped nil":                     {reference: "crypto.PublicKey", other: nil},
	}

	key := SecretKey(secret)
	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			if got := key.Equal(tc.other); got != tc.equal {
				t.Errorf("[%s] comparing a secret key with %s must give %v, got %v", tc.reference, name, tc.equal, got)
			}
		})
	}
}

func TestSecretKey_EqualIsInTheMethodSetOfTheValueTypeThatIsHandedOut(t *testing.T) {
	var handedOut crypto.PublicKey = SecretKey(bytes.Repeat([]byte("k"), 64))

	comparer, ok := handedOut.(interface{ Equal(crypto.PublicKey) bool })
	if !ok {
		t.Fatal("Signer.Public and Validator.Public return a SecretKey value, so Equal must be in the method set of the value type, or a consumer cannot reach it at all")
	}
	if !comparer.Equal(SecretKey(bytes.Repeat([]byte("k"), 64))) {
		t.Error("two secret keys of the same bytes must compare equal through the interface a consumer holds")
	}
}

func ptr[T any](v T) *T { return &v }

func TestProduceMac_MatchesTheRFC4231ShortKeyVector(t *testing.T) {
	key := []byte("Jefe")
	data := []byte("what do ya want for nothing?")

	tests := map[string]struct {
		hasher func() hash.Hash
		want   string
	}{
		"HMAC-SHA-256": {sha256.New, "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843"},
		"HMAC-SHA-384": {sha512.New384, "af45d2e376484031617f78d2b58a6b1b9c7ef464f5a01b47e42ec3736322445e8e2240ca5e69e2c78b3239ecfab21649"},
		"HMAC-SHA-512": {sha512.New, "164b7a7bfcf819e2e395fbe73b56e0a387bd64222e831fd610270cd7ea2505549758bf75c05a994a6d034f65f8f0e6fdcaeab1a34d4a6b4b636e070a38bce737"},
	}

	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			if got := hex.EncodeToString(ProduceMac(hmac.New(test.hasher, key), data)); got != test.want {
				t.Errorf("[RFC 4231 test case 2] %s of %q under the 4 byte key %q is %s, got %s", name, data, key, test.want, got)
			}
		})
	}
}
