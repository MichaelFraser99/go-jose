package jwa

import "testing"

func TestKeyManagementAlgorithm_NamesAreTheRegisteredOnes(t *testing.T) {
	tests := map[Algorithm]string{
		RSAOAEP:    "RSA-OAEP",
		RSAOAEP256: "RSA-OAEP-256",
		RSAOAEP384: "RSA-OAEP-384",
		RSAOAEP512: "RSA-OAEP-512",
		A128KW:     "A128KW",
		A192KW:     "A192KW",
		A256KW:     "A256KW",
		Dir:        "dir",
	}
	for alg, name := range tests {
		if alg.String() != name {
			t.Errorf("[RFC 7518 4.1] the alg value is %q, got %q", name, alg.String())
		}
		if GetAlgorithm(name) != alg {
			t.Errorf("[RFC 7518 4.1] GetAlgorithm(%q) must give back the same algorithm", name)
		}
		if alg == Unknown {
			t.Errorf("%q must not be the zero value", name)
		}
	}
	for _, name := range []string{"RSA1_5", "rsa-oaep", "DIR", "A128kw"} {
		if GetAlgorithm(name) != Unknown {
			t.Errorf("[RFC 8725 3.2, RFC 7515 4.1.1] %q is not an algorithm this library supports, so it must be Unknown", name)
		}
	}
}

func TestEncryption_NamesAreTheRegisteredOnes(t *testing.T) {
	tests := map[Encryption]string{
		A128CBCHS256: "A128CBC-HS256",
		A192CBCHS384: "A192CBC-HS384",
		A256CBCHS512: "A256CBC-HS512",
		A128GCM:      "A128GCM",
		A192GCM:      "A192GCM",
		A256GCM:      "A256GCM",
	}
	for enc, name := range tests {
		if enc.String() != name {
			t.Errorf("[RFC 7518 5.1] the enc value is %q, got %q", name, enc.String())
		}
		if GetEncryption(name) != enc {
			t.Errorf("[RFC 7518 5.1] GetEncryption(%q) must give back the same encryption", name)
		}
		if enc == UnknownEncryption {
			t.Errorf("%q must not be the zero value", name)
		}
	}
	var unset Encryption
	if unset != UnknownEncryption || unset.String() != "" {
		t.Errorf("an unset Encryption must be UnknownEncryption and name nothing, got %q", unset.String())
	}
	for _, name := range []string{"", "a128gcm", "A128CBC", "A128CBC-HS512", "ES256", "dir"} {
		if GetEncryption(name) != UnknownEncryption {
			t.Errorf("[RFC 7516 4.1.2] %q is not a content encryption this library supports, so it must be UnknownEncryption", name)
		}
	}
	for name := range map[string]bool{"A128GCM": true, "A128CBC-HS256": true} {
		if GetAlgorithm(name) != Unknown {
			t.Errorf("[RFC 7516 4.1.2] %q is an enc value, not an alg value, so GetAlgorithm must not name it", name)
		}
	}
}
