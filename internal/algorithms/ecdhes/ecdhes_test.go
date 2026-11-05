package ecdhes

import (
	"bytes"
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"errors"
	"testing"

	"github.com/MichaelFraser99/go-jose/internal/algorithms/aeskw"
	"github.com/MichaelFraser99/go-jose/internal/algorithms/concatkdf"
	internal_jwk "github.com/MichaelFraser99/go-jose/internal/jose/jwk"
	"github.com/MichaelFraser99/go-jose/internal/testvectors"
	"github.com/MichaelFraser99/go-jose/joseerror"
	"github.com/MichaelFraser99/go-jose/jwa"
	"github.com/MichaelFraser99/go-jose/model"
)

var appendixCAlice = map[string]any{"kty": "EC", "crv": "P-256", "x": "gI0GAILBdu7T53akrFmMyGcsF3n5dO7MmwNBHKW5SV0", "y": "SLW_xSffzlPWrHEVI30DHM_4egVwt3NQqeUD7nMFpps", "d": "0_NxaRPUMQoAJt50Gz8YiTr8gRTwyEaCumd-MToTmIo"}

var appendixCBob = map[string]any{"kty": "EC", "crv": "P-256", "x": "weNJy2HscCSM6AEDTDg04biOvhFhyyWvOHQfeF_PxMQ", "y": "e8lnCO-AlStT-NJVX-crhB7QRYhiix03illJOVAOyck", "d": "VEmDZpDXXK8p8N0Cndsxs924q6nS1RXFASRl6BfUqdw"}

func appendixCHeader() map[string]any {
	return map[string]any{
		"alg": "ECDH-ES", "enc": "A128GCM", "apu": "QWxpY2U", "apv": "Qm9i",
		"epk": map[string]any{"kty": "EC", "crv": "P-256", "x": "gI0GAILBdu7T53akrFmMyGcsF3n5dO7MmwNBHKW5SV0", "y": "SLW_xSffzlPWrHEVI30DHM_4egVwt3NQqeUD7nMFpps"},
	}
}

func mustDecode(t *testing.T, s string) []byte {
	t.Helper()
	b, err := base64.RawURLEncoding.DecodeString(s)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func privateFromJwk(t *testing.T, jwk map[string]any) *ecdsa.PrivateKey {
	t.Helper()
	key, err := internal_jwk.PrivateFromJwk(jwk)
	if err != nil {
		t.Fatal(err)
	}
	return key.(*ecdsa.PrivateKey)
}

func TestDecrypt_DerivesTheRFC7518AppendixCKey(t *testing.T) {
	bob, err := NewDecrypter(jwa.ECDHES, privateFromJwk(t, appendixCBob))
	if err != nil {
		t.Fatal(err)
	}
	cek, err := bob.Decrypt(nil, nil, model.DecrypterOpts{Header: appendixCHeader(), Enc: jwa.A128GCM})
	if err != nil || !bytes.Equal(cek, mustDecode(t, "VqqN6vgjbSBcIijNcacQGg")) {
		t.Errorf("[RFC 7518 C] Bob must derive VqqN6vgjbSBcIijNcacQGg, got %x and %v", cek, err)
	}
}

func TestWrapWith_ProducesTheRFC7518AppendixCKeyAndHeader(t *testing.T) {
	bob := privateFromJwk(t, appendixCBob)
	alice, err := privateFromJwk(t, appendixCAlice).ECDH()
	if err != nil {
		t.Fatal(err)
	}
	encrypter, err := NewEncrypter(jwa.ECDHES, &bob.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	header := map[string]any{}
	cek, encryptedKey, err := encrypter.wrapWith(alice, rand.Reader, jwa.A128GCM, header, []byte("Alice"), []byte("Bob"))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(cek, mustDecode(t, "VqqN6vgjbSBcIijNcacQGg")) || len(encryptedKey) != 0 {
		t.Errorf("[RFC 7518 C] want the CEK VqqN6vgjbSBcIijNcacQGg and an empty encrypted key, got %x and %d octets", cek, len(encryptedKey))
	}
	want := appendixCHeader()["epk"].(map[string]any)
	got := header["epk"].(map[string]any)
	for _, member := range []string{"kty", "crv", "x", "y"} {
		if got[member] != want[member] {
			t.Errorf("[RFC 7518 C] the epk %s is %v, want %v", member, got[member], want[member])
		}
	}
	if len(got) != 4 {
		t.Errorf("[RFC 7518 4.6.1.1] the epk holds only the public members, got %v", got)
	}
}

func TestDecrypt_ApuAndApvEnterTheKeyDerivation(t *testing.T) {
	bob, err := NewDecrypter(jwa.ECDHES, privateFromJwk(t, appendixCBob))
	if err != nil {
		t.Fatal(err)
	}
	want := mustDecode(t, "VqqN6vgjbSBcIijNcacQGg")
	for name, change := range map[string]func(map[string]any){
		"apu changed":         func(h map[string]any) { h["apu"] = "QWxpY2E" },
		"apv changed":         func(h map[string]any) { h["apv"] = "Qm9j" },
		"apu and apv swapped": func(h map[string]any) { h["apu"], h["apv"] = h["apv"], h["apu"] },
		"apu removed":         func(h map[string]any) { delete(h, "apu") },
		"apv removed":         func(h map[string]any) { delete(h, "apv") },
	} {
		t.Run(name, func(t *testing.T) {
			header := appendixCHeader()
			change(header)
			cek, err := bob.Decrypt(nil, nil, model.DecrypterOpts{Header: header, Enc: jwa.A128GCM})
			if err != nil || bytes.Equal(cek, want) {
				t.Errorf("[RFC 7518 4.6.2] PartyUInfo and PartyVInfo are inputs to the KDF, so a changed one must change the key, got %x and %v", cek, err)
			}
		})
	}
	cek, err := bob.Decrypt(nil, nil, model.DecrypterOpts{Header: appendixCHeader(), Enc: jwa.A256GCM})
	if err != nil || len(cek) != 32 || bytes.Equal(cek[:16], want) {
		t.Errorf("[RFC 7518 4.6.2] the enc is the AlgorithmID and sets keydatalen, so A256GCM must give another, 32-octet key, got %x and %v", cek, err)
	}
}

func TestWrapWith_AgreesTheRFC8037AppendixA6X25519Secret(t *testing.T) {
	example, err := testvectors.RFC8037X25519()
	if err != nil {
		t.Fatal(err)
	}
	recipient, err := ecdh.X25519().NewPublicKey(example.RecipientPublicKey)
	if err != nil {
		t.Fatal(err)
	}
	ephemeral, err := ecdh.X25519().NewPrivateKey(example.EphemeralPrivateKey)
	if err != nil {
		t.Fatal(err)
	}
	encrypter, err := NewEncrypter(jwa.ECDHESA128KW, recipient)
	if err != nil {
		t.Fatal(err)
	}
	header := map[string]any{}
	cek, encryptedKey, err := encrypter.wrapWith(ephemeral, rand.Reader, jwa.A128GCM, header, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	epk := header["epk"].(map[string]any)
	if epk["kty"] != "OKP" || epk["crv"] != "X25519" || epk["x"] != base64.RawURLEncoding.EncodeToString(example.EphemeralPublicKey) || len(epk) != 3 {
		t.Errorf("[RFC 8037 A.6] the epk is {kty OKP, crv X25519, x hSDwCYkw...}, got %v", epk)
	}
	kek, err := concatkdf.Derive(example.SenderZ, 128, []byte("ECDH-ES+A128KW"), nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	unwrapped, err := aeskw.Unwrap(kek, encryptedKey)
	if err != nil || !bytes.Equal(unwrapped, cek) {
		t.Errorf("[RFC 8037 A.6, RFC 7518 4.6.2] the CEK must be wrapped under the key derived from the appendix's Z, got %v", err)
	}
}

func TestDecrypt_RefusesWhatCannotAgreeAKey(t *testing.T) {
	p256, err := ecdh.P256().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	p384, err := ecdh.P384().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	decrypter, err := NewDecrypter(jwa.ECDHESA128KW, p256)
	if err != nil {
		t.Fatal(err)
	}
	x25519, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	x25519Decrypter, err := NewDecrypter(jwa.ECDHES, x25519)
	if err != nil {
		t.Fatal(err)
	}
	onP256 := publicJwk(p256.PublicKey())
	withD := publicJwk(p256.PublicKey())
	withD["d"] = "AAAA"
	tests := []struct {
		name      string
		decrypter *Decrypter
		header    map[string]any
		opts      any
		msg       []byte
	}{
		{name: "opts that are not DecrypterOpts", decrypter: decrypter, header: map[string]any{"epk": onP256}, opts: "nope", msg: make([]byte, 24)},
		{name: "no epk", decrypter: decrypter, header: map[string]any{}, msg: make([]byte, 24)},
		{name: "an epk that is not an object", decrypter: decrypter, header: map[string]any{"epk": "x"}, msg: make([]byte, 24)},
		{name: "an epk on another curve", decrypter: decrypter, header: map[string]any{"epk": publicJwk(p384.PublicKey())}, msg: make([]byte, 24)},
		{name: "an epk carrying a private member", decrypter: decrypter, header: map[string]any{"epk": withD}, msg: make([]byte, 24)},
		{name: "an X25519 epk of small order", decrypter: x25519Decrypter, header: map[string]any{"epk": map[string]any{"kty": "OKP", "crv": "X25519", "x": base64.RawURLEncoding.EncodeToString(make([]byte, 32))}}},
		{name: "an apu equal to the apv", decrypter: decrypter, header: map[string]any{"epk": onP256, "apu": "QQ", "apv": "QQ"}, msg: make([]byte, 24)},
		{name: "an apu that is not base64url", decrypter: decrypter, header: map[string]any{"epk": onP256, "apu": "!"}, msg: make([]byte, 24)},
		{name: "a direct agreement with an encrypted key", decrypter: x25519Decrypter, header: map[string]any{"epk": publicJwk(x25519.PublicKey())}, msg: []byte{0}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var opts any = model.DecrypterOpts{Header: tt.header, Enc: jwa.A128GCM}
			if tt.opts != nil {
				opts = tt.opts
			}
			cek, err := tt.decrypter.Decrypt(nil, tt.msg, opts)
			if !errors.Is(err, ErrKeyAgreement) || cek != nil {
				t.Errorf("[RFC 7518 4.6, RFC 8725 3.4] want ErrKeyAgreement and no CEK, got %v", err)
			}
		})
	}
}

func TestNewEncrypterAndNewDecrypter_RefuseAKeyThatCannotAgreeAKey(t *testing.T) {
	p224, err := ecdsa.GenerateKey(elliptic.P224(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	edPublic, edPrivate, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	var nilECDSAPublic *ecdsa.PublicKey
	var nilECDSAPrivate *ecdsa.PrivateKey
	var nilECDHPublic *ecdh.PublicKey
	var nilECDHPrivate *ecdh.PrivateKey
	tests := []struct {
		name    string
		public  any
		private any
	}{
		{name: "a P-224 key", public: &p224.PublicKey, private: p224},
		{name: "an RSA key", public: &rsaKey.PublicKey, private: rsaKey},
		{name: "an Ed25519 key", public: edPublic, private: edPrivate},
		{name: "a nil ecdsa key", public: nilECDSAPublic, private: nilECDSAPrivate},
		{name: "a nil ecdh key", public: nilECDHPublic, private: nilECDHPrivate},
		{name: "bytes", public: make([]byte, 32), private: make([]byte, 32)},
		{name: "nothing"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if e, err := NewEncrypter(jwa.ECDHES, tt.public); !errors.Is(err, joseerror.ErrInvalidPublicKey) || e != nil {
				t.Errorf("[RFC 7518 4.6] want ErrInvalidPublicKey, got %v", err)
			}
			if d, err := NewDecrypter(jwa.ECDHESA256KW, tt.private); !errors.Is(err, joseerror.ErrInvalidPrivateKey) || d != nil {
				t.Errorf("[RFC 7518 4.6] want ErrInvalidPrivateKey, got %v", err)
			}
		})
	}
	key, err := ecdh.P256().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	for _, alg := range []jwa.Algorithm{jwa.RSAOAEP, jwa.A128KW, jwa.Dir, jwa.ES256, jwa.Unknown} {
		if e, err := NewEncrypter(alg, key.PublicKey()); !errors.Is(err, joseerror.ErrUnsupportedAlgorithm) || e != nil {
			t.Errorf("[RFC 7518 4.6] %s is not an ECDH-ES algorithm, got %v", alg, err)
		}
		if d, err := NewDecrypter(alg, key); !errors.Is(err, joseerror.ErrUnsupportedAlgorithm) || d != nil {
			t.Errorf("[RFC 7518 4.6] %s is not an ECDH-ES algorithm, got %v", alg, err)
		}
	}
}

func TestWrapKey_RefusesAHeaderItCannotHonour(t *testing.T) {
	key, err := ecdh.P256().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	encrypter, err := NewEncrypter(jwa.ECDHESA128KW, key.PublicKey())
	if err != nil {
		t.Fatal(err)
	}
	for name, header := range map[string]map[string]any{
		"an epk already given":        {"epk": map[string]any{}},
		"an apu equal to the apv":     {"apu": "QQ", "apv": "QQ"},
		"an apv that is not a string": {"apv": 7},
	} {
		t.Run(name, func(t *testing.T) {
			if cek, encryptedKey, err := encrypter.WrapKey(rand.Reader, jwa.A128GCM, header); !errors.Is(err, joseerror.ErrMalformedClaim) || cek != nil || encryptedKey != nil {
				t.Errorf("[RFC 7518 4.6] want ErrMalformedClaim, got %v", err)
			}
		})
	}
	if _, _, err := encrypter.WrapKey(rand.Reader, jwa.UnknownEncryption, map[string]any{}); !errors.Is(err, joseerror.ErrUnsupportedAlgorithm) {
		t.Errorf("want ErrUnsupportedAlgorithm for an unknown enc, got %v", err)
	}
}

func TestWrapKey_GeneratesANewEphemeralKeyEachTime(t *testing.T) {
	key, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	encrypter, err := NewEncrypter(jwa.ECDHES, key.PublicKey())
	if err != nil {
		t.Fatal(err)
	}
	first, second := map[string]any{}, map[string]any{}
	firstCEK, _, err := encrypter.WrapKey(rand.Reader, jwa.A128GCM, first)
	if err != nil {
		t.Fatal(err)
	}
	secondCEK, _, err := encrypter.WrapKey(rand.Reader, jwa.A128GCM, second)
	if err != nil {
		t.Fatal(err)
	}
	if first["epk"].(map[string]any)["x"] == second["epk"].(map[string]any)["x"] || bytes.Equal(firstCEK, secondCEK) {
		t.Error("[RFC 7518 4.6] a new ephemeral public key MUST be generated for each key agreement")
	}
}
