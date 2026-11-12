package jwk

import (
	"crypto/ed25519"
	"encoding/base64"
	"maps"
	"math/big"
	"reflect"
	"strings"
	"testing"
)

const (
	rfc8037A1D         = "nWGxne_9WmC6hEr0kuwsxERJxWl7MmkZcDusAxyuf2A"
	rfc8037A1X         = "11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo"
	rfc8037A3Kid       = "kPrK_qmxVWaYVA9wwBF6Iuo3vVzz7TxHCTwXBygrS4k"
	rfc8037A4Input     = "eyJhbGciOiJFZERTQSJ9.RXhhbXBsZSBvZiBFZDI1NTE5IHNpZ25pbmc"
	rfc8037A4Signature = "hgyY0il_MGCjP0JzlnLWG1PPOt7-09PGcvMg3AIbQR6dWbhijcNR4ki4iylGjg5BhVsPt9g7sVvpAr_MuM0KAg"
)

func rfc8037A1PrivateJwk() map[string]any {
	return map[string]any{"kty": "OKP", "crv": "Ed25519", "d": rfc8037A1D, "x": rfc8037A1X}
}

func rfc8037A2PublicJwk() map[string]any {
	return map[string]any{"kty": "OKP", "crv": "Ed25519", "x": rfc8037A1X}
}

func TestFromJwk_AnEd25519KeyIsTheValueTypeTheStandardLibraryDocuments(t *testing.T) {
	tests := map[string]struct {
		read func() (any, error)
		want reflect.Type
	}{
		"PublicFromJwk of the A.2 public jwk":   {read: func() (any, error) { return PublicFromJwk(rfc8037A2PublicJwk()) }, want: reflect.TypeFor[ed25519.PublicKey]()},
		"PublicFromJwk of the A.1 private jwk":  {read: func() (any, error) { return PublicFromJwk(rfc8037A1PrivateJwk()) }, want: reflect.TypeFor[ed25519.PublicKey]()},
		"PrivateFromJwk of the A.1 private jwk": {read: func() (any, error) { return PrivateFromJwk(rfc8037A1PrivateJwk()) }, want: reflect.TypeFor[ed25519.PrivateKey]()},
	}

	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			key, err := test.read()
			if err != nil {
				t.Fatalf("[RFC 8037 A.1] the example key must read, got %v", err)
			}
			if got := reflect.TypeOf(key); got != test.want {
				t.Errorf("[x509.ParsePKIXPublicKey, x509.ParsePKCS8PrivateKey godoc] an Ed25519 key is the value type %v, not a pointer, got %v", test.want, got)
			}
		})
	}
}

func TestFromJwk_AnEd25519KeyReadsBackToTheJwkItCameFrom(t *testing.T) {
	public, err := PublicFromJwk(rfc8037A2PublicJwk())
	if err != nil {
		t.Fatal(err)
	}
	publicJwk, err := produce(t, func() (*map[string]any, error) { return PublicJwk(public) })
	if err != nil {
		t.Fatalf("[RFC 8037 2] PublicJwk must encode the key PublicFromJwk read, got %v", err)
	}
	wantPublic := rfc8037A2PublicJwk()
	wantPublic["kid"] = rfc8037A3Kid
	if !maps.Equal(*publicJwk, wantPublic) {
		t.Errorf("[RFC 8037 A.2, A.3] got %v, want %v", *publicJwk, wantPublic)
	}

	private, err := PrivateFromJwk(rfc8037A1PrivateJwk())
	if err != nil {
		t.Fatal(err)
	}
	privateJwk, err := produce(t, func() (*map[string]any, error) { return PrivateJwk(private) })
	if err != nil {
		t.Fatalf("[RFC 8037 2] PrivateJwk must encode the key PrivateFromJwk read, got %v", err)
	}
	wantPrivate := rfc8037A1PrivateJwk()
	wantPrivate["kid"] = rfc8037A3Kid
	if !maps.Equal(*privateJwk, wantPrivate) {
		t.Errorf("[RFC 8037 A.1, A.3] got %v, want %v", *privateJwk, wantPrivate)
	}
}

func TestFromJwk_AnEd25519KeyWorksWithTheStandardLibraryDirectly(t *testing.T) {
	publicRead, err := PublicFromJwk(rfc8037A2PublicJwk())
	if err != nil {
		t.Fatal(err)
	}
	privateRead, err := PrivateFromJwk(rfc8037A1PrivateJwk())
	if err != nil {
		t.Fatal(err)
	}
	public, ok := publicRead.(ed25519.PublicKey)
	if !ok {
		t.Fatalf("[x509.ParsePKIXPublicKey godoc] an Ed25519 public key is an ed25519.PublicKey, got %T", publicRead)
	}
	private, ok := privateRead.(ed25519.PrivateKey)
	if !ok {
		t.Fatalf("[x509.ParsePKCS8PrivateKey godoc] an Ed25519 private key is an ed25519.PrivateKey, got %T", privateRead)
	}

	if !public.Equal(private.Public()) {
		t.Errorf("[RFC 8037 A.2] the public key of the A.1 private key must equal the A.2 public key, got %x and %x", private.Public(), public)
	}

	signature := ed25519.Sign(private, []byte(rfc8037A4Input))
	if got := base64.RawURLEncoding.EncodeToString(signature); got != rfc8037A4Signature {
		t.Errorf("[RFC 8037 A.4] ed25519.Sign with the key read must give the example signature, got %s", got)
	}
	if !ed25519.Verify(public, []byte(rfc8037A4Input), signature) {
		t.Error("[RFC 8037 A.5] ed25519.Verify with the key read must accept the example signature")
	}
	if ed25519.Verify(public, []byte(rfc8037A4Input+"."), signature) {
		t.Error("[RFC 8032 5.1.7] ed25519.Verify with the key read must refuse the signature over a different input")
	}
}

func TestFromJwk_ARefusedEd25519JwkReturnsANilKey(t *testing.T) {
	p := new(big.Int).Sub(new(big.Int).Lsh(big.NewInt(1), 255), big.NewInt(19))
	nonCanonical := ed25519Encoding(p, false)
	with := func(base map[string]any, member string, value any) map[string]any {
		jwk := maps.Clone(base)
		jwk[member] = value
		return jwk
	}
	short := base64.RawURLEncoding.EncodeToString(make([]byte, ed25519.PublicKeySize-1))
	long := base64.RawURLEncoding.EncodeToString(make([]byte, ed25519.PublicKeySize+1))
	huge := strings.Repeat("A", 1<<20)

	tests := map[string]struct {
		jwk           map[string]any
		publicRefused bool
	}{
		"x one octet short":                    {jwk: with(rfc8037A2PublicJwk(), "x", short), publicRefused: true},
		"x one octet over":                     {jwk: with(rfc8037A2PublicJwk(), "x", long), publicRefused: true},
		"x a megabyte":                         {jwk: with(rfc8037A2PublicJwk(), "x", huge), publicRefused: true},
		"x empty":                              {jwk: with(rfc8037A2PublicJwk(), "x", ""), publicRefused: true},
		"x null":                               {jwk: with(rfc8037A2PublicJwk(), "x", nil), publicRefused: true},
		"x a number":                           {jwk: with(rfc8037A2PublicJwk(), "x", 7), publicRefused: true},
		"x not base64url":                      {jwk: with(rfc8037A2PublicJwk(), "x", "é"), publicRefused: true},
		"x a y of p, not canonical":            {jwk: with(rfc8037A2PublicJwk(), "x", nonCanonical), publicRefused: true},
		"d one octet short":                    {jwk: with(rfc8037A1PrivateJwk(), "d", short)},
		"d one octet over":                     {jwk: with(rfc8037A1PrivateJwk(), "d", long)},
		"d a megabyte":                         {jwk: with(rfc8037A1PrivateJwk(), "d", huge)},
		"d null":                               {jwk: with(rfc8037A1PrivateJwk(), "d", nil)},
		"a private jwk whose x is not d's key": {jwk: with(rfc8037A1PrivateJwk(), "x", ed25519Encoding(big.NewInt(1), false))},
		"a private jwk whose x is a y of p":    {jwk: with(rfc8037A1PrivateJwk(), "x", nonCanonical), publicRefused: true},
	}

	for name, test := range tests {
		t.Run(name+", private", func(t *testing.T) {
			key, err := PrivateFromJwk(test.jwk)
			if err == nil {
				t.Fatalf("[RFC 8037 2, RFC 8032 5.1.5] %s must be refused, got %T", name, key)
			}
			if key != nil {
				t.Errorf("a refused read must return a nil key, not an interface holding a typed nil ed25519.PrivateKey, got %#v", key)
			}
		})
		if !test.publicRefused {
			continue
		}
		t.Run(name+", public", func(t *testing.T) {
			key, err := PublicFromJwk(test.jwk)
			if err == nil {
				t.Fatalf("[RFC 8032 5.1.3, 5.1.5] %s must be refused, got %T", name, key)
			}
			if key != nil {
				t.Errorf("a refused read must return a nil key, not an interface holding a typed nil ed25519.PublicKey, got %#v", key)
			}
		})
	}
}
