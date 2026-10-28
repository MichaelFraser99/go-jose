package jwk

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"math/big"
	"testing"

	"github.com/MichaelFraser99/go-jose/joseerror"
)

type ecReaderCurve struct {
	name  string
	curve elliptic.Curve
	size  int
}

func ecReaderCurves() []ecReaderCurve {
	return []ecReaderCurve{
		{name: "P-256", curve: elliptic.P256(), size: 32},
		{name: "P-384", curve: elliptic.P384(), size: 48},
		{name: "P-521", curve: elliptic.P521(), size: 66},
	}
}

func ecOctets(i *big.Int, size int) []byte {
	return i.FillBytes(make([]byte, size))
}

func ecMember(b []byte) string {
	return base64.RawURLEncoding.EncodeToString(b)
}

func ecPointJwk(c ecReaderCurve, x, y *big.Int) map[string]any {
	return map[string]any{
		"kty": "EC",
		"crv": c.name,
		"x":   ecMember(ecOctets(x, c.size)),
		"y":   ecMember(ecOctets(y, c.size)),
	}
}

func ecPrivateJwk(c ecReaderCurve, x, y, d *big.Int) map[string]any {
	jwk := ecPointJwk(c, x, y)
	jwk["d"] = ecMember(ecOctets(d, c.size))
	return jwk
}

func ecKeyWhere(t *testing.T, c ecReaderCurve, want func(*ecdsa.PrivateKey) bool) *ecdsa.PrivateKey {
	t.Helper()
	for i := 0; i < 100000; i++ {
		key, err := ecdsa.GenerateKey(c.curve, rand.Reader)
		if err != nil {
			t.Fatalf("failed to generate a key: %v", err)
		}
		if want(key) {
			return key
		}
	}
	t.Fatalf("no %s key with the wanted shape was generated", c.name)
	return nil
}

func ecLeadingOctetIsZero(i *big.Int, size int) bool {
	return ecOctets(i, size)[0] == 0
}

func ecReaders() map[string]struct {
	read  func(map[string]any) (any, error)
	class error
} {
	return map[string]struct {
		read  func(map[string]any) (any, error)
		class error
	}{
		"PublicFromJwk":  {read: func(j map[string]any) (any, error) { return PublicFromJwk(j) }, class: joseerror.ErrInvalidPublicKey},
		"PrivateFromJwk": {read: func(j map[string]any) (any, error) { return PrivateFromJwk(j) }, class: joseerror.ErrInvalidPrivateKey},
	}
}

func TestPrivateFromJwk_RefusesAnEcJwkWithoutD(t *testing.T) {
	for _, c := range ecReaderCurves() {
		t.Run(c.name, func(t *testing.T) {
			key, err := ecdsa.GenerateKey(c.curve, rand.Reader)
			if err != nil {
				t.Fatal(err)
			}
			read, err := PrivateFromJwk(ecPointJwk(c, key.X, key.Y))
			if err == nil {
				t.Fatalf("[RFC 7518 6.2.2] 'd' MUST be present in an EC private key, so a jwk without it must be refused, got %T", read)
			}
			if !errors.Is(err, joseerror.ErrInvalidPrivateKey) {
				t.Errorf("[RFC 7518 6.2.2] the refusal must carry the private key error class, got %v", err)
			}
			if !errors.Is(err, joseerror.ErrMissingClaim) {
				t.Errorf("[RFC 7518 6.2.2] the refusal must name 'd' as the missing member, got %v", err)
			}
			if read != nil {
				t.Errorf("no key may be returned alongside the refusal, got %#v", read)
			}
		})
	}
}

func TestFromJwk_RefusesAnEcCoordinateThatIsNotTheFullCoordinateSize(t *testing.T) {
	for _, c := range ecReaderCurves() {
		shortX := ecKeyWhere(t, c, func(k *ecdsa.PrivateKey) bool { return ecLeadingOctetIsZero(k.X, c.size) })
		shortY := ecKeyWhere(t, c, func(k *ecdsa.PrivateKey) bool { return ecLeadingOctetIsZero(k.Y, c.size) })
		whole, err := ecdsa.GenerateKey(c.curve, rand.Reader)
		if err != nil {
			t.Fatal(err)
		}

		tests := map[string]map[string]any{
			"x with its zero leading octet dropped": func() map[string]any {
				j := ecPrivateJwk(c, shortX.X, shortX.Y, shortX.D)
				j["x"] = ecMember(ecOctets(shortX.X, c.size)[1:])
				return j
			}(),
			"y with its zero leading octet dropped": func() map[string]any {
				j := ecPrivateJwk(c, shortY.X, shortY.Y, shortY.D)
				j["y"] = ecMember(ecOctets(shortY.Y, c.size)[1:])
				return j
			}(),
			"x with a zero octet prepended": func() map[string]any {
				j := ecPrivateJwk(c, whole.X, whole.Y, whole.D)
				j["x"] = ecMember(append([]byte{0}, ecOctets(whole.X, c.size)...))
				return j
			}(),
			"y with a zero octet prepended": func() map[string]any {
				j := ecPrivateJwk(c, whole.X, whole.Y, whole.D)
				j["y"] = ecMember(append([]byte{0}, ecOctets(whole.Y, c.size)...))
				return j
			}(),
		}

		for readerName, reader := range ecReaders() {
			for name, jwk := range tests {
				t.Run(c.name+" "+readerName+" "+name, func(t *testing.T) {
					key, err := reader.read(jwk)
					if err == nil {
						t.Fatalf("[RFC 7518 6.2.1.2] the octet string MUST be the full size of a coordinate for %s, %d octets, so %s must be refused, got %T", c.name, c.size, name, key)
					}
					if !errors.Is(err, reader.class) {
						t.Errorf("[RFC 7518 6.2.1.2] the refusal must carry the key error class, got %v", err)
					}
					if key != nil {
						t.Errorf("no key may be returned alongside the refusal, got %#v", key)
					}
				})
			}
		}
	}
}

func TestPrivateFromJwk_RefusesAnEcDThatIsNotTheLengthOfTheOrder(t *testing.T) {
	for _, c := range ecReaderCurves() {
		shortD := ecKeyWhere(t, c, func(k *ecdsa.PrivateKey) bool { return ecLeadingOctetIsZero(k.D, c.size) })
		whole, err := ecdsa.GenerateKey(c.curve, rand.Reader)
		if err != nil {
			t.Fatal(err)
		}

		tests := map[string]map[string]any{
			"d with its zero leading octet dropped": func() map[string]any {
				j := ecPrivateJwk(c, shortD.X, shortD.Y, shortD.D)
				j["d"] = ecMember(ecOctets(shortD.D, c.size)[1:])
				return j
			}(),
			"d with a zero octet prepended": func() map[string]any {
				j := ecPrivateJwk(c, whole.X, whole.Y, whole.D)
				j["d"] = ecMember(append([]byte{0}, ecOctets(whole.D, c.size)...))
				return j
			}(),
			"d empty": func() map[string]any {
				j := ecPrivateJwk(c, whole.X, whole.Y, whole.D)
				j["d"] = ""
				return j
			}(),
		}

		for name, jwk := range tests {
			t.Run(c.name+" "+name, func(t *testing.T) {
				key, err := PrivateFromJwk(jwk)
				if err == nil {
					t.Fatalf("[RFC 7518 6.2.2.1] 'd' MUST be ceiling(log-base-2(n)/8) octets, %d for %s, so %s must be refused, got %T", c.size, c.name, name, key)
				}
				if !errors.Is(err, joseerror.ErrInvalidPrivateKey) {
					t.Errorf("[RFC 7518 6.2.2.1] the refusal must carry the private key error class, got %v", err)
				}
				if key != nil {
					t.Errorf("no key may be returned alongside the refusal, got %#v", key)
				}
			})
		}
	}
}

func TestFromJwk_RefusesAnEcPointThatIsNotOnItsCurve(t *testing.T) {
	for _, c := range ecReaderCurves() {
		key, err := ecdsa.GenerateKey(c.curve, rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		p := c.curve.Params().P
		nextY := new(big.Int).Add(key.Y, big.NewInt(1))
		nextY.Mod(nextY, p)

		tests := map[string]map[string]any{
			"y moved by one": ecPrivateJwk(c, key.X, nextY, key.D),
		}
		if xPlusP := new(big.Int).Add(key.X, p); xPlusP.BitLen() <= 8*c.size {
			tests["x past the field prime by p"] = ecPrivateJwk(c, xPlusP, key.Y, key.D)
		}

		for readerName, reader := range ecReaders() {
			for name, jwk := range tests {
				t.Run(c.name+" "+readerName+" "+name, func(t *testing.T) {
					read, err := reader.read(jwk)
					if err == nil {
						t.Fatalf("[RFC 7518 6.2.1] x and y are the coordinates of a point on %s, so a point with %s must be refused, got %T", c.name, name, read)
					}
					if !errors.Is(err, reader.class) {
						t.Errorf("[RFC 7518 6.2.1] the refusal must carry the key error class, got %v", err)
					}
					if read != nil {
						t.Errorf("no key may be returned alongside the refusal, got %#v", read)
					}
				})
			}
		}
	}
}

func TestPrivateFromJwk_RefusesAnEcDThatIsNotThePrivateKeyOfItsPoint(t *testing.T) {
	for _, c := range ecReaderCurves() {
		params := c.curve.Params()
		a, err := ecdsa.GenerateKey(c.curve, rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		b, err := ecdsa.GenerateKey(c.curve, rand.Reader)
		if err != nil {
			t.Fatal(err)
		}

		tests := map[string]map[string]any{
			"x and y of one key, d of another":                 ecPrivateJwk(c, a.X, a.Y, b.D),
			"d one past the order, which multiplies G to G":    ecPrivateJwk(c, params.Gx, params.Gy, new(big.Int).Add(params.N, big.NewInt(1))),
			"d equal to the order, with G as its public point": ecPrivateJwk(c, params.Gx, params.Gy, params.N),
			"d zero, with G as its public point":               ecPrivateJwk(c, params.Gx, params.Gy, big.NewInt(0)),
		}

		for name, jwk := range tests {
			t.Run(c.name+" "+name, func(t *testing.T) {
				key, err := PrivateFromJwk(jwk)
				if err == nil {
					t.Fatalf("[RFC 7518 6.2.2.1] 'd' is the private key value of the point x, y, so %s must be refused, got %T", name, key)
				}
				if !errors.Is(err, joseerror.ErrInvalidPrivateKey) {
					t.Errorf("[RFC 7518 6.2.2.1] the refusal must carry the private key error class, got %v", err)
				}
				if key != nil {
					t.Errorf("no key may be returned alongside the refusal, got %#v", key)
				}
			})
		}
	}
}

func TestPrivateFromJwk_AcceptsAnEcKeyWhoseDIsThePrivateKeyOfItsPoint(t *testing.T) {
	for _, c := range ecReaderCurves() {
		params := c.curve.Params()
		generated, err := ecdsa.GenerateKey(c.curve, rand.Reader)
		if err != nil {
			t.Fatal(err)
		}

		tests := map[string]struct {
			x, y, d *big.Int
		}{
			"d of one, whose point is G":               {x: params.Gx, y: params.Gy, d: big.NewInt(1)},
			"d of n minus one, whose point is minus G": {x: params.Gx, y: new(big.Int).Sub(params.P, params.Gy), d: new(big.Int).Sub(params.N, big.NewInt(1))},
			"a generated key":                          {x: generated.X, y: generated.Y, d: generated.D},
		}

		for name, test := range tests {
			t.Run(c.name+" "+name, func(t *testing.T) {
				read, err := PrivateFromJwk(ecPrivateJwk(c, test.x, test.y, test.d))
				if err != nil {
					t.Fatalf("[RFC 7518 6.2.2.1] %s is a valid private key, got %v", name, err)
				}
				key, ok := read.(*ecdsa.PrivateKey)
				if !ok {
					t.Fatalf("expected an *ecdsa.PrivateKey, got %T", read)
				}
				public := ecdsa.PublicKey{Curve: c.curve, X: test.x, Y: test.y}
				digest := sha256.Sum256([]byte("the signing input"))
				r, s, err := ecdsa.Sign(rand.Reader, key, digest[:])
				if err != nil {
					t.Fatalf("the key read must sign, got %v", err)
				}
				if !ecdsa.Verify(&public, digest[:], r, s) {
					t.Errorf("[RFC 7518 6.2.2.1] a signature by the key read must verify under the point x, y the jwk carries")
				}
			})
		}
	}
}

func TestFromJwk_ReadsTheRFC7517ExampleEcKey(t *testing.T) {
	example := map[string]any{
		"kty": "EC",
		"crv": "P-256",
		"x":   "MKBCTNIcKUSDii11ySs3526iDZ8AiTo7Tu6KPAqv7D4",
		"y":   "4Etl6SRW2YiLUrN5vfvVHuhp7x8PxltmWWlbbM4IFyM",
		"d":   "870MB6gfuTJ4HtUnUvYMyJpr5eUZNP4Bk43bVdj3eAE",
		"use": "enc",
		"kid": "1",
	}
	if _, err := PublicFromJwk(example); err != nil {
		t.Errorf("[RFC 7517 A.2] the example EC key must be read as a public key, got %v", err)
	}
	if _, err := PrivateFromJwk(example); err != nil {
		t.Errorf("[RFC 7517 A.2] the example EC key must be read as a private key, got %v", err)
	}
}
