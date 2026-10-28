package jwk

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"math/big"
	"sync"
	"testing"

	"github.com/MichaelFraser99/go-jose/joseerror"
)

func rfc7517ExampleRSAKey() map[string]any {
	return map[string]any{
		"kty": "RSA",
		"n":   "0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx4cbbfAAtVT86zwu1RK7aPFFxuhDR1L6tSoc_BJECPebWKRXjBZCiFV4n3oknjhMstn64tZ_2W-5JsGY4Hc5n9yBXArwl93lqt7_RN5w6Cf0h4QyQ5v-65YGjQR0_FDW2QvzqY368QQMicAtaSqzs8KJZgnYb9c7d0zgdAZHzu6qMQvRL5hajrn1n91CbOpbISD08qNLyrdkt-bFTWhAI4vMQFh6WeZu0fM4lFd2NcRwr3XPksINHaQ-G_xBniIqbw0Ls1jF44-csFCur-kEgU8awapJzKnqDKgw",
		"e":   "AQAB",
		"d":   "X4cTteJY_gn4FYPsXB8rdXix5vwsg1FLN5E3EaG6RJoVH-HLLKD9M7dx5oo7GURknchnrRweUkC7hT5fJLM0WbFAKNLWY2vv7B6NqXSzUvxT0_YSfqijwp3RTzlBaCxWp4doFk5N2o8Gy_nHNKroADIkJ46pRUohsXywbReAdYaMwFs9tv8d_cPVY3i07a3t8MN6TNwm0dSawm9v47UiCl3Sk5ZiG7xojPLu4sbg1U2jx4IBTNBznbJSzFHK66jT8bgkuqsk0GjskDJk19Z4qwjwbsnn4j2WBii3RL-Us2lGVkY8fkFzme1z0HbIkfz0Y6mqnOYtqc0X4jfcKoAC8Q",
		"p":   "83i-7IvMGXoMXCskv73TKr8637FiO7Z27zv8oj6pbWUQyLPQBQxtPVnwD20R-60eTDmD2ujnMt5PoqMrm8RfmNhVWDtjjMmCMjOpSXicFHj7XOuVIYQyqVWlWEh6dN36GVZYk93N8Bc9vY41xy8B9RzzOGVQzXvNEvn7O0nVbfs",
		"q":   "3dfOR9cuYq-0S-mkFLzgItgMEfFzB2q3hWehMuG0oCuqnb3vobLyumqjVZQO1dIrdwgTnCdpYzBcOfW5r370AFXjiWft_NGEiovonizhKpo9VVS78TzFgxkIdrecRezsZ-1kYd_s1qDbxtkDEgfAITAG9LUnADun4vIcb6yelxk",
		"dp":  "G4sPXkc6Ya9y8oJW9_ILj4xuppu0lzi_H7VTkS8xj5SdX3coE0oimYwxIi2emTAue0UOa5dpgFGyBJ4c8tQ2VF402XRugKDTP8akYhFo5tAA77Qe_NmtuYZc3C3m3I24G2GvR5sSDxUyAN2zq8Lfn9EUms6rY3Ob8YeiKkTiBj0",
		"dq":  "s9lAH9fggBsoFR8Oac2R_E2gw282rT2kGOAhvIllETE1efrA6huUUvMfBcMpn8lqeW6vzznYY5SSQF7pMdC_agI3nG8Ibp1BUb0JUiraRNqUfLhcQb_d9GF4Dh7e74WbRsobRonujTYN1xCaP6TO61jvWrX-L18txXw494Q_cgk",
		"qi":  "GyM_p6JrXySiz1toFgKbWV-JdI3jQ4ypu9rbMWx3rQJBfmt0FoYzgUIZEVFEcOqwemRN81zoDAaa-Bk0KWNGDjJHZDdDmFhW3AN7lI-puxk_mHZGJ11rxyR8O55XLSe3SPmRfKwZI6yU24ZxvQKFYItdldUKGzO6Ia6zTKhAVRU",
		"alg": "RS256",
		"kid": "2011-04-29",
	}
}

func rsaMember(i *big.Int) string {
	return base64.RawURLEncoding.EncodeToString(i.Bytes())
}

var rsaReaderKeys struct {
	once sync.Once
	a, b *rsa.PrivateKey
	err  error
}

func rsaReaderKeyPair(t *testing.T) (*rsa.PrivateKey, *rsa.PrivateKey) {
	t.Helper()
	rsaReaderKeys.once.Do(func() {
		rsaReaderKeys.a, rsaReaderKeys.err = rsa.GenerateKey(rand.Reader, 2048)
		if rsaReaderKeys.err != nil {
			return
		}
		rsaReaderKeys.b, rsaReaderKeys.err = rsa.GenerateKey(rand.Reader, 2048)
	})
	if rsaReaderKeys.err != nil {
		t.Fatalf("failed to generate a key: %v", rsaReaderKeys.err)
	}
	return rsaReaderKeys.a, rsaReaderKeys.b
}

func rsaFullJwk(key *rsa.PrivateKey) map[string]any {
	return map[string]any{
		"kty": "RSA",
		"n":   rsaMember(key.N),
		"e":   rsaMember(big.NewInt(int64(key.E))),
		"d":   rsaMember(key.D),
		"p":   rsaMember(key.Primes[0]),
		"q":   rsaMember(key.Primes[1]),
		"dp":  rsaMember(key.Precomputed.Dp),
		"dq":  rsaMember(key.Precomputed.Dq),
		"qi":  rsaMember(key.Precomputed.Qinv),
	}
}

func rsaDOnlyJwk(key *rsa.PrivateKey) map[string]any {
	return map[string]any{
		"kty": "RSA",
		"n":   rsaMember(key.N),
		"e":   rsaMember(big.NewInt(int64(key.E))),
		"d":   rsaMember(key.D),
	}
}

func TestPublicFromJwk_ReadsAnRSAExponentExactlyOrRefusesIt(t *testing.T) {
	pow := func(bits uint) *big.Int { return new(big.Int).Lsh(big.NewInt(1), bits) }
	plus := func(a *big.Int, b int64) *big.Int { return new(big.Int).Add(a, big.NewInt(b)) }

	tests := map[string]struct {
		e      string
		accept bool
		want   int
	}{
		"65537, the RFC 7518 example":                 {e: "AQAB", accept: true, want: 65537},
		"3, the smallest RFC 3447 allows":             {e: rsaMember(big.NewInt(3)), accept: true, want: 3},
		"2^31-1, the largest crypto/rsa will use":     {e: rsaMember(plus(pow(31), -1)), accept: true, want: 1<<31 - 1},
		"65537 with a zero leading octet":             {e: "AAEAAQ", accept: true, want: 65537},
		"2^64+65537, whose low 64 bits are 65537":     {e: rsaMember(plus(pow(64), 65537))},
		"2^32+65537, whose low 32 bits are 65537":     {e: rsaMember(plus(pow(32), 65537))},
		"2^31+1, one odd value past what Go will use": {e: rsaMember(plus(pow(31), 1))},
		"2^63+65537, which overflows an int64":        {e: rsaMember(plus(pow(63), 65537))},
		"empty":                                       {e: ""},
		"zero":                                        {e: "AA"},
		"one":                                         {e: "AQ"},
		"two":                                         {e: "Ag"},
		"65536, an even value":                        {e: rsaMember(pow(16))},
	}

	n := rfc7517ExampleRSAKey()["n"]
	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			key, err := PublicFromJwk(map[string]any{"kty": "RSA", "n": n, "e": test.e})
			if test.accept {
				if err != nil {
					t.Fatalf("[RFC 7518 6.3.1.2] e of %s must be read, got %v", name, err)
				}
				if got := key.(*rsa.PublicKey).E; got != test.want {
					t.Errorf("[RFC 7518 6.3.1.2] e is the Base64urlUInt %s, so E must be %d, got %d", name, test.want, got)
				}
				return
			}
			if err == nil {
				t.Fatalf("[RFC 7518 6.3.1.2] e of %s is not an exponent crypto/rsa will use with every toolchain, so it must be refused rather than read as E=%d", name, key.(*rsa.PublicKey).E)
			}
			if !errors.Is(err, joseerror.ErrInvalidPublicKey) {
				t.Errorf("[RFC 7518 6.3.1.2] the refusal must carry the public key error class, got %v", err)
			}
			if key != nil {
				t.Errorf("no key may be returned alongside the refusal, got %#v", key)
			}
		})
	}
}

func TestPrivateFromJwk_RefusesAnRSAExponentPublicFromJwkRefuses(t *testing.T) {
	a, _ := rsaReaderKeyPair(t)
	jwk := rsaFullJwk(a)
	jwk["e"] = rsaMember(new(big.Int).Add(new(big.Int).Lsh(big.NewInt(1), 64), big.NewInt(int64(a.E))))

	key, err := PrivateFromJwk(jwk)
	if err == nil {
		t.Fatalf("[RFC 7518 6.3.1.2] an e of 2^64+%d must be refused rather than read as its low 64 bits, got %T", a.E, key)
	}
	if !errors.Is(err, joseerror.ErrInvalidPublicKey) {
		t.Errorf("[RFC 7518 6.3.1.2] the refusal must carry the public key error class of the member at fault, got %v", err)
	}
}

func TestPrivateFromJwk_RefusesAnRSAKeyWhosePrivateMembersDisagree(t *testing.T) {
	a, b := rsaReaderKeyPair(t)
	p, q := a.Primes[0], a.Primes[1]

	with := func(base map[string]any, member string, value *big.Int) map[string]any {
		out := map[string]any{}
		for k, v := range base {
			out[k] = v
		}
		out[member] = rsaMember(value)
		return out
	}
	full := rsaFullJwk(a)
	dOnly := rsaDOnlyJwk(a)
	pMinus1 := new(big.Int).Sub(p, big.NewInt(1))
	qMinus1 := new(big.Int).Sub(q, big.NewInt(1))
	lambda := new(big.Int).Mul(pMinus1, qMinus1)
	lambda.Div(lambda, new(big.Int).GCD(nil, nil, pMinus1, qMinus1))
	dPastN := new(big.Int).Add(a.D, new(big.Int).Mul(lambda, new(big.Int).Add(new(big.Int).Div(a.N, lambda), big.NewInt(1))))
	larger, smaller := a, b
	if larger.N.Cmp(smaller.N) < 0 {
		larger, smaller = b, a
	}
	otherPrivateMembers := rsaFullJwk(smaller)
	otherPrivateMembers["n"] = rsaMember(larger.N)

	tests := map[string]map[string]any{
		"d of another key, with every other member of this one":     with(full, "d", b.D),
		"d of another key reduced below n, with no primes":          with(dOnly, "d", new(big.Int).Mod(b.D, a.N)),
		"d equal to n, with no primes":                              with(dOnly, "d", a.N),
		"d zero, with no primes":                                    with(dOnly, "d", big.NewInt(0)),
		"dp moved by p-1, which still inverts e mod p-1":            with(full, "dp", new(big.Int).Add(a.Precomputed.Dp, pMinus1)),
		"dq moved by q-1, which still inverts e mod q-1":            with(full, "dq", new(big.Int).Add(a.Precomputed.Dq, qMinus1)),
		"qi moved by p, which still inverts q mod p":                with(full, "qi", new(big.Int).Add(a.Precomputed.Qinv, p)),
		"dp of another key":                                         with(full, "dp", b.Precomputed.Dp),
		"dq of another key":                                         with(full, "dq", b.Precomputed.Dq),
		"qi of another key":                                         with(full, "qi", b.Precomputed.Qinv),
		"p of one and q of n, whose product is n":                   with(with(full, "p", big.NewInt(1)), "q", a.N),
		"p and q of another key":                                    with(with(full, "p", b.Primes[0]), "q", b.Primes[1]),
		"p and q both zero":                                         with(with(full, "p", big.NewInt(0)), "q", big.NewInt(0)),
		"d past n by a multiple of lambda(n), with no primes":       with(dOnly, "d", dPastN),
		"d past n by a multiple of lambda(n), with every member":    with(full, "d", dPastN),
		"n of one and d of zero":                                    {"kty": "RSA", "n": "AQ", "e": "Aw", "d": "AA"},
		"n of three and d of three, which undoes e of three":        {"kty": "RSA", "n": "Aw", "e": "Aw", "d": "Aw"},
		"an even p of four, whose members are otherwise consistent": {"kty": "RSA", "n": "DA", "e": "BQ", "d": "BQ", "p": "BA", "q": "Aw", "dp": "Ag", "dq": "AQ", "qi": "Aw"},
		"n of one key, every private member of another":             otherPrivateMembers,
	}

	for name, jwk := range tests {
		t.Run(name, func(t *testing.T) {
			var key crypto.PrivateKey
			var err error
			func() {
				defer func() {
					if r := recover(); r != nil {
						err = fmt.Errorf("panicked: %v", r)
					}
				}()
				key, err = PrivateFromJwk(jwk)
			}()
			if err == nil {
				t.Fatalf("[RFC 7518 6.3.2] the private members carry RFC 3447 section 3.2 semantics, so a key with %s must be refused, got %T", name, key)
			}
			if !errors.Is(err, joseerror.ErrInvalidPrivateKey) {
				t.Errorf("[RFC 7518 6.3.2] the refusal must carry the private key error class, got %v", err)
			}
			if key != nil {
				t.Errorf("no key may be returned alongside the refusal, got %#v", key)
			}
		})
	}
}

func TestPrivateFromJwk_ReadsAnRSAKeyWhosePrivateMembersAgree(t *testing.T) {
	a, _ := rsaReaderKeyPair(t)
	tests := map[string]struct {
		jwk    map[string]any
		public *rsa.PublicKey
	}{
		"a generated key with every member":    {jwk: rsaFullJwk(a), public: &a.PublicKey},
		"a generated key with n, e and d only": {jwk: rsaDOnlyJwk(a), public: &a.PublicKey},
		"the RFC 7517 A.2 example key": {jwk: rfc7517ExampleRSAKey(), public: func() *rsa.PublicKey {
			n, err := base64.RawURLEncoding.DecodeString(rfc7517ExampleRSAKey()["n"].(string))
			if err != nil {
				t.Fatal(err)
			}
			return &rsa.PublicKey{N: new(big.Int).SetBytes(n), E: 65537}
		}()},
	}

	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			read, err := PrivateFromJwk(test.jwk)
			if err != nil {
				t.Fatalf("[RFC 7518 6.3.2] %s is a valid RSA private key, got %v", name, err)
			}
			key, ok := read.(*rsa.PrivateKey)
			if !ok {
				t.Fatalf("expected an *rsa.PrivateKey, got %T", read)
			}
			digest := sha256.Sum256([]byte("the signing input"))
			signature, err := rsa.SignPKCS1v15(rand.Reader, key, crypto.SHA256, digest[:])
			if err != nil {
				t.Fatalf("the key read must sign, got %v", err)
			}
			if err := rsa.VerifyPKCS1v15(test.public, crypto.SHA256, digest[:], signature); err != nil {
				t.Errorf("[RFC 7518 6.3.2] a signature by the key read must verify under the n and e the jwk carries, got %v", err)
			}
		})
	}
}

func TestPrivateFromJwk_RefusesAnRSAPrivateMemberThatIsNotABase64urlUInt(t *testing.T) {
	a, _ := rsaReaderKeyPair(t)
	for _, member := range []string{"d", "p", "q", "dp", "dq", "qi"} {
		for shape, value := range map[string]any{"not base64url": "!!!", "a number": 7} {
			t.Run(member+" "+shape, func(t *testing.T) {
				jwk := rsaFullJwk(a)
				jwk[member] = value
				key, err := PrivateFromJwk(jwk)
				if err == nil {
					t.Fatalf("[RFC 7518 6.3.2] '%s' is a Base64urlUInt, so %s must be refused, got %T", member, shape, key)
				}
				if !errors.Is(err, joseerror.ErrMalformedClaim) {
					t.Errorf("[RFC 7518 6.3.2] the refusal must name '%s' as malformed, got %v", member, err)
				}
			})
		}
	}
}
