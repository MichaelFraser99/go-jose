// Package ecdhes implements the ECDH-ES key management algorithms of RFC 7518
// section 4.6: "ECDH-ES", where the key agreed is the CEK, and
// "ECDH-ES+A128KW", "ECDH-ES+A192KW" and "ECDH-ES+A256KW", where it wraps the
// CEK. The curves are P-256, P-384 and P-521 (RFC 7518 section 6.2) and X25519
// (RFC 8037 section 3.2).
package ecdhes

import (
	"bytes"
	"crypto"
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/elliptic"
	"encoding/base64"
	"errors"
	"fmt"
	"io"

	"github.com/MichaelFraser99/go-jose/internal/algorithms/aeskw"
	"github.com/MichaelFraser99/go-jose/internal/algorithms/common"
	"github.com/MichaelFraser99/go-jose/internal/algorithms/concatkdf"
	"github.com/MichaelFraser99/go-jose/internal/algorithms/contentenc"
	"github.com/MichaelFraser99/go-jose/internal/jose/jsonutils"
	internal_jwk "github.com/MichaelFraser99/go-jose/internal/jose/jwk"
	"github.com/MichaelFraser99/go-jose/joseerror"
	"github.com/MichaelFraser99/go-jose/jwa"
	"github.com/MichaelFraser99/go-jose/model"
)

// ErrKeyAgreement is the one error Decrypt returns, whatever was wrong with the
// "epk", "apu" or "apv" it was given, so that the failure reveals nothing a
// recipient must not (RFC 7516 section 11.5).
var ErrKeyAgreement = errors.New("the ECDH-ES key agreement failed")

type Encrypter struct {
	alg    jwa.Algorithm
	public *ecdh.PublicKey
}

type Decrypter struct {
	alg     jwa.Algorithm
	private *ecdh.PrivateKey
}

var wrapKeySizes = map[jwa.Algorithm]int{
	jwa.ECDHES:       0,
	jwa.ECDHESA128KW: 16,
	jwa.ECDHESA192KW: 24,
	jwa.ECDHESA256KW: 32,
}

var curveNames = map[ecdh.Curve]string{
	ecdh.P256():   "P-256",
	ecdh.P384():   "P-384",
	ecdh.P521():   "P-521",
	ecdh.X25519(): "X25519",
}

func nistCurve(curve elliptic.Curve) bool {
	switch curve {
	case elliptic.P256(), elliptic.P384(), elliptic.P521():
		return true
	}
	return false
}

func checkAlg(alg jwa.Algorithm) error {
	if _, ok := wrapKeySizes[alg]; !ok {
		return fmt.Errorf("%w'%s' is not an ECDH-ES algorithm", joseerror.ErrUnsupportedAlgorithm, alg)
	}
	return nil
}

// NewEncrypter returns an Encrypter for alg that agrees a key with publicKey,
// the recipient's *ecdsa.PublicKey on P-256, P-384 or P-521, or *ecdh.PublicKey
// on one of those curves or X25519.
func NewEncrypter(alg jwa.Algorithm, publicKey crypto.PublicKey) (*Encrypter, error) {
	if err := checkAlg(alg); err != nil {
		return nil, err
	}
	var public *ecdh.PublicKey
	switch key := publicKey.(type) {
	case *ecdsa.PublicKey:
		if key == nil || !nistCurve(key.Curve) {
			return nil, fmt.Errorf("%wan ECDH-ES key must be on P-256, P-384 or P-521", joseerror.ErrInvalidPublicKey)
		}
		if err := common.CheckECDSAPublicKey(key, key.Curve, joseerror.ErrInvalidPublicKey); err != nil {
			return nil, err
		}
		converted, err := key.ECDH()
		if err != nil {
			return nil, fmt.Errorf("%wan ECDH-ES key must be on P-256, P-384 or P-521: %s", joseerror.ErrInvalidPublicKey, err.Error())
		}
		public = converted
	case *ecdh.PublicKey:
		public = key
	default:
		return nil, fmt.Errorf("%wshould be instance of *ecdsa.PublicKey or *ecdh.PublicKey", joseerror.ErrInvalidPublicKey)
	}
	if public == nil || curveNames[public.Curve()] == "" {
		return nil, fmt.Errorf("%wan ECDH-ES key must be on P-256, P-384, P-521 or X25519", joseerror.ErrInvalidPublicKey)
	}
	return &Encrypter{alg: alg, public: public}, nil
}

// NewDecrypter returns a Decrypter for alg with privateKey, an
// *ecdsa.PrivateKey on P-256, P-384 or P-521, or an *ecdh.PrivateKey on one of
// those curves or X25519. An *ecdsa.PrivateKey's point must be the public point
// of its scalar d, as RFC 7518 section 6.2.2.1 requires.
func NewDecrypter(alg jwa.Algorithm, privateKey crypto.PrivateKey) (*Decrypter, error) {
	if err := checkAlg(alg); err != nil {
		return nil, err
	}
	var private *ecdh.PrivateKey
	switch key := privateKey.(type) {
	case *ecdsa.PrivateKey:
		if key == nil || !nistCurve(key.Curve) {
			return nil, fmt.Errorf("%wan ECDH-ES key must be on P-256, P-384 or P-521", joseerror.ErrInvalidPrivateKey)
		}
		if err := common.CheckECDSAPrivateKey(key, key.Curve); err != nil {
			return nil, err
		}
		converted, err := key.ECDH()
		if err != nil {
			return nil, fmt.Errorf("%wan ECDH-ES key must be on P-256, P-384 or P-521: %s", joseerror.ErrInvalidPrivateKey, err.Error())
		}
		private = converted
	case *ecdh.PrivateKey:
		private = key
	default:
		return nil, fmt.Errorf("%wshould be instance of *ecdsa.PrivateKey or *ecdh.PrivateKey", joseerror.ErrInvalidPrivateKey)
	}
	if private == nil || curveNames[private.Curve()] == "" {
		return nil, fmt.Errorf("%wan ECDH-ES key must be on P-256, P-384, P-521 or X25519", joseerror.ErrInvalidPrivateKey)
	}
	return &Decrypter{alg: alg, private: private}, nil
}

func (encrypter *Encrypter) Alg() jwa.Algorithm {
	return encrypter.alg
}

func (encrypter *Encrypter) Public() crypto.PublicKey {
	return encrypter.public
}

// WrapKey generates a fresh ephemeral key on the recipient's curve, as RFC 7518
// section 4.6 requires for each key agreement, writes its public half into
// header as "epk", and derives the key with the Concat KDF of section 4.6.2,
// using any "apu" and "apv" already in header. For ECDH-ES that key is the
// CEK and the JWE Encrypted Key is empty. Otherwise it wraps a random CEK.
// A header that already holds "epk", or whose "apu" and "apv" are equal or not
// base64url strings, is refused with ErrMalformedClaim.
func (encrypter *Encrypter) WrapKey(rand io.Reader, enc jwa.Encryption, header map[string]any) (cek, encryptedKey []byte, err error) {
	if _, present := header["epk"]; present {
		return nil, nil, fmt.Errorf("%wthe 'epk' header is generated for each token and must not be given", joseerror.ErrMalformedClaim)
	}
	partyU, partyV, err := PartyInfo(header)
	if err != nil {
		return nil, nil, err
	}
	ephemeral, err := encrypter.public.Curve().GenerateKey(rand)
	if err != nil {
		return nil, nil, fmt.Errorf("%wgenerating an ephemeral key: %s", joseerror.ErrEncryptionError, err.Error())
	}
	return encrypter.wrapWith(ephemeral, rand, enc, header, partyU, partyV)
}

func (encrypter *Encrypter) wrapWith(ephemeral *ecdh.PrivateKey, rand io.Reader, enc jwa.Encryption, header map[string]any, partyU, partyV []byte) (cek, encryptedKey []byte, err error) {
	size := contentenc.KeySize(enc)
	if size == 0 {
		return nil, nil, fmt.Errorf("%w%s is not a content encryption algorithm this library implements", joseerror.ErrUnsupportedAlgorithm, contentenc.Name(enc))
	}
	z, err := ephemeral.ECDH(encrypter.public)
	if err != nil {
		return nil, nil, fmt.Errorf("%wthe key agreement failed: %s", joseerror.ErrEncryptionError, err.Error())
	}
	header["epk"] = publicJwk(ephemeral.PublicKey())
	key, err := derive(encrypter.alg, enc, z, partyU, partyV)
	if err != nil {
		return nil, nil, fmt.Errorf("%w%s", joseerror.ErrEncryptionError, err.Error())
	}
	if encrypter.alg == jwa.ECDHES {
		return key, []byte{}, nil
	}
	cek = make([]byte, size)
	if _, err := io.ReadFull(rand, cek); err != nil {
		return nil, nil, fmt.Errorf("%wgenerating a content encryption key: %s", joseerror.ErrEncryptionError, err.Error())
	}
	encryptedKey, err = aeskw.Wrap(key, cek)
	if err != nil {
		return nil, nil, fmt.Errorf("%wwrapping the content encryption key: %s", joseerror.ErrEncryptionError, err.Error())
	}
	return cek, encryptedKey, nil
}

func (decrypter *Decrypter) Alg() jwa.Algorithm {
	return decrypter.alg
}

func (decrypter *Decrypter) Public() crypto.PublicKey {
	return decrypter.private.PublicKey()
}

// Decrypt agrees a key with the "epk" in the JWE Protected Header that opts,
// a model.DecrypterOpts, carries, and recovers the CEK from it and msg, the JWE
// Encrypted Key. The "epk" must be a public key on this decrypter's curve, as
// RFC 8725 section 3.4 requires. Any failure is ErrKeyAgreement, or
// aeskw.ErrUnwrap for a wrapped key that does not unwrap.
func (decrypter *Decrypter) Decrypt(_ io.Reader, msg []byte, opts crypto.DecrypterOpts) ([]byte, error) {
	options, ok := opts.(model.DecrypterOpts)
	if !ok {
		return nil, ErrKeyAgreement
	}
	epk, ok := options.Header["epk"].(map[string]any)
	if !ok {
		return nil, ErrKeyAgreement
	}
	public, err := EphemeralPublicKey(epk)
	if err != nil {
		return nil, ErrKeyAgreement
	}
	partyU, partyV, err := PartyInfo(options.Header)
	if err != nil {
		return nil, ErrKeyAgreement
	}
	z, err := decrypter.private.ECDH(public)
	if err != nil {
		return nil, ErrKeyAgreement
	}
	key, err := derive(decrypter.alg, options.Enc, z, partyU, partyV)
	if err != nil {
		return nil, ErrKeyAgreement
	}
	if decrypter.alg == jwa.ECDHES {
		if len(msg) != 0 {
			return nil, ErrKeyAgreement
		}
		return key, nil
	}
	return aeskw.Unwrap(key, msg)
}

func derive(alg jwa.Algorithm, enc jwa.Encryption, z, partyU, partyV []byte) ([]byte, error) {
	if alg == jwa.ECDHES {
		size := contentenc.KeySize(enc)
		if size == 0 {
			return nil, fmt.Errorf("%s is not a content encryption algorithm this library implements", contentenc.Name(enc))
		}
		return concatkdf.Derive(z, size*8, []byte(enc.String()), partyU, partyV)
	}
	return concatkdf.Derive(z, wrapKeySizes[alg]*8, []byte(alg.String()), partyU, partyV)
}

// PartyInfo reads the "apu" and "apv" headers that enter the Concat KDF. Each
// is a base64url string, and RFC 7518 section 4.6.2 requires the two to be
// distinct; any other value is refused with ErrMalformedClaim.
func PartyInfo(header map[string]any) (partyU, partyV []byte, err error) {
	for _, name := range []string{"apu", "apv"} {
		raw, present := header[name]
		if !present {
			continue
		}
		encoded, ok := raw.(string)
		if !ok {
			return nil, nil, fmt.Errorf("%wthe '%s' header must be a base64url string", joseerror.ErrMalformedClaim, name)
		}
		decoded, err := jsonutils.DecodeBase64url(encoded)
		if err != nil {
			return nil, nil, fmt.Errorf("%wthe '%s' header must be a base64url string", joseerror.ErrMalformedClaim, name)
		}
		if name == "apu" {
			partyU = decoded
		} else {
			partyV = decoded
		}
	}
	_, hasU := header["apu"]
	_, hasV := header["apv"]
	if hasU && hasV && bytes.Equal(partyU, partyV) {
		return nil, nil, fmt.Errorf("%wthe 'apu' and 'apv' headers must be distinct (RFC 7518 section 4.6.2)", joseerror.ErrMalformedClaim)
	}
	return partyU, partyV, nil
}

// EphemeralPublicKey reads an "epk" header as a public key on a curve this
// package implements, refusing one that carries a private member, as RFC 7518
// section 4.6.1.1 requires. A key that cannot agree a key at all, one whose
// "kty" is not "EC" or "OKP", or an OKP key whose subtype is not X25519 or
// X448 (RFC 8037 section 3.2), is ErrMalformedClaim. An EC or OKP key on a
// curve this package does not implement, such as X448, is
// ErrUnsupportedAlgorithm.
func EphemeralPublicKey(epk map[string]any) (*ecdh.PublicKey, error) {
	if _, private := epk["d"]; private {
		return nil, fmt.Errorf("%wthe 'epk' header must hold only public key members", joseerror.ErrMalformedClaim)
	}
	switch epk["kty"] {
	case "EC":
	case "OKP":
		if crv := epk["crv"]; crv != "X25519" && crv != "X448" {
			return nil, fmt.Errorf("%wthe 'epk' header is an OKP key of a subtype other than X25519 or X448, so it cannot agree a key (RFC 8037 section 3.2)", joseerror.ErrMalformedClaim)
		}
	default:
		return nil, fmt.Errorf("%wthe 'epk' header is not an EC or OKP key, so it cannot agree a key (RFC 7518 section 4.6)", joseerror.ErrMalformedClaim)
	}
	key, err := internal_jwk.PublicFromJwk(epk)
	if err != nil {
		return nil, err
	}
	switch public := key.(type) {
	case *ecdh.PublicKey:
		return public, nil
	case *ecdsa.PublicKey:
		converted, err := public.ECDH()
		if err != nil {
			return nil, fmt.Errorf("%wthe 'epk' header is not a key on P-256, P-384 or P-521", joseerror.ErrMalformedClaim)
		}
		return converted, nil
	}
	return nil, fmt.Errorf("%wthe 'epk' header is not an EC or X25519 key, so it cannot agree a key (RFC 8037 section 3.2)", joseerror.ErrMalformedClaim)
}

func publicJwk(public *ecdh.PublicKey) map[string]any {
	name := curveNames[public.Curve()]
	encoded := public.Bytes()
	if public.Curve() == ecdh.X25519() {
		return map[string]any{"kty": "OKP", "crv": name, "x": base64.RawURLEncoding.EncodeToString(encoded)}
	}
	coordinates := encoded[1:]
	half := len(coordinates) / 2
	return map[string]any{
		"kty": "EC",
		"crv": name,
		"x":   base64.RawURLEncoding.EncodeToString(coordinates[:half]),
		"y":   base64.RawURLEncoding.EncodeToString(coordinates[half:]),
	}
}
