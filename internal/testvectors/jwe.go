package testvectors

import (
	_ "embed"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
)

//go:embed jwe_examples.json
var jweExamples []byte

// JWEExample is one JWE Compact Serialization example from RFC 7516 Appendix A
// or RFC 7520 Section 5, with every value as the RFC prints it. Octet values
// are base64url-decoded; a field the example does not use is empty or nil.
//
// RecipientJWK is the recipient's private JWK, or nil for PBES2, which uses
// Password (UTF-8) instead. EphemeralJWK is the sender's ephemeral private JWK
// for ECDH-ES. CEK is the key agreed by ECDH-ES for "ECDH-ES" and the JWK "k"
// for "dir". KeyWrapIV and KeyWrapTag are the AES-GCM key wrap "iv" and "tag",
// and P2S and P2C the PBES2 salt input and iteration count. For "zip":"DEF",
// CompressedPlaintext is the raw DEFLATE of Plaintext that was encrypted.
type JWEExample struct {
	ID  string
	Alg string
	Enc string
	Zip string

	RecipientJWK map[string]any
	Password     string
	EphemeralJWK map[string]any

	Plaintext           []byte
	CompressedPlaintext []byte
	CEK                 []byte
	IV                  []byte
	KeyWrapIV           []byte
	KeyWrapTag          []byte
	P2S                 []byte
	P2C                 int

	ProtectedHeaderJSON string
	ProtectedHeader     string
	EncryptedKey        []byte
	Ciphertext          []byte
	Tag                 []byte
	Compact             string
}

// X25519Example is the ECDH-ES key agreement example from RFC 8037 Appendix
// A.6. The RFC prints no recipient private key and no JWE, so neither is here.
type X25519Example struct {
	RecipientPublicJWK  map[string]any
	RecipientPublicKey  []byte
	EphemeralPrivateKey []byte
	EphemeralPublicKey  []byte
	EphemeralPublicJWK  map[string]any
	ProtectedHeaderJSON string
	SenderZ             []byte
	ReceiverZ           []byte
}

type jweFile struct {
	JWEExamples []struct {
		ID                  string         `json:"id"`
		Alg                 string         `json:"alg"`
		Enc                 string         `json:"enc"`
		Zip                 string         `json:"zip"`
		RecipientJWK        map[string]any `json:"recipient_jwk"`
		Password            string         `json:"password"`
		EphemeralJWK        map[string]any `json:"ephemeral_jwk"`
		Plaintext           string         `json:"plaintext"`
		CompressedPlaintext string         `json:"compressed_plaintext"`
		CEK                 string         `json:"cek"`
		IV                  string         `json:"iv"`
		KeyWrapIV           string         `json:"key_wrap_iv"`
		KeyWrapTag          string         `json:"key_wrap_tag"`
		P2S                 string         `json:"p2s"`
		P2C                 int            `json:"p2c"`
		ProtectedHeaderJSON string         `json:"protected_header_json"`
		ProtectedHeader     string         `json:"protected_header"`
		EncryptedKey        string         `json:"encrypted_key"`
		Ciphertext          string         `json:"ciphertext"`
		Tag                 string         `json:"tag"`
		Compact             string         `json:"compact"`
	} `json:"jwe_examples"`
	RFC8037A6 struct {
		RecipientPublicJWK     map[string]any `json:"recipient_public_jwk"`
		RecipientPublicKeyHex  string         `json:"recipient_public_key_hex"`
		EphemeralPrivateKeyHex string         `json:"ephemeral_private_key_hex"`
		EphemeralPublicKeyHex  string         `json:"ephemeral_public_key_hex"`
		EphemeralPublicJWK     map[string]any `json:"ephemeral_public_jwk"`
		ProtectedHeaderJSON    string         `json:"protected_header_json"`
		SenderZHex             string         `json:"sender_z_hex"`
		ReceiverZHex           string         `json:"receiver_z_hex"`
	} `json:"rfc8037_a6"`
}

// JWEExamples returns the JWE examples in the order RFC7516-A.1, RFC7516-A.3,
// then RFC7520-5.2 through RFC7520-5.9. RFC 7516 A.2 and RFC 7520 5.1 use
// RSA1_5 and are left out, as are RFC 7520 5.10 to 5.13, which have no
// Compact Serialization.
//
// ProtectedHeaderJSON is the header as the RFC prints it: byte-exact for
// RFC 7516, and with RFC 7520's display whitespace kept, so it equals the
// decoded ProtectedHeader only once that whitespace is removed.
// ProtectedHeader is the base64url header as printed, which is also the
// Additional Authenticated Data.
func JWEExamples() ([]JWEExample, error) {
	var f jweFile
	if err := json.Unmarshal(jweExamples, &f); err != nil {
		return nil, err
	}
	examples := make([]JWEExample, 0, len(f.JWEExamples))
	for _, r := range f.JWEExamples {
		fields := []string{r.Plaintext, r.CompressedPlaintext, r.CEK, r.IV, r.KeyWrapIV, r.KeyWrapTag, r.P2S, r.EncryptedKey, r.Ciphertext, r.Tag}
		decoded := make([][]byte, len(fields))
		for i, s := range fields {
			if s == "" {
				continue
			}
			b, err := base64.RawURLEncoding.DecodeString(s)
			if err != nil {
				return nil, fmt.Errorf("decoding JWE example %s: %w", r.ID, err)
			}
			decoded[i] = b
		}
		examples = append(examples, JWEExample{
			ID:                  r.ID,
			Alg:                 r.Alg,
			Enc:                 r.Enc,
			Zip:                 r.Zip,
			RecipientJWK:        r.RecipientJWK,
			Password:            r.Password,
			EphemeralJWK:        r.EphemeralJWK,
			Plaintext:           decoded[0],
			CompressedPlaintext: decoded[1],
			CEK:                 decoded[2],
			IV:                  decoded[3],
			KeyWrapIV:           decoded[4],
			KeyWrapTag:          decoded[5],
			P2S:                 decoded[6],
			P2C:                 r.P2C,
			ProtectedHeaderJSON: r.ProtectedHeaderJSON,
			ProtectedHeader:     r.ProtectedHeader,
			EncryptedKey:        decoded[7],
			Ciphertext:          decoded[8],
			Tag:                 decoded[9],
			Compact:             r.Compact,
		})
	}
	return examples, nil
}

// RFC8037X25519 returns the RFC 8037 Appendix A.6 ECDH-ES with X25519 example.
// ProtectedHeaderJSON is the RFC's example header with its display line
// breaks removed.
func RFC8037X25519() (X25519Example, error) {
	var f jweFile
	if err := json.Unmarshal(jweExamples, &f); err != nil {
		return X25519Example{}, err
	}
	a := f.RFC8037A6
	hexes := []string{a.RecipientPublicKeyHex, a.EphemeralPrivateKeyHex, a.EphemeralPublicKeyHex, a.SenderZHex, a.ReceiverZHex}
	decoded := make([][]byte, len(hexes))
	for i, h := range hexes {
		b, err := hex.DecodeString(h)
		if err != nil {
			return X25519Example{}, fmt.Errorf("decoding the RFC 8037 A.6 example: %w", err)
		}
		decoded[i] = b
	}
	return X25519Example{
		RecipientPublicJWK:  a.RecipientPublicJWK,
		RecipientPublicKey:  decoded[0],
		EphemeralPrivateKey: decoded[1],
		EphemeralPublicKey:  decoded[2],
		EphemeralPublicJWK:  a.EphemeralPublicJWK,
		ProtectedHeaderJSON: a.ProtectedHeaderJSON,
		SenderZ:             decoded[3],
		ReceiverZ:           decoded[4],
	}, nil
}
