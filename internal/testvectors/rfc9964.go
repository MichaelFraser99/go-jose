package testvectors

import (
	_ "embed"
	"encoding/hex"
	"encoding/json"
	"fmt"
)

//go:embed rfc9964_a1.json
var rfc9964 []byte

// MLDSAExample is one ML-DSA example from RFC 9964 Appendix A.1.
type MLDSAExample struct {
	Alg          string
	Seed         []byte
	PublicKey    []byte
	PrivateJwk   map[string]any
	JWS          string
	SigningInput []byte
	Signature    []byte
}

// RFC9964 returns the RFC 9964 Appendix A.1 examples, for ML-DSA-44, ML-DSA-65
// and ML-DSA-87 in that order.
func RFC9964() ([]MLDSAExample, error) {
	var raw []struct {
		Priv          string         `json:"priv"`
		Jwk           map[string]any `json:"jwk"`
		Jws           string         `json:"jws"`
		RawPublicKey  string         `json:"raw_public_key"`
		RawSignature  string         `json:"raw_signature"`
		RawToBeSigned string         `json:"raw_to_be_signed"`
	}
	if err := json.Unmarshal(rfc9964, &raw); err != nil {
		return nil, err
	}
	examples := make([]MLDSAExample, 0, len(raw))
	for _, r := range raw {
		decoded := make([][]byte, 4)
		for i, h := range []string{r.Priv, r.RawPublicKey, r.RawToBeSigned, r.RawSignature} {
			b, err := hex.DecodeString(h)
			if err != nil {
				return nil, fmt.Errorf("decoding an RFC 9964 example: %w", err)
			}
			decoded[i] = b
		}
		alg, _ := r.Jwk["alg"].(string)
		examples = append(examples, MLDSAExample{
			Alg:          alg,
			Seed:         decoded[0],
			PublicKey:    decoded[1],
			PrivateJwk:   r.Jwk,
			JWS:          r.Jws,
			SigningInput: decoded[2],
			Signature:    decoded[3],
		})
	}
	return examples, nil
}
