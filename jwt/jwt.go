package jwt

import (
	"crypto"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"github.com/MichaelFraser99/go-jose/model"
)

// New This function takes a signer implementation and contents for a head and body, signs them, and returns a complete jwt
func New(signer crypto.Signer, head, body map[string]any) (*string, error) {
	if s, ok := signer.(model.Signer); ok {
		if _, found := head["alg"]; !found {
			head["alg"] = s.Alg().String()
		}
	}
	return newJwt(signer, head, body)
}

func newJwt(signer crypto.Signer, head, body map[string]any) (*string, error) {
	if _, found := head["typ"]; !found {
		head["typ"] = "JWT"
	}

	headBytes, err := json.Marshal(head)
	if err != nil {
		return nil, err
	}
	bodyBytes, err := json.Marshal(body)
	if err != nil {
		return nil, err
	}
	b64Head := make([]byte, base64.RawURLEncoding.EncodedLen(len(headBytes)))
	b64Body := make([]byte, base64.RawURLEncoding.EncodedLen(len(bodyBytes)))
	base64.RawURLEncoding.Encode(b64Head, headBytes)
	base64.RawURLEncoding.Encode(b64Body, bodyBytes)

	signatureBytes, err := signer.Sign(rand.Reader, append(append(b64Head, '.'), b64Body...), model.SignerOpts{})
	if err != nil {
		return nil, err
	}
	b64Signature := make([]byte, base64.RawURLEncoding.EncodedLen(len(signatureBytes)))
	base64.RawURLEncoding.Encode(b64Signature, signatureBytes)

	finalJwt := fmt.Sprintf("%s.%s.%s", string(b64Head), string(b64Body), string(b64Signature))
	return &finalJwt, nil
}
