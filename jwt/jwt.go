package jwt

import (
	"crypto"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"github.com/MichaelFraser99/go-jose/jwa"
	"github.com/MichaelFraser99/go-jose/jws"
	"github.com/MichaelFraser99/go-jose/model"
	"slices"
	"strings"
	"time"
)

type Opts struct {
	Algorithm jwa.Algorithm
}

//todo: jwe support

// New This function takes a signer implementation and contents for a head and body, signs them, and returns a complete jwt
func New(signer crypto.Signer, head, body map[string]any, opts Opts) (*string, error) {
	if s, ok := signer.(model.Signer); ok {
		if _, found := head["alg"]; !found {
			head["alg"] = s.Alg().String()
		}
	}
	return newJwt(signer, head, body, opts)
}

// Validate verifies a token's structure, claims, and signature, returning its header and body or an error if validation fails.
func Validate(token string, outOfBoundsPublicKey model.Retriever, opts *model.JoseOptions) (head, body map[string]any, err error) {
	segments := strings.Split(token, ".")
	if len(segments) == 3 {
		head, body, err = jws.VerifyCompactSerialization(token, outOfBoundsPublicKey, opts)
		if err != nil {
			return nil, nil, fmt.Errorf("failed to verify jws compact serialization: %w", err)
		}
	} else if len(segments) == 5 {
		//todo jwe
		return nil, nil, fmt.Errorf("jwe not yet supported")
	} else {
		return nil, nil, fmt.Errorf("invalid token")
	}

	if iat, present := body["iat"]; present {
		if iatFloat64, ok := iat.(float64); !ok {
			return nil, nil, fmt.Errorf("iat claim malformed")
		} else {
			if time.Now().Unix() < int64(iatFloat64) {
				return nil, nil, fmt.Errorf("iat claim is after current time")
			}
		}
	}

	if nbf, present := body["nbf"]; present {
		if nbfFloat64, ok := nbf.(float64); !ok {
			return nil, nil, fmt.Errorf("nbf claim malformed")
		} else {
			if time.Now().Unix() < int64(nbfFloat64) {
				return nil, nil, fmt.Errorf("nbf claim is after current time")
			}
		}
	}

	if nbf, present := body["exp"]; present {
		if expFloat64, ok := nbf.(float64); !ok {
			return nil, nil, fmt.Errorf("exp claim malformed")
		} else {
			if time.Now().Unix() > int64(expFloat64) {
				return nil, nil, fmt.Errorf("exp claim is before current time")
			}
		}
	}

	return head, body, nil
}

func newJwt(signer crypto.Signer, head, body map[string]any, opts Opts) (*string, error) {
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

	signerOpts := model.SignerOpts{}
	var digest []byte
	if slices.Contains([]string{"RS256", "PS256", "ES256"}, opts.Algorithm.String()) {
		signerOpts.Hash = crypto.SHA256
	} else if slices.Contains([]string{"RS384", "PS384", "ES384"}, opts.Algorithm.String()) {
		signerOpts.Hash = crypto.SHA384
	} else if slices.Contains([]string{"RS512", "PS512", "ES512"}, opts.Algorithm.String()) {
		signerOpts.Hash = crypto.SHA512
	}

	if signerOpts.Hash != 0 {
		h := signerOpts.Hash.New()
		_, err = h.Write(append(append(b64Head, '.'), b64Body...))
		if err != nil {
			return nil, err
		}
		digest = h.Sum(nil)
	} else {
		digest = append(append(b64Head, '.'), b64Body...)
	}

	signatureBytes, err := signer.Sign(rand.Reader, digest, signerOpts)
	if err != nil {
		return nil, err
	}
	b64Signature := make([]byte, base64.RawURLEncoding.EncodedLen(len(signatureBytes)))
	base64.RawURLEncoding.Encode(b64Signature, signatureBytes)

	finalJwt := fmt.Sprintf("%s.%s.%s", string(b64Head), string(b64Body), string(b64Signature))
	return &finalJwt, nil
}
