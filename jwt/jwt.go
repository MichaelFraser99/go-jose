package jwt

import (
	"crypto"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"github.com/MichaelFraser99/go-jose/internal/algorithms/common"
	"github.com/MichaelFraser99/go-jose/internal/algorithms/es256"
	"github.com/MichaelFraser99/go-jose/internal/algorithms/es384"
	"github.com/MichaelFraser99/go-jose/internal/algorithms/es512"
	"github.com/MichaelFraser99/go-jose/internal/algorithms/hs256"
	"github.com/MichaelFraser99/go-jose/internal/algorithms/hs384"
	"github.com/MichaelFraser99/go-jose/internal/algorithms/hs512"
	"github.com/MichaelFraser99/go-jose/internal/algorithms/ps256"
	"github.com/MichaelFraser99/go-jose/internal/algorithms/ps384"
	"github.com/MichaelFraser99/go-jose/internal/algorithms/ps512"
	"github.com/MichaelFraser99/go-jose/internal/algorithms/rs256"
	"github.com/MichaelFraser99/go-jose/internal/algorithms/rs384"
	"github.com/MichaelFraser99/go-jose/internal/algorithms/rs512"
	"github.com/MichaelFraser99/go-jose/model"
	"slices"
	"strings"
	"time"
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

// Validate This function takes a public key (must be a valid []byte if using the symmetric HS algorithms) and errors if the provided jwt isn't valid.
// The iat, nbf, and exp claims will be validated if present.
// The returned values are the head
func Validate(publicKey crypto.PublicKey, jwt string) (head, body map[string]any, err error) {
	jwtComponents := strings.Split(jwt, ".")
	if len(jwtComponents) != 3 {
		return nil, nil, fmt.Errorf("malformed jwt provided")
	}
	headBytes, err := base64.RawURLEncoding.DecodeString(jwtComponents[0])
	if err != nil {
		return nil, nil, fmt.Errorf("error decoding head base64url: %w", err)
	}
	bodyBytes, err := base64.RawURLEncoding.DecodeString(jwtComponents[1])
	if err != nil {
		return nil, nil, fmt.Errorf("error decoding body base64url: %w", err)
	}
	signatureBytes, err := base64.RawURLEncoding.DecodeString(jwtComponents[2])
	if err != nil {
		return nil, nil, fmt.Errorf("error decoding signature base64url: %w", err)
	}

	if err = json.Unmarshal(headBytes, &head); err != nil {
		return nil, nil, fmt.Errorf("error unmarshalling head into a readable format: %w", err)
	}
	if err = json.Unmarshal(bodyBytes, &body); err != nil {
		return nil, nil, fmt.Errorf("error unmarshalling body into a readable format: %w", err)
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

	alg, present := head["alg"]
	if !present {
		return nil, nil, fmt.Errorf("no alg claim present in head, cannot validate")
	}

	var v model.Validator
	parsedAlgorithm := model.GetAlgorithm(alg.(string))
	if parsedAlgorithm == nil {
		return nil, nil, fmt.Errorf("unknown algorithm claim value: %s", alg.(string))
	}
	switch *parsedAlgorithm {
	case model.ES256:
		v, err = es256.NewValidator(publicKey)
	case model.ES384:
		v, err = es384.NewValidator(publicKey)
	case model.ES512:
		v, err = es512.NewValidator(publicKey)
	case model.RS256:
		v, err = rs256.NewValidator(publicKey)
	case model.RS384:
		v, err = rs384.NewValidator(publicKey)
	case model.RS512:
		v, err = rs512.NewValidator(publicKey)
	case model.PS256:
		v, err = ps256.NewValidator(publicKey)
	case model.PS384:
		v, err = ps384.NewValidator(publicKey)
	case model.PS512:
		v, err = ps512.NewValidator(publicKey)
	case model.HS256:
		return head, body, validateSymmetricAlgorithm(model.HS256, publicKey, []byte(fmt.Sprintf("%s.%s", jwtComponents[0], jwtComponents[1])), signatureBytes)
	case model.HS384:
		return head, body, validateSymmetricAlgorithm(model.HS384, publicKey, []byte(fmt.Sprintf("%s.%s", jwtComponents[0], jwtComponents[1])), signatureBytes)
	case model.HS512:
		return head, body, validateSymmetricAlgorithm(model.HS512, publicKey, []byte(fmt.Sprintf("%s.%s", jwtComponents[0], jwtComponents[1])), signatureBytes)
	}
	if err != nil {
		return nil, nil, fmt.Errorf("error created validator from provided algorithm: %w", err)
	}
	valid, err := v.ValidateSignature([]byte(fmt.Sprintf("%s.%s", jwtComponents[0], jwtComponents[1])), signatureBytes)
	if err != nil {
		return nil, nil, fmt.Errorf("error validating signature: %w", err)
	}
	if valid {
		return head, body, nil
	} else {
		return nil, nil, fmt.Errorf("signature invalid")
	}
}

func validateSymmetricAlgorithm(alg model.Algorithm, publicKey crypto.PublicKey, digest, signature []byte) error {
	var signer model.Signer
	var err error
	var passphrase []byte
	var ok bool
	if passphrase, ok = publicKey.([]byte); !ok {
		var secretKeyPassphrase common.SecretKey
		if secretKeyPassphrase, ok = publicKey.(common.SecretKey); !ok {
			return fmt.Errorf("provided publicKey must be either a valid []byte or common.SecretKey instance")
		} else {
			passphrase = secretKeyPassphrase
		}
	}
	if alg == model.HS256 {
		signer, err = hs256.NewSigner(&passphrase)
		if err != nil {
			return fmt.Errorf("failed to create hs256 signer from provided passphrase: %w", err)
		}
	}
	if alg == model.HS384 {
		signer, err = hs384.NewSigner(&passphrase)
		if err != nil {
			return fmt.Errorf("failed to create hs384 signer from provided passphrase: %w", err)
		}
	}
	if alg == model.HS512 {
		signer, err = hs512.NewSigner(&passphrase)
		if err != nil {
			return fmt.Errorf("failed to create hs512 signer from provided passphrase: %w", err)
		}
	}
	newSignature, err := signer.Sign(rand.Reader, digest, model.SignerOpts{})
	if err != nil {
		return fmt.Errorf("failed to generate signature for valdiation: %w", err)
	}
	if slices.Compare(newSignature, signature) != 0 {
		return fmt.Errorf("invalid signature")
	}

	return nil
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
