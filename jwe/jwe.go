package jwe

import (
	"crypto"
	"fmt"
	"github.com/MichaelFraser99/go-jose/internal/jose/header"
	"github.com/MichaelFraser99/go-jose/internal/jose/jsonutils"
	"github.com/MichaelFraser99/go-jose/joseerror"
	"github.com/MichaelFraser99/go-jose/model"
	"strings"
)

/*
   BASE64URL(UTF8(JWE Protected Header)) || '.' ||
   BASE64URL(JWE Encrypted Key) || '.' ||
   BASE64URL(JWE Initialization Vector) || '.' ||
   BASE64URL(JWE Ciphertext) || '.' ||
   BASE64URL(JWE Authentication Tag)
*/

func VerifyCompactSerialization(compactSerialization string, publicKey crypto.PublicKey) (protectedHeader, body map[string]any, err error) {
	components := strings.Split(compactSerialization, ".")
	if len(components) != 5 {
		return nil, nil, fmt.Errorf("%winvalid compact serialization format", joseerror.MalformedToken)
	}

	protectedHeader, err = jsonutils.DecodeBase64urlMap(components[0])
	if err != nil {
		return nil, nil, fmt.Errorf("%werror processing protected header: %v", joseerror.MalformedToken, err)
	}

	var jwkRetrievers []model.Retriever

	if publicKey != nil {
		jwkRetrievers = []model.Retriever{
			func() ([]crypto.PublicKey, error) {
				return []crypto.PublicKey{publicKey}, nil
			},
		}
	}

	headerJwkRetrievers, err := header.ValidateHeader(protectedHeader, nil, model.JWE) //todo: sort out client providing
	if err != nil {
		return nil, nil, fmt.Errorf("%werror validating header: %v", joseerror.MalformedToken, err)
	}

	jwkRetrievers = append(jwkRetrievers, headerJwkRetrievers...)

	if len(jwkRetrievers) == 0 {
		return nil, nil, fmt.Errorf("%wno cyptographic material provided for decryption", joseerror.MalformedToken)
	}

}
