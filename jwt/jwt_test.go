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
	"maps"
	"slices"
	"strings"
	"testing"
	"time"
)

func TestNew(t *testing.T) {
	tests := []struct {
		name      string
		signer    func(t *testing.T) model.Signer
		validator func(t *testing.T, pubKey crypto.PublicKey) model.Validator
		head      map[string]any
		body      map[string]any
		validate  func(t *testing.T, validator model.Validator, jwt *string, err error)
	}{
		{
			name: "we can sign a jwt with rs256",
			signer: func(t *testing.T) model.Signer {
				t.Helper()
				signer, err := rs256.NewSigner(2048)
				if err != nil {
					t.Fatalf("no error should be thrown: %s", err.Error())
				}
				return signer
			},
			validator: func(t *testing.T, pubKey crypto.PublicKey) model.Validator {
				t.Helper()
				validator, err := rs256.NewValidator(pubKey)
				if err != nil {
					t.Fatalf("no error should be thrown: %s", err.Error())
				}
				return validator
			},
			head: map[string]any{},
			body: map[string]any{
				"firstname": "Michael",
				"surname":   "Fraser",
				"status":    "alive (hopefully)",
			},
			validate: func(t *testing.T, validator model.Validator, jwt *string, err error) {
				if err != nil {
					t.Errorf("no error should be thrown: %s", err.Error())
				}
				if jwt == nil {
					t.Fatal("a jwt should be returned")
				}

				jwtComponents := validateJwtSignature(t, *jwt, validator)
				validateHeadContents(t, jwtComponents[0], "RS256", "JWT")
				validateBodyContents(t, jwtComponents[1])
			},
		},
		{
			name: "we can sign a jwt with rs384",
			signer: func(t *testing.T) model.Signer {
				t.Helper()
				signer, err := rs384.NewSigner(2048)
				if err != nil {
					t.Fatalf("no error should be thrown: %s", err.Error())
				}
				return signer
			},
			validator: func(t *testing.T, pubKey crypto.PublicKey) model.Validator {
				t.Helper()
				validator, err := rs384.NewValidator(pubKey)
				if err != nil {
					t.Fatalf("no error should be thrown: %s", err.Error())
				}
				return validator
			},
			head: map[string]any{},
			body: map[string]any{
				"firstname": "Michael",
				"surname":   "Fraser",
				"status":    "alive (hopefully)",
			},
			validate: func(t *testing.T, validator model.Validator, jwt *string, err error) {
				if err != nil {
					t.Errorf("no error should be thrown: %s", err.Error())
				}
				if jwt == nil {
					t.Fatal("a jwt should be returned")
				}

				jwtComponents := validateJwtSignature(t, *jwt, validator)
				validateHeadContents(t, jwtComponents[0], "RS384", "JWT")
				validateBodyContents(t, jwtComponents[1])
			},
		},
		{
			name: "we can sign a jwt with rs512",
			signer: func(t *testing.T) model.Signer {
				t.Helper()
				signer, err := rs512.NewSigner(2048)
				if err != nil {
					t.Fatalf("no error should be thrown: %s", err.Error())
				}
				return signer
			},
			validator: func(t *testing.T, pubKey crypto.PublicKey) model.Validator {
				t.Helper()
				validator, err := rs512.NewValidator(pubKey)
				if err != nil {
					t.Fatalf("no error should be thrown: %s", err.Error())
				}
				return validator
			},
			head: map[string]any{},
			body: map[string]any{
				"firstname": "Michael",
				"surname":   "Fraser",
				"status":    "alive (hopefully)",
			},
			validate: func(t *testing.T, validator model.Validator, jwt *string, err error) {
				if err != nil {
					t.Errorf("no error should be thrown: %s", err.Error())
				}
				if jwt == nil {
					t.Fatal("a jwt should be returned")
				}

				jwtComponents := validateJwtSignature(t, *jwt, validator)
				validateHeadContents(t, jwtComponents[0], "RS512", "JWT")
				validateBodyContents(t, jwtComponents[1])
			},
		},
		{
			name: "we can sign a jwt with ps256",
			signer: func(t *testing.T) model.Signer {
				t.Helper()
				signer, err := ps256.NewSigner(2048)
				if err != nil {
					t.Fatalf("no error should be thrown: %s", err.Error())
				}
				return signer
			},
			validator: func(t *testing.T, pubKey crypto.PublicKey) model.Validator {
				t.Helper()
				validator, err := ps256.NewValidator(pubKey)
				if err != nil {
					t.Fatalf("no error should be thrown: %s", err.Error())
				}
				return validator
			},
			head: map[string]any{},
			body: map[string]any{
				"firstname": "Michael",
				"surname":   "Fraser",
				"status":    "alive (hopefully)",
			},
			validate: func(t *testing.T, validator model.Validator, jwt *string, err error) {
				if err != nil {
					t.Errorf("no error should be thrown: %s", err.Error())
				}
				if jwt == nil {
					t.Fatal("a jwt should be returned")
				}

				jwtComponents := validateJwtSignature(t, *jwt, validator)
				validateHeadContents(t, jwtComponents[0], "PS256", "JWT")
				validateBodyContents(t, jwtComponents[1])
			},
		},
		{
			name: "we can sign a jwt with ps384",
			signer: func(t *testing.T) model.Signer {
				t.Helper()
				signer, err := ps384.NewSigner(2048)
				if err != nil {
					t.Fatalf("no error should be thrown: %s", err.Error())
				}
				return signer
			},
			validator: func(t *testing.T, pubKey crypto.PublicKey) model.Validator {
				t.Helper()
				validator, err := ps384.NewValidator(pubKey)
				if err != nil {
					t.Fatalf("no error should be thrown: %s", err.Error())
				}
				return validator
			},
			head: map[string]any{},
			body: map[string]any{
				"firstname": "Michael",
				"surname":   "Fraser",
				"status":    "alive (hopefully)",
			},
			validate: func(t *testing.T, validator model.Validator, jwt *string, err error) {
				if err != nil {
					t.Errorf("no error should be thrown: %s", err.Error())
				}
				if jwt == nil {
					t.Fatal("a jwt should be returned")
				}

				jwtComponents := validateJwtSignature(t, *jwt, validator)
				validateHeadContents(t, jwtComponents[0], "PS384", "JWT")
				validateBodyContents(t, jwtComponents[1])
			},
		},
		{
			name: "we can sign a jwt with ps512",
			signer: func(t *testing.T) model.Signer {
				t.Helper()
				signer, err := ps512.NewSigner(2048)
				if err != nil {
					t.Fatalf("no error should be thrown: %s", err.Error())
				}
				return signer
			},
			validator: func(t *testing.T, pubKey crypto.PublicKey) model.Validator {
				t.Helper()
				validator, err := ps512.NewValidator(pubKey)
				if err != nil {
					t.Fatalf("no error should be thrown: %s", err.Error())
				}
				return validator
			},
			head: map[string]any{},
			body: map[string]any{
				"firstname": "Michael",
				"surname":   "Fraser",
				"status":    "alive (hopefully)",
			},
			validate: func(t *testing.T, validator model.Validator, jwt *string, err error) {
				if err != nil {
					t.Errorf("no error should be thrown: %s", err.Error())
				}
				if jwt == nil {
					t.Fatal("a jwt should be returned")
				}

				jwtComponents := validateJwtSignature(t, *jwt, validator)
				validateHeadContents(t, jwtComponents[0], "PS512", "JWT")
				validateBodyContents(t, jwtComponents[1])
			},
		},
		{
			name: "we can sign a jwt with es256",
			signer: func(t *testing.T) model.Signer {
				t.Helper()
				signer, err := es256.NewSigner()
				if err != nil {
					t.Fatalf("no error should be thrown: %s", err.Error())
				}
				return signer
			},
			validator: func(t *testing.T, pubKey crypto.PublicKey) model.Validator {
				t.Helper()
				validator, err := es256.NewValidator(pubKey)
				if err != nil {
					t.Fatalf("no error should be thrown: %s", err.Error())
				}
				return validator
			},
			head: map[string]any{},
			body: map[string]any{
				"firstname": "Michael",
				"surname":   "Fraser",
				"status":    "alive (hopefully)",
			},
			validate: func(t *testing.T, validator model.Validator, jwt *string, err error) {
				if err != nil {
					t.Errorf("no error should be thrown: %s", err.Error())
				}
				if jwt == nil {
					t.Fatal("a jwt should be returned")
				}

				jwtComponents := validateJwtSignature(t, *jwt, validator)
				validateHeadContents(t, jwtComponents[0], "ES256", "JWT")
				validateBodyContents(t, jwtComponents[1])
			},
		},
		{
			name: "we can sign a jwt with es384",
			signer: func(t *testing.T) model.Signer {
				t.Helper()
				signer, err := es384.NewSigner()
				if err != nil {
					t.Fatalf("no error should be thrown: %s", err.Error())
				}
				return signer
			},
			validator: func(t *testing.T, pubKey crypto.PublicKey) model.Validator {
				t.Helper()
				validator, err := es384.NewValidator(pubKey)
				if err != nil {
					t.Fatalf("no error should be thrown: %s", err.Error())
				}
				return validator
			},
			head: map[string]any{},
			body: map[string]any{
				"firstname": "Michael",
				"surname":   "Fraser",
				"status":    "alive (hopefully)",
			},
			validate: func(t *testing.T, validator model.Validator, jwt *string, err error) {
				if err != nil {
					t.Errorf("no error should be thrown: %s", err.Error())
				}
				if jwt == nil {
					t.Fatal("a jwt should be returned")
				}

				jwtComponents := validateJwtSignature(t, *jwt, validator)
				validateHeadContents(t, jwtComponents[0], "ES384", "JWT")
				validateBodyContents(t, jwtComponents[1])
			},
		},
		{
			name: "we can sign a jwt with es512",
			signer: func(t *testing.T) model.Signer {
				t.Helper()
				signer, err := es512.NewSigner()
				if err != nil {
					t.Fatalf("no error should be thrown: %s", err.Error())
				}
				return signer
			},
			validator: func(t *testing.T, pubKey crypto.PublicKey) model.Validator {
				t.Helper()
				validator, err := es512.NewValidator(pubKey)
				if err != nil {
					t.Fatalf("no error should be thrown: %s", err.Error())
				}
				return validator
			},
			head: map[string]any{},
			body: map[string]any{
				"firstname": "Michael",
				"surname":   "Fraser",
				"status":    "alive (hopefully)",
			},
			validate: func(t *testing.T, validator model.Validator, jwt *string, err error) {
				if err != nil {
					t.Errorf("no error should be thrown: %s", err.Error())
				}
				if jwt == nil {
					t.Fatal("a jwt should be returned")
				}

				jwtComponents := validateJwtSignature(t, *jwt, validator)
				validateHeadContents(t, jwtComponents[0], "ES512", "JWT")
				validateBodyContents(t, jwtComponents[1])
			},
		},
		{
			name: "we can sign a jwt with hs256",
			signer: func(t *testing.T) model.Signer {
				t.Helper()
				signer, err := hs256.NewSigner(&[]byte{'f', 'o', 'o', 'b', 'a', 'r'})
				if err != nil {
					t.Fatalf("no error should be thrown: %s", err.Error())
				}
				return signer
			},
			validator: func(t *testing.T, pubKey crypto.PublicKey) model.Validator {
				return nil
			},
			head: map[string]any{},
			body: map[string]any{
				"firstname": "Michael",
				"surname":   "Fraser",
				"status":    "alive (hopefully)",
			},
			validate: func(t *testing.T, validator model.Validator, jwt *string, err error) {
				if err != nil {
					t.Errorf("no error should be thrown: %s", err.Error())
				}
				if jwt == nil {
					t.Fatal("a jwt should be returned")
				}

				signer, err := hs256.NewSigner(&[]byte{'f', 'o', 'o', 'b', 'a', 'r'})
				if err != nil {
					t.Fatalf("no error should be thrown: %s", err.Error())
				}

				jwtComponents := strings.Split(*jwt, ".")
				if len(jwtComponents) != 3 {
					t.Errorf("wrong number of components returned: %d", len(jwtComponents))
				}

				signatureBytes, err := base64.RawURLEncoding.DecodeString(jwtComponents[2])
				if err != nil {
					t.Fatalf("no error should be thrown decoding signature: %s", err.Error())
				}

				newSignature, err := signer.Sign(rand.Reader, []byte(fmt.Sprintf("%s.%s", jwtComponents[0], jwtComponents[1])), model.SignerOpts{})
				if err != nil {
					t.Fatalf("no error should be thrown decoding signature: %s", err.Error())
				}

				if slices.Compare(signatureBytes, newSignature) != 0 {
					t.Error("the two signatures do not match")
				}

				validateHeadContents(t, jwtComponents[0], "HS256", "JWT")
				validateBodyContents(t, jwtComponents[1])
			},
		},
		{
			name: "we can sign a jwt with hs384",
			signer: func(t *testing.T) model.Signer {
				t.Helper()
				signer, err := hs384.NewSigner(&[]byte{'f', 'o', 'o', 'b', 'a', 'r'})
				if err != nil {
					t.Fatalf("no error should be thrown: %s", err.Error())
				}
				return signer
			},
			validator: func(t *testing.T, pubKey crypto.PublicKey) model.Validator {
				return nil
			},
			head: map[string]any{},
			body: map[string]any{
				"firstname": "Michael",
				"surname":   "Fraser",
				"status":    "alive (hopefully)",
			},
			validate: func(t *testing.T, validator model.Validator, jwt *string, err error) {
				if err != nil {
					t.Errorf("no error should be thrown: %s", err.Error())
				}
				if jwt == nil {
					t.Fatal("a jwt should be returned")
				}

				signer, err := hs384.NewSigner(&[]byte{'f', 'o', 'o', 'b', 'a', 'r'})
				if err != nil {
					t.Fatalf("no error should be thrown: %s", err.Error())
				}

				jwtComponents := strings.Split(*jwt, ".")
				if len(jwtComponents) != 3 {
					t.Errorf("wrong number of components returned: %d", len(jwtComponents))
				}

				signatureBytes, err := base64.RawURLEncoding.DecodeString(jwtComponents[2])
				if err != nil {
					t.Fatalf("no error should be thrown decoding signature: %s", err.Error())
				}

				newSignature, err := signer.Sign(rand.Reader, []byte(fmt.Sprintf("%s.%s", jwtComponents[0], jwtComponents[1])), model.SignerOpts{})
				if err != nil {
					t.Fatalf("no error should be thrown decoding signature: %s", err.Error())
				}

				if slices.Compare(signatureBytes, newSignature) != 0 {
					t.Error("the two signatures do not match")
				}

				validateHeadContents(t, jwtComponents[0], "HS384", "JWT")
				validateBodyContents(t, jwtComponents[1])
			},
		},
		{
			name: "we can sign a jwt with hs512",
			signer: func(t *testing.T) model.Signer {
				t.Helper()
				signer, err := hs512.NewSigner(&[]byte{'f', 'o', 'o', 'b', 'a', 'r'})
				if err != nil {
					t.Fatalf("no error should be thrown: %s", err.Error())
				}
				return signer
			},
			validator: func(t *testing.T, pubKey crypto.PublicKey) model.Validator {
				return nil
			},
			head: map[string]any{},
			body: map[string]any{
				"firstname": "Michael",
				"surname":   "Fraser",
				"status":    "alive (hopefully)",
			},
			validate: func(t *testing.T, validator model.Validator, jwt *string, err error) {
				if err != nil {
					t.Errorf("no error should be thrown: %s", err.Error())
				}
				if jwt == nil {
					t.Fatal("a jwt should be returned")
				}

				signer, err := hs512.NewSigner(&[]byte{'f', 'o', 'o', 'b', 'a', 'r'})
				if err != nil {
					t.Fatalf("no error should be thrown: %s", err.Error())
				}

				jwtComponents := strings.Split(*jwt, ".")
				if len(jwtComponents) != 3 {
					t.Errorf("wrong number of components returned: %d", len(jwtComponents))
				}

				signatureBytes, err := base64.RawURLEncoding.DecodeString(jwtComponents[2])
				if err != nil {
					t.Fatalf("no error should be thrown decoding signature: %s", err.Error())
				}

				newSignature, err := signer.Sign(rand.Reader, []byte(fmt.Sprintf("%s.%s", jwtComponents[0], jwtComponents[1])), model.SignerOpts{})
				if err != nil {
					t.Fatalf("no error should be thrown decoding signature: %s", err.Error())
				}

				if slices.Compare(signatureBytes, newSignature) != 0 {
					t.Error("the two signatures do not match")
				}
				validateHeadContents(t, jwtComponents[0], "HS512", "JWT")
				validateBodyContents(t, jwtComponents[1])
			},
		},
		{
			name: "we can sign a jwt with pre-defined values in header",
			signer: func(t *testing.T) model.Signer {
				t.Helper()
				signer, err := rs256.NewSigner(2048)
				if err != nil {
					t.Fatalf("no error should be thrown: %s", err.Error())
				}
				return signer
			},
			validator: func(t *testing.T, pubKey crypto.PublicKey) model.Validator {
				t.Helper()
				validator, err := rs256.NewValidator(pubKey)
				if err != nil {
					t.Fatalf("no error should be thrown: %s", err.Error())
				}
				return validator
			},
			head: map[string]any{
				"typ": "some other type",
				"alg": "another alg",
			},
			body: map[string]any{
				"firstname": "Michael",
				"surname":   "Fraser",
				"status":    "alive (hopefully)",
			},
			validate: func(t *testing.T, validator model.Validator, jwt *string, err error) {
				if err != nil {
					t.Errorf("no error should be thrown: %s", err.Error())
				}
				if jwt == nil {
					t.Fatal("a jwt should be returned")
				}

				jwtComponents := validateJwtSignature(t, *jwt, validator)
				validateHeadContents(t, jwtComponents[0], "another alg", "some other type")
				validateBodyContents(t, jwtComponents[1])
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			signer := tt.signer(t)
			jwt, err := New(signer, tt.head, tt.body)
			validator := tt.validator(t, signer.Public())
			tt.validate(t, validator, jwt, err)
		})
	}
}

func TestValidate(t *testing.T) {
	tests := []struct {
		name      string
		signer    func(t *testing.T) model.Signer
		publicKey func(t *testing.T, signer model.Signer) crypto.PublicKey
		jwt       func(t *testing.T, signer crypto.Signer) string
		validate  func(t *testing.T, head, body map[string]any, err error)
	}{
		{
			name: "we can validate a jwt signed with rs256",
			signer: func(t *testing.T) model.Signer {
				t.Helper()
				signer, err := rs256.NewSigner(2048)
				if err != nil {
					t.Fatalf("no error should be thrown: %s", err.Error())
				}
				return signer
			},
			publicKey: func(t *testing.T, signer model.Signer) crypto.PublicKey {
				return signer.Public()
			},
			jwt: func(t *testing.T, signer crypto.Signer) string {
				t.Helper()
				jwt, err := New(signer,
					map[string]any{},
					map[string]any{
						"firstname": "Michael",
						"surname":   "Fraser",
						"status":    "alive (hopefully)",
					},
				)
				if err != nil {
					t.Fatalf("no error should be thrown: %s", err.Error())
				}
				return *jwt
			},
			validate: func(t *testing.T, head, body map[string]any, err error) {
				if err != nil {
					t.Errorf("no error should be thrown: %s", err.Error())
				}
				if !maps.Equal(head, map[string]any{
					"typ": "JWT",
					"alg": "RS256",
				}) {
					t.Error("returned head does not match expected")
				}
				if !maps.Equal(body, map[string]any{
					"firstname": "Michael",
					"surname":   "Fraser",
					"status":    "alive (hopefully)",
				}) {
					t.Error("returned body does not match expected")
				}
			},
		},
		{
			name: "we can validate a jwt signed with rs384",
			signer: func(t *testing.T) model.Signer {
				t.Helper()
				signer, err := rs384.NewSigner(2048)
				if err != nil {
					t.Fatalf("no error should be thrown: %s", err.Error())
				}
				return signer
			},
			publicKey: func(t *testing.T, signer model.Signer) crypto.PublicKey {
				return signer.Public()
			},
			jwt: func(t *testing.T, signer crypto.Signer) string {
				t.Helper()
				jwt, err := New(signer,
					map[string]any{},
					map[string]any{
						"firstname": "Michael",
						"surname":   "Fraser",
						"status":    "alive (hopefully)",
					},
				)
				if err != nil {
					t.Fatalf("no error should be thrown: %s", err.Error())
				}
				return *jwt
			},
			validate: func(t *testing.T, head, body map[string]any, err error) {
				if err != nil {
					t.Errorf("no error should be thrown: %s", err.Error())
				}
				if !maps.Equal(head, map[string]any{
					"typ": "JWT",
					"alg": "RS384",
				}) {
					t.Error("returned head does not match expected")
				}
				if !maps.Equal(body, map[string]any{
					"firstname": "Michael",
					"surname":   "Fraser",
					"status":    "alive (hopefully)",
				}) {
					t.Error("returned body does not match expected")
				}
			},
		},
		{
			name: "we can validate a jwt signed with rs512",
			signer: func(t *testing.T) model.Signer {
				t.Helper()
				signer, err := rs512.NewSigner(2048)
				if err != nil {
					t.Fatalf("no error should be thrown: %s", err.Error())
				}
				return signer
			},
			publicKey: func(t *testing.T, signer model.Signer) crypto.PublicKey {
				return signer.Public()
			},
			jwt: func(t *testing.T, signer crypto.Signer) string {
				t.Helper()
				jwt, err := New(signer,
					map[string]any{},
					map[string]any{
						"firstname": "Michael",
						"surname":   "Fraser",
						"status":    "alive (hopefully)",
					},
				)
				if err != nil {
					t.Fatalf("no error should be thrown: %s", err.Error())
				}
				return *jwt
			},
			validate: func(t *testing.T, head, body map[string]any, err error) {
				if err != nil {
					t.Errorf("no error should be thrown: %s", err.Error())
				}
				if !maps.Equal(head, map[string]any{
					"typ": "JWT",
					"alg": "RS512",
				}) {
					t.Error("returned head does not match expected")
				}
				if !maps.Equal(body, map[string]any{
					"firstname": "Michael",
					"surname":   "Fraser",
					"status":    "alive (hopefully)",
				}) {
					t.Error("returned body does not match expected")
				}
			},
		},
		{
			name: "we can validate a jwt signed with ps256",
			signer: func(t *testing.T) model.Signer {
				t.Helper()
				signer, err := ps256.NewSigner(2048)
				if err != nil {
					t.Fatalf("no error should be thrown: %s", err.Error())
				}
				return signer
			},
			publicKey: func(t *testing.T, signer model.Signer) crypto.PublicKey {
				return signer.Public()
			},
			jwt: func(t *testing.T, signer crypto.Signer) string {
				t.Helper()
				jwt, err := New(signer,
					map[string]any{},
					map[string]any{
						"firstname": "Michael",
						"surname":   "Fraser",
						"status":    "alive (hopefully)",
					},
				)
				if err != nil {
					t.Fatalf("no error should be thrown: %s", err.Error())
				}
				return *jwt
			},
			validate: func(t *testing.T, head, body map[string]any, err error) {
				if err != nil {
					t.Errorf("no error should be thrown: %s", err.Error())
				}
				if !maps.Equal(head, map[string]any{
					"typ": "JWT",
					"alg": "PS256",
				}) {
					t.Error("returned head does not match expected")
				}
				if !maps.Equal(body, map[string]any{
					"firstname": "Michael",
					"surname":   "Fraser",
					"status":    "alive (hopefully)",
				}) {
					t.Error("returned body does not match expected")
				}
			},
		},
		{
			name: "we can validate a jwt signed with ps384",
			signer: func(t *testing.T) model.Signer {
				t.Helper()
				signer, err := ps384.NewSigner(2048)
				if err != nil {
					t.Fatalf("no error should be thrown: %s", err.Error())
				}
				return signer
			},
			publicKey: func(t *testing.T, signer model.Signer) crypto.PublicKey {
				return signer.Public()
			},
			jwt: func(t *testing.T, signer crypto.Signer) string {
				t.Helper()
				jwt, err := New(signer,
					map[string]any{},
					map[string]any{
						"firstname": "Michael",
						"surname":   "Fraser",
						"status":    "alive (hopefully)",
					},
				)
				if err != nil {
					t.Fatalf("no error should be thrown: %s", err.Error())
				}
				return *jwt
			},
			validate: func(t *testing.T, head, body map[string]any, err error) {
				if err != nil {
					t.Errorf("no error should be thrown: %s", err.Error())
				}
				if !maps.Equal(head, map[string]any{
					"typ": "JWT",
					"alg": "PS384",
				}) {
					t.Error("returned head does not match expected")
				}
				if !maps.Equal(body, map[string]any{
					"firstname": "Michael",
					"surname":   "Fraser",
					"status":    "alive (hopefully)",
				}) {
					t.Error("returned body does not match expected")
				}
			},
		},
		{
			name: "we can validate a jwt signed with ps512",
			signer: func(t *testing.T) model.Signer {
				t.Helper()
				signer, err := ps512.NewSigner(2048)
				if err != nil {
					t.Fatalf("no error should be thrown: %s", err.Error())
				}
				return signer
			},
			publicKey: func(t *testing.T, signer model.Signer) crypto.PublicKey {
				return signer.Public()
			},
			jwt: func(t *testing.T, signer crypto.Signer) string {
				t.Helper()
				jwt, err := New(signer,
					map[string]any{},
					map[string]any{
						"firstname": "Michael",
						"surname":   "Fraser",
						"status":    "alive (hopefully)",
					},
				)
				if err != nil {
					t.Fatalf("no error should be thrown: %s", err.Error())
				}
				return *jwt
			},
			validate: func(t *testing.T, head, body map[string]any, err error) {
				if err != nil {
					t.Errorf("no error should be thrown: %s", err.Error())
				}
				if !maps.Equal(head, map[string]any{
					"typ": "JWT",
					"alg": "PS512",
				}) {
					t.Error("returned head does not match expected")
				}
				if !maps.Equal(body, map[string]any{
					"firstname": "Michael",
					"surname":   "Fraser",
					"status":    "alive (hopefully)",
				}) {
					t.Error("returned body does not match expected")
				}
			},
		},
		{
			name: "we can validate a jwt signed with es256",
			signer: func(t *testing.T) model.Signer {
				t.Helper()
				signer, err := es256.NewSigner()
				if err != nil {
					t.Fatalf("no error should be thrown: %s", err.Error())
				}
				return signer
			},
			publicKey: func(t *testing.T, signer model.Signer) crypto.PublicKey {
				return signer.Public()
			},
			jwt: func(t *testing.T, signer crypto.Signer) string {
				t.Helper()
				jwt, err := New(signer,
					map[string]any{},
					map[string]any{
						"firstname": "Michael",
						"surname":   "Fraser",
						"status":    "alive (hopefully)",
					},
				)
				if err != nil {
					t.Fatalf("no error should be thrown: %s", err.Error())
				}
				return *jwt
			},
			validate: func(t *testing.T, head, body map[string]any, err error) {
				if err != nil {
					t.Errorf("no error should be thrown: %s", err.Error())
				}
				if !maps.Equal(head, map[string]any{
					"typ": "JWT",
					"alg": "ES256",
				}) {
					t.Error("returned head does not match expected")
				}
				if !maps.Equal(body, map[string]any{
					"firstname": "Michael",
					"surname":   "Fraser",
					"status":    "alive (hopefully)",
				}) {
					t.Error("returned body does not match expected")
				}
			},
		},
		{
			name: "we can validate a jwt signed with es384",
			signer: func(t *testing.T) model.Signer {
				t.Helper()
				signer, err := es384.NewSigner()
				if err != nil {
					t.Fatalf("no error should be thrown: %s", err.Error())
				}
				return signer
			},
			publicKey: func(t *testing.T, signer model.Signer) crypto.PublicKey {
				return signer.Public()
			},
			jwt: func(t *testing.T, signer crypto.Signer) string {
				t.Helper()
				jwt, err := New(signer,
					map[string]any{},
					map[string]any{
						"firstname": "Michael",
						"surname":   "Fraser",
						"status":    "alive (hopefully)",
					},
				)
				if err != nil {
					t.Fatalf("no error should be thrown: %s", err.Error())
				}
				return *jwt
			},
			validate: func(t *testing.T, head, body map[string]any, err error) {
				if err != nil {
					t.Errorf("no error should be thrown: %s", err.Error())
				}
				if !maps.Equal(head, map[string]any{
					"typ": "JWT",
					"alg": "ES384",
				}) {
					t.Error("returned head does not match expected")
				}
				if !maps.Equal(body, map[string]any{
					"firstname": "Michael",
					"surname":   "Fraser",
					"status":    "alive (hopefully)",
				}) {
					t.Error("returned body does not match expected")
				}
			},
		},
		{
			name: "we can validate a jwt signed with es512",
			signer: func(t *testing.T) model.Signer {
				t.Helper()
				signer, err := es512.NewSigner()
				if err != nil {
					t.Fatalf("no error should be thrown: %s", err.Error())
				}
				return signer
			},
			publicKey: func(t *testing.T, signer model.Signer) crypto.PublicKey {
				return signer.Public()
			},
			jwt: func(t *testing.T, signer crypto.Signer) string {
				t.Helper()
				jwt, err := New(signer,
					map[string]any{},
					map[string]any{
						"firstname": "Michael",
						"surname":   "Fraser",
						"status":    "alive (hopefully)",
					},
				)
				if err != nil {
					t.Fatalf("no error should be thrown: %s", err.Error())
				}
				return *jwt
			},
			validate: func(t *testing.T, head, body map[string]any, err error) {
				if err != nil {
					t.Errorf("no error should be thrown: %s", err.Error())
				}
				if !maps.Equal(head, map[string]any{
					"typ": "JWT",
					"alg": "ES512",
				}) {
					t.Error("returned head does not match expected")
				}
				if !maps.Equal(body, map[string]any{
					"firstname": "Michael",
					"surname":   "Fraser",
					"status":    "alive (hopefully)",
				}) {
					t.Error("returned body does not match expected")
				}
			},
		},
		{
			name: "we can validate a jwt signed with hs256",
			signer: func(t *testing.T) model.Signer {
				t.Helper()
				signer, err := hs256.NewSigner(&[]byte{'f', 'o', 'o', 'b', 'a', 'r'})
				if err != nil {
					t.Fatalf("no error should be thrown: %s", err.Error())
				}
				return signer
			},
			publicKey: func(t *testing.T, signer model.Signer) crypto.PublicKey {
				return signer.Public()
			},
			jwt: func(t *testing.T, signer crypto.Signer) string {
				t.Helper()
				jwt, err := New(signer,
					map[string]any{},
					map[string]any{
						"firstname": "Michael",
						"surname":   "Fraser",
						"status":    "alive (hopefully)",
					},
				)
				if err != nil {
					t.Fatalf("no error should be thrown: %s", err.Error())
				}
				return *jwt
			},
			validate: func(t *testing.T, head, body map[string]any, err error) {
				if err != nil {
					t.Errorf("no error should be thrown: %s", err.Error())
				}
				if !maps.Equal(head, map[string]any{
					"typ": "JWT",
					"alg": "HS256",
				}) {
					t.Error("returned head does not match expected")
				}
				if !maps.Equal(body, map[string]any{
					"firstname": "Michael",
					"surname":   "Fraser",
					"status":    "alive (hopefully)",
				}) {
					t.Error("returned body does not match expected")
				}
			},
		},
		{
			name: "we can validate a jwt signed with hs384",
			signer: func(t *testing.T) model.Signer {
				t.Helper()
				signer, err := hs384.NewSigner(&[]byte{'f', 'o', 'o', 'b', 'a', 'r'})
				if err != nil {
					t.Fatalf("no error should be thrown: %s", err.Error())
				}
				return signer
			},
			publicKey: func(t *testing.T, signer model.Signer) crypto.PublicKey {
				return signer.Public()
			},
			jwt: func(t *testing.T, signer crypto.Signer) string {
				t.Helper()
				jwt, err := New(signer,
					map[string]any{},
					map[string]any{
						"firstname": "Michael",
						"surname":   "Fraser",
						"status":    "alive (hopefully)",
					},
				)
				if err != nil {
					t.Fatalf("no error should be thrown: %s", err.Error())
				}
				return *jwt
			},
			validate: func(t *testing.T, head, body map[string]any, err error) {
				if err != nil {
					t.Errorf("no error should be thrown: %s", err.Error())
				}
				if !maps.Equal(head, map[string]any{
					"typ": "JWT",
					"alg": "HS384",
				}) {
					t.Error("returned head does not match expected")
				}
				if !maps.Equal(body, map[string]any{
					"firstname": "Michael",
					"surname":   "Fraser",
					"status":    "alive (hopefully)",
				}) {
					t.Error("returned body does not match expected")
				}
			},
		},
		{
			name: "we can validate a jwt signed with hs512",
			signer: func(t *testing.T) model.Signer {
				t.Helper()
				signer, err := hs512.NewSigner(&[]byte{'f', 'o', 'o', 'b', 'a', 'r'})
				if err != nil {
					t.Fatalf("no error should be thrown: %s", err.Error())
				}
				return signer
			},
			publicKey: func(t *testing.T, signer model.Signer) crypto.PublicKey {
				return signer.Public()
			},
			jwt: func(t *testing.T, signer crypto.Signer) string {
				t.Helper()
				jwt, err := New(signer,
					map[string]any{},
					map[string]any{
						"firstname": "Michael",
						"surname":   "Fraser",
						"status":    "alive (hopefully)",
					},
				)
				if err != nil {
					t.Fatalf("no error should be thrown: %s", err.Error())
				}
				return *jwt
			},
			validate: func(t *testing.T, head, body map[string]any, err error) {
				if err != nil {
					t.Errorf("no error should be thrown: %s", err.Error())
				}
				if !maps.Equal(head, map[string]any{
					"typ": "JWT",
					"alg": "HS512",
				}) {
					t.Error("returned head does not match expected")
				}
				if !maps.Equal(body, map[string]any{
					"firstname": "Michael",
					"surname":   "Fraser",
					"status":    "alive (hopefully)",
				}) {
					t.Error("returned body does not match expected")
				}
			},
		},
		{
			name: "we can validate a jwt signed with an hs algorithm and pass in the passphrase as a secret key implementation",
			signer: func(t *testing.T) model.Signer {
				t.Helper()
				signer, err := hs256.NewSigner(&[]byte{'f', 'o', 'o', 'b', 'a', 'r'})
				if err != nil {
					t.Fatalf("no error should be thrown: %s", err.Error())
				}
				return signer
			},
			publicKey: func(t *testing.T, signer model.Signer) crypto.PublicKey {
				return common.SecretKey("foobar")
			},
			jwt: func(t *testing.T, signer crypto.Signer) string {
				t.Helper()
				jwt, err := New(signer,
					map[string]any{},
					map[string]any{
						"firstname": "Michael",
						"surname":   "Fraser",
						"status":    "alive (hopefully)",
					},
				)
				if err != nil {
					t.Fatalf("no error should be thrown: %s", err.Error())
				}
				return *jwt
			},
			validate: func(t *testing.T, head, body map[string]any, err error) {
				if err != nil {
					t.Errorf("no error should be thrown: %s", err.Error())
				}
			},
		},
		{
			name: "we handler an unknown algorithm identifier",
			signer: func(t *testing.T) model.Signer {
				t.Helper()
				signer, err := rs256.NewSigner(2048)
				if err != nil {
					t.Fatalf("no error should be thrown: %s", err.Error())
				}
				return signer
			},
			publicKey: func(t *testing.T, signer model.Signer) crypto.PublicKey {
				return signer.Public()
			},
			jwt: func(t *testing.T, signer crypto.Signer) string {
				t.Helper()
				jwt, err := New(signer,
					map[string]any{
						"alg": "foobar",
					},
					map[string]any{
						"firstname": "Michael",
						"surname":   "Fraser",
						"status":    "alive (hopefully)",
					},
				)
				if err != nil {
					t.Fatalf("no error should be thrown: %s", err.Error())
				}
				return *jwt
			},
			validate: func(t *testing.T, head, body map[string]any, err error) {
				if err == nil {
					t.Fatal("an error should be thrown")
				}
				if err.Error() != "unknown algorithm claim value: foobar" {
					t.Errorf("wrong error returned: %s", err.Error())
				}
			},
		},
		{
			name: "we handler a malformed iat",
			signer: func(t *testing.T) model.Signer {
				t.Helper()
				signer, err := rs256.NewSigner(2048)
				if err != nil {
					t.Fatalf("no error should be thrown: %s", err.Error())
				}
				return signer
			},
			publicKey: func(t *testing.T, signer model.Signer) crypto.PublicKey {
				return signer.Public()
			},
			jwt: func(t *testing.T, signer crypto.Signer) string {
				t.Helper()
				jwt, err := New(signer,
					map[string]any{},
					map[string]any{
						"firstname": "Michael",
						"surname":   "Fraser",
						"status":    "alive (hopefully)",
						"iat":       "foobar",
					},
				)
				if err != nil {
					t.Fatalf("no error should be thrown: %s", err.Error())
				}
				return *jwt
			},
			validate: func(t *testing.T, head, body map[string]any, err error) {
				if err == nil {
					t.Fatal("an error should be thrown")
				}
				if err.Error() != "iat claim malformed" {
					t.Errorf("wrong error returned: %s", err.Error())
				}
			},
		},
		{
			name: "we handler a future-dated iat",
			signer: func(t *testing.T) model.Signer {
				t.Helper()
				signer, err := rs256.NewSigner(2048)
				if err != nil {
					t.Fatalf("no error should be thrown: %s", err.Error())
				}
				return signer
			},
			publicKey: func(t *testing.T, signer model.Signer) crypto.PublicKey {
				return signer.Public()
			},
			jwt: func(t *testing.T, signer crypto.Signer) string {
				t.Helper()
				jwt, err := New(signer,
					map[string]any{},
					map[string]any{
						"firstname": "Michael",
						"surname":   "Fraser",
						"status":    "alive (hopefully)",
						"iat":       time.Now().Add(1 * time.Hour).Unix(),
					},
				)
				if err != nil {
					t.Fatalf("no error should be thrown: %s", err.Error())
				}
				return *jwt
			},
			validate: func(t *testing.T, head, body map[string]any, err error) {
				if err == nil {
					t.Fatal("an error should be thrown")
				}
				if err.Error() != "iat claim is after current time" {
					t.Errorf("wrong error returned: %s", err.Error())
				}
			},
		},
		{
			name: "we handler a malformed nbf",
			signer: func(t *testing.T) model.Signer {
				t.Helper()
				signer, err := rs256.NewSigner(2048)
				if err != nil {
					t.Fatalf("no error should be thrown: %s", err.Error())
				}
				return signer
			},
			publicKey: func(t *testing.T, signer model.Signer) crypto.PublicKey {
				return signer.Public()
			},
			jwt: func(t *testing.T, signer crypto.Signer) string {
				t.Helper()
				jwt, err := New(signer,
					map[string]any{},
					map[string]any{
						"firstname": "Michael",
						"surname":   "Fraser",
						"status":    "alive (hopefully)",
						"nbf":       "foobar",
					},
				)
				if err != nil {
					t.Fatalf("no error should be thrown: %s", err.Error())
				}
				return *jwt
			},
			validate: func(t *testing.T, head, body map[string]any, err error) {
				if err == nil {
					t.Fatal("an error should be thrown")
				}
				if err.Error() != "nbf claim malformed" {
					t.Errorf("wrong error returned: %s", err.Error())
				}
			},
		},
		{
			name: "we handler a future-dated nbf",
			signer: func(t *testing.T) model.Signer {
				t.Helper()
				signer, err := rs256.NewSigner(2048)
				if err != nil {
					t.Fatalf("no error should be thrown: %s", err.Error())
				}
				return signer
			},
			publicKey: func(t *testing.T, signer model.Signer) crypto.PublicKey {
				return signer.Public()
			},
			jwt: func(t *testing.T, signer crypto.Signer) string {
				t.Helper()
				jwt, err := New(signer,
					map[string]any{},
					map[string]any{
						"firstname": "Michael",
						"surname":   "Fraser",
						"status":    "alive (hopefully)",
						"nbf":       time.Now().Add(1 * time.Hour).Unix(),
					},
				)
				if err != nil {
					t.Fatalf("no error should be thrown: %s", err.Error())
				}
				return *jwt
			},
			validate: func(t *testing.T, head, body map[string]any, err error) {
				if err == nil {
					t.Fatal("an error should be thrown")
				}
				if err.Error() != "nbf claim is after current time" {
					t.Errorf("wrong error returned: %s", err.Error())
				}
			},
		},
		{
			name: "we handler a malformed exp",
			signer: func(t *testing.T) model.Signer {
				t.Helper()
				signer, err := rs256.NewSigner(2048)
				if err != nil {
					t.Fatalf("no error should be thrown: %s", err.Error())
				}
				return signer
			},
			publicKey: func(t *testing.T, signer model.Signer) crypto.PublicKey {
				return signer.Public()
			},
			jwt: func(t *testing.T, signer crypto.Signer) string {
				t.Helper()
				jwt, err := New(signer,
					map[string]any{},
					map[string]any{
						"firstname": "Michael",
						"surname":   "Fraser",
						"status":    "alive (hopefully)",
						"exp":       "foobar",
					},
				)
				if err != nil {
					t.Fatalf("no error should be thrown: %s", err.Error())
				}
				return *jwt
			},
			validate: func(t *testing.T, head, body map[string]any, err error) {
				if err == nil {
					t.Fatal("an error should be thrown")
				}
				if err.Error() != "exp claim malformed" {
					t.Errorf("wrong error returned: %s", err.Error())
				}
			},
		},
		{
			name: "we handler a future-dated exp",
			signer: func(t *testing.T) model.Signer {
				t.Helper()
				signer, err := rs256.NewSigner(2048)
				if err != nil {
					t.Fatalf("no error should be thrown: %s", err.Error())
				}
				return signer
			},
			publicKey: func(t *testing.T, signer model.Signer) crypto.PublicKey {
				return signer.Public()
			},
			jwt: func(t *testing.T, signer crypto.Signer) string {
				t.Helper()
				jwt, err := New(signer,
					map[string]any{},
					map[string]any{
						"firstname": "Michael",
						"surname":   "Fraser",
						"status":    "alive (hopefully)",
						"exp":       time.Now().Add(-1 * time.Hour).Unix(),
					},
				)
				if err != nil {
					t.Fatalf("no error should be thrown: %s", err.Error())
				}
				return *jwt
			},
			validate: func(t *testing.T, head, body map[string]any, err error) {
				if err == nil {
					t.Fatal("an error should be thrown")
				}
				if err.Error() != "exp claim is before current time" {
					t.Errorf("wrong error returned: %s", err.Error())
				}
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			signer := tt.signer(t)
			head, body, err := Validate(tt.publicKey(t, signer), tt.jwt(t, signer))
			tt.validate(t, head, body, err)
		})
	}
}

func validateJwtSignature(t *testing.T, jwt string, validator model.Validator) []string {
	t.Helper()
	jwtComponents := strings.Split(jwt, ".")
	if len(jwtComponents) != 3 {
		t.Errorf("wrong number of components returned: %d", len(jwtComponents))
	}

	signatureBytes, err := base64.RawURLEncoding.DecodeString(jwtComponents[2])
	if err != nil {
		t.Errorf("no error should be thrown decoding signature: %s", err.Error())
	}

	valid, err := validator.ValidateSignature([]byte(fmt.Sprintf("%s.%s", jwtComponents[0], jwtComponents[1])), signatureBytes)
	if err != nil {
		t.Errorf("no error should be thrown validating signature: %s", err.Error())
	}
	if !valid {
		t.Error("signature does not validate")
	}
	return jwtComponents
}

func validateHeadContents(t *testing.T, headJwtComponent, expectedAlgorithm, expectedType string) {
	t.Helper()

	headBytes, err := base64.RawURLEncoding.DecodeString(headJwtComponent)
	if err != nil {
		t.Fatalf("error decoding head base64: %s", err.Error())
	}

	var head map[string]any
	if err := json.Unmarshal(headBytes, &head); err != nil {
		t.Fatalf("no error should be thrown unmarshaling head to a map: %s", err.Error())
	}

	if typ, found := head["typ"]; !found {
		t.Error("head should have a typ value")
	} else {
		if typ != expectedType {
			t.Errorf("wrong typ value in head: %s", typ.(string))
		}
	}

	if alg, found := head["alg"]; !found {
		t.Error("head should have an alg value")
	} else {
		if alg != expectedAlgorithm {
			t.Errorf("wrong alg value in head: %s", alg.(string))
		}
	}
}

func validateBodyContents(t *testing.T, bodyJwtComponent string) {
	t.Helper()

	bodyBytes, err := base64.RawURLEncoding.DecodeString(bodyJwtComponent)
	if err != nil {
		t.Fatalf("error decoding body base64: %s", err.Error())
	}

	var body map[string]any
	if err = json.Unmarshal(bodyBytes, &body); err != nil {
		t.Fatalf("no error should be thrown unmarshaling body to a map: %s", err.Error())
	}

	for k, v := range map[string]string{
		"firstname": "Michael",
		"surname":   "Fraser",
		"status":    "alive (hopefully)",
	} {
		if val, found := body[k]; !found {
			t.Errorf("body should have a %s value", k)
		} else {
			if val != v {
				t.Errorf("wrong %s value in body - got: %s expected: %s", k, val.(string), v)
			}
		}
	}
}
