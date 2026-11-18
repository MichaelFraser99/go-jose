package jwt_test

import (
	"context"
	"crypto"
	"errors"
	"fmt"
	"time"

	"github.com/MichaelFraser99/go-jose/joseerror"
	"github.com/MichaelFraser99/go-jose/jwa"
	"github.com/MichaelFraser99/go-jose/jws"
	"github.com/MichaelFraser99/go-jose/jwt"
	"github.com/MichaelFraser99/go-jose/model"
)

type issuerKeys struct {
	issuer    string
	retriever model.Retriever
}

var refusedAfterTheSignature = []error{
	joseerror.ErrExpired,
	joseerror.ErrNotYetValid,
	joseerror.ErrMissingClaim,
	joseerror.ErrMalformedClaim,
	joseerror.ErrIssuerMismatch,
	joseerror.ErrAudienceMismatch,
}

func validateFromOneOf(ctx context.Context, token string, issuers []issuerKeys) (*jwt.Token, error) {
	if len(issuers) == 0 {
		return nil, fmt.Errorf("%wno issuer is configured", joseerror.ErrInvalidOptions)
	}
	failures := make([]error, 0, len(issuers))
	for _, candidate := range issuers {
		opts := &model.JoseOptions{ExpectedIssuer: []string{candidate.issuer}}
		validated, err := jwt.Validate(ctx, token, candidate.retriever, nil, opts, nil)
		if err == nil {
			return validated, nil
		}
		failures = append(failures, err)
	}
	for _, err := range failures {
		for _, reason := range refusedAfterTheSignature {
			if errors.Is(err, reason) {
				return nil, err
			}
		}
	}
	for _, err := range failures {
		if !errors.Is(err, joseerror.ErrInvalidSignature) {
			return nil, err
		}
	}
	return nil, failures[0]
}

func Example_severalIssuers() {
	signerA, err := jws.GetSigner(jwa.ES256, nil)
	if err != nil {
		panic(err)
	}
	signerB, err := jws.GetSigner(jwa.ES256, nil)
	if err != nil {
		panic(err)
	}
	keysOf := func(signer crypto.Signer) model.Retriever {
		return func() ([]crypto.PublicKey, error) { return []crypto.PublicKey{signer.Public()}, nil }
	}
	outage := func() ([]crypto.PublicKey, error) { return nil, errors.New("key store unavailable") }
	sign := func(signer crypto.Signer, claims map[string]any) string {
		token, err := jwt.New(signer, map[string]any{"typ": "JWT"}, claims, jwt.Opts{})
		if err != nil {
			panic(err)
		}
		return *token
	}
	later := float64(time.Now().Add(time.Hour).Unix())
	earlier := float64(time.Now().Add(-time.Hour).Unix())
	issuers := []issuerKeys{
		{issuer: "https://b.example", retriever: keysOf(signerB)},
		{issuer: "https://a.example", retriever: keysOf(signerA)},
	}
	ctx := context.Background()

	validated, err := validateFromOneOf(ctx, sign(signerA, map[string]any{"iss": "https://a.example", "exp": later}), issuers)
	if err != nil {
		panic(err)
	}
	_, forged := validateFromOneOf(ctx, sign(signerB, map[string]any{"iss": "https://a.example", "exp": later}), issuers)
	bDown := []issuerKeys{{issuer: "https://b.example", retriever: outage}, issuers[1]}
	_, expired := validateFromOneOf(ctx, sign(signerA, map[string]any{"iss": "https://a.example", "exp": earlier}), bDown)
	stranger, err := jws.GetSigner(jwa.ES256, nil)
	if err != nil {
		panic(err)
	}
	aThenBDown := []issuerKeys{issuers[1], bDown[0]}
	_, unknown := validateFromOneOf(ctx, sign(stranger, map[string]any{"iss": "https://b.example", "exp": later}), aThenBDown)
	_, unconfigured := validateFromOneOf(ctx, sign(signerA, map[string]any{"iss": "https://a.example", "exp": later}), nil)
	fmt.Println(validated.Claims["iss"], errors.Is(forged, joseerror.ErrIssuerMismatch), errors.Is(expired, joseerror.ErrExpired), errors.Is(unknown, joseerror.ErrInvalidSignature), errors.Is(unconfigured, joseerror.ErrInvalidOptions))
	// Output: https://a.example true true false true
}
