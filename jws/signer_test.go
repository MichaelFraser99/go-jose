package jws

import (
	"github.com/MichaelFraser99/go-jose/jwa"
	"github.com/MichaelFraser99/go-jose/model"
	"testing"
)

func TestGetSigner(t *testing.T) {
	secretKey := []byte("a super secret key")
	tests := []struct {
		algorithm jwa.Algorithm
		opts      *model.Opts
		verify    func(t *testing.T, signer model.Signer, err error)
	}{
		{
			algorithm: jwa.RS256,
			opts:      nil,
			verify: func(t *testing.T, signer model.Signer, err error) {
				if err != nil {
					t.Fatalf("no error expected: %s", err.Error())
				}
				if signer.Alg() != jwa.RS256 {
					t.Errorf("wrong algorithm returned: %s", signer.Alg())
				}
			},
		},
		{
			algorithm: jwa.RS256,
			opts: &model.Opts{
				BitSize: 2048,
			},
			verify: func(t *testing.T, signer model.Signer, err error) {
				if err != nil {
					t.Fatalf("no error expected: %s", err.Error())
				}
				if signer.Alg() != jwa.RS256 {
					t.Errorf("wrong algorithm returned: %s", signer.Alg())
				}
			},
		},
		{
			algorithm: jwa.RS256,
			opts: &model.Opts{
				BitSize: 1024,
			},
			verify: func(t *testing.T, signer model.Signer, err error) {
				if err == nil {
					t.Fatalf("an error should have been thrown")
				}
				if err.Error() != "specified key bit size should be at least 2048" {
					t.Errorf("wrong error returned: %s", err.Error())
				}
			},
		},
		{
			algorithm: jwa.RS384,
			opts:      nil,
			verify: func(t *testing.T, signer model.Signer, err error) {
				if err != nil {
					t.Fatalf("no error expected: %s", err.Error())
				}
				if signer.Alg() != jwa.RS384 {
					t.Errorf("wrong algorithm returned: %s", signer.Alg())
				}
			},
		},
		{
			algorithm: jwa.RS384,
			opts: &model.Opts{
				BitSize: 2048,
			},
			verify: func(t *testing.T, signer model.Signer, err error) {
				if err != nil {
					t.Fatalf("no error expected: %s", err.Error())
				}
				if signer.Alg() != jwa.RS384 {
					t.Errorf("wrong algorithm returned: %s", signer.Alg())
				}
			},
		},
		{
			algorithm: jwa.RS384,
			opts: &model.Opts{
				BitSize: 1024,
			},
			verify: func(t *testing.T, signer model.Signer, err error) {
				if err == nil {
					t.Fatalf("an error should have been thrown")
				}
				if err.Error() != "specified key bit size should be at least 2048" {
					t.Errorf("wrong error returned: %s", err.Error())
				}
			},
		},
		{
			algorithm: jwa.RS512,
			opts:      nil,
			verify: func(t *testing.T, signer model.Signer, err error) {
				if err != nil {
					t.Fatalf("no error expected: %s", err.Error())
				}
				if signer.Alg() != jwa.RS512 {
					t.Errorf("wrong algorithm returned: %s", signer.Alg())
				}
			},
		},
		{
			algorithm: jwa.RS512,
			opts: &model.Opts{
				BitSize: 2048,
			},
			verify: func(t *testing.T, signer model.Signer, err error) {
				if err != nil {
					t.Fatalf("no error expected: %s", err.Error())
				}
				if signer.Alg() != jwa.RS512 {
					t.Errorf("wrong algorithm returned: %s", signer.Alg())
				}
			},
		},
		{
			algorithm: jwa.RS512,
			opts: &model.Opts{
				BitSize: 1024,
			},
			verify: func(t *testing.T, signer model.Signer, err error) {
				if err == nil {
					t.Fatalf("an error should have been thrown")
				}
				if err.Error() != "specified key bit size should be at least 2048" {
					t.Errorf("wrong error returned: %s", err.Error())
				}
			},
		},
		{
			algorithm: jwa.PS256,
			opts:      nil,
			verify: func(t *testing.T, signer model.Signer, err error) {
				if err != nil {
					t.Fatalf("no error expected: %s", err.Error())
				}
				if signer.Alg() != jwa.PS256 {
					t.Errorf("wrong algorithm returned: %s", signer.Alg())
				}
			},
		},
		{
			algorithm: jwa.PS256,
			opts: &model.Opts{
				BitSize: 2048,
			},
			verify: func(t *testing.T, signer model.Signer, err error) {
				if err != nil {
					t.Fatalf("no error expected: %s", err.Error())
				}
				if signer.Alg() != jwa.PS256 {
					t.Errorf("wrong algorithm returned: %s", signer.Alg())
				}
			},
		},
		{
			algorithm: jwa.PS256,
			opts: &model.Opts{
				BitSize: 1024,
			},
			verify: func(t *testing.T, signer model.Signer, err error) {
				if err == nil {
					t.Fatalf("an error should have been thrown")
				}
				if err.Error() != "specified key bit size should be at least 2048" {
					t.Errorf("wrong error returned: %s", err.Error())
				}
			},
		},
		{
			algorithm: jwa.PS384,
			opts:      nil,
			verify: func(t *testing.T, signer model.Signer, err error) {
				if err != nil {
					t.Fatalf("no error expected: %s", err.Error())
				}
				if signer.Alg() != jwa.PS384 {
					t.Errorf("wrong algorithm returned: %s", signer.Alg())
				}
			},
		},
		{
			algorithm: jwa.PS384,
			opts: &model.Opts{
				BitSize: 2048,
			},
			verify: func(t *testing.T, signer model.Signer, err error) {
				if err != nil {
					t.Fatalf("no error expected: %s", err.Error())
				}
				if signer.Alg() != jwa.PS384 {
					t.Errorf("wrong algorithm returned: %s", signer.Alg())
				}
			},
		},
		{
			algorithm: jwa.PS384,
			opts: &model.Opts{
				BitSize: 1024,
			},
			verify: func(t *testing.T, signer model.Signer, err error) {
				if err == nil {
					t.Fatalf("an error should have been thrown")
				}
				if err.Error() != "specified key bit size should be at least 2048" {
					t.Errorf("wrong error returned: %s", err.Error())
				}
			},
		},
		{
			algorithm: jwa.PS512,
			opts:      nil,
			verify: func(t *testing.T, signer model.Signer, err error) {
				if err != nil {
					t.Fatalf("no error expected: %s", err.Error())
				}
				if signer.Alg() != jwa.PS512 {
					t.Errorf("wrong algorithm returned: %s", signer.Alg())
				}
			},
		},
		{
			algorithm: jwa.PS512,
			opts: &model.Opts{
				BitSize: 2048,
			},
			verify: func(t *testing.T, signer model.Signer, err error) {
				if err != nil {
					t.Fatalf("no error expected: %s", err.Error())
				}
				if signer.Alg() != jwa.PS512 {
					t.Errorf("wrong algorithm returned: %s", signer.Alg())
				}
			},
		},
		{
			algorithm: jwa.PS512,
			opts: &model.Opts{
				BitSize: 1024,
			},
			verify: func(t *testing.T, signer model.Signer, err error) {
				if err == nil {
					t.Fatalf("an error should have been thrown")
				}
				if err.Error() != "specified key bit size should be at least 2048" {
					t.Errorf("wrong error returned: %s", err.Error())
				}
			},
		},
		{
			algorithm: jwa.ES256,
			opts:      nil,
			verify: func(t *testing.T, signer model.Signer, err error) {
				if err != nil {
					t.Fatalf("no error expected: %s", err.Error())
				}
				if signer.Alg() != jwa.ES256 {
					t.Errorf("wrong algorithm returned: %s", signer.Alg())
				}
			},
		},
		{
			algorithm: jwa.ES256,
			opts: &model.Opts{
				BitSize: 2048,
			},
			verify: func(t *testing.T, signer model.Signer, err error) {
				if err != nil {
					t.Fatalf("no error expected: %s", err.Error())
				}
				if signer.Alg() != jwa.ES256 {
					t.Errorf("wrong algorithm returned: %s", signer.Alg())
				}
			},
		},
		{
			algorithm: jwa.ES256,
			opts: &model.Opts{
				BitSize: 1024,
			},
			verify: func(t *testing.T, signer model.Signer, err error) {
				if err != nil {
					t.Fatalf("no error expected: %s", err.Error())
				}
				if signer.Alg() != jwa.ES256 {
					t.Errorf("wrong algorithm returned: %s", signer.Alg())
				}
			},
		},
		{
			algorithm: jwa.ES384,
			opts:      nil,
			verify: func(t *testing.T, signer model.Signer, err error) {
				if err != nil {
					t.Fatalf("no error expected: %s", err.Error())
				}
				if signer.Alg() != jwa.ES384 {
					t.Errorf("wrong algorithm returned: %s", signer.Alg())
				}
			},
		},
		{
			algorithm: jwa.ES384,
			opts: &model.Opts{
				BitSize: 2048,
			},
			verify: func(t *testing.T, signer model.Signer, err error) {
				if err != nil {
					t.Fatalf("no error expected: %s", err.Error())
				}
				if signer.Alg() != jwa.ES384 {
					t.Errorf("wrong algorithm returned: %s", signer.Alg())
				}
			},
		},
		{
			algorithm: jwa.ES384,
			opts: &model.Opts{
				BitSize: 1024,
			},
			verify: func(t *testing.T, signer model.Signer, err error) {
				if err != nil {
					t.Fatalf("no error expected: %s", err.Error())
				}
				if signer.Alg() != jwa.ES384 {
					t.Errorf("wrong algorithm returned: %s", signer.Alg())
				}
			},
		},
		{
			algorithm: jwa.ES512,
			opts:      nil,
			verify: func(t *testing.T, signer model.Signer, err error) {
				if err != nil {
					t.Fatalf("no error expected: %s", err.Error())
				}
				if signer.Alg() != jwa.ES512 {
					t.Errorf("wrong algorithm returned: %s", signer.Alg())
				}
			},
		},
		{
			algorithm: jwa.ES512,
			opts: &model.Opts{
				BitSize: 2048,
			},
			verify: func(t *testing.T, signer model.Signer, err error) {
				if err != nil {
					t.Fatalf("no error expected: %s", err.Error())
				}
				if signer.Alg() != jwa.ES512 {
					t.Errorf("wrong algorithm returned: %s", signer.Alg())
				}
			},
		},
		{
			algorithm: jwa.ES512,
			opts: &model.Opts{
				BitSize: 1024,
			},
			verify: func(t *testing.T, signer model.Signer, err error) {
				if err != nil {
					t.Fatalf("no error expected: %s", err.Error())
				}
				if signer.Alg() != jwa.ES512 {
					t.Errorf("wrong algorithm returned: %s", signer.Alg())
				}
			},
		},
		{
			algorithm: jwa.HS256,
			opts:      nil,
			verify: func(t *testing.T, signer model.Signer, err error) {
				if err == nil {
					t.Fatalf("an error should have been thrown")
				}
				if err.Error() != "secret key must be specified for HS algorithms" {
					t.Errorf("wrong error returned: %s", err.Error())
				}
			},
		},
		{
			algorithm: jwa.HS256,
			opts: &model.Opts{
				SecretKey: &secretKey,
			},
			verify: func(t *testing.T, signer model.Signer, err error) {
				if err != nil {
					t.Fatalf("no error expected: %s", err.Error())
				}
				if signer.Alg() != jwa.HS256 {
					t.Errorf("wrong algorithm returned: %s", signer.Alg())
				}
			},
		},
		{
			algorithm: jwa.HS256,
			opts:      &model.Opts{},
			verify: func(t *testing.T, signer model.Signer, err error) {
				if err == nil {
					t.Fatalf("an error should have been thrown")
				}
				if err.Error() != "secret key must be specified for HS algorithms" {
					t.Errorf("wrong error returned: %s", err.Error())
				}
			},
		},
		{
			algorithm: jwa.HS384,
			opts:      nil,
			verify: func(t *testing.T, signer model.Signer, err error) {
				if err == nil {
					t.Fatalf("an error should have been thrown")
				}
				if err.Error() != "secret key must be specified for HS algorithms" {
					t.Errorf("wrong error returned: %s", err.Error())
				}
			},
		},
		{
			algorithm: jwa.HS384,
			opts: &model.Opts{
				SecretKey: &secretKey,
			},
			verify: func(t *testing.T, signer model.Signer, err error) {
				if err != nil {
					t.Fatalf("no error expected: %s", err.Error())
				}
				if signer.Alg() != jwa.HS384 {
					t.Errorf("wrong algorithm returned: %s", signer.Alg())
				}
			},
		},
		{
			algorithm: jwa.HS384,
			opts:      &model.Opts{},
			verify: func(t *testing.T, signer model.Signer, err error) {
				if err == nil {
					t.Fatalf("an error should have been thrown")
				}
				if err.Error() != "secret key must be specified for HS algorithms" {
					t.Errorf("wrong error returned: %s", err.Error())
				}
			},
		},
		{
			algorithm: jwa.HS512,
			opts:      nil,
			verify: func(t *testing.T, signer model.Signer, err error) {
				if err == nil {
					t.Fatalf("an error should have been thrown")
				}
				if err.Error() != "secret key must be specified for HS algorithms" {
					t.Errorf("wrong error returned: %s", err.Error())
				}
			},
		},
		{
			algorithm: jwa.HS512,
			opts: &model.Opts{
				SecretKey: &secretKey,
			},
			verify: func(t *testing.T, signer model.Signer, err error) {
				if err != nil {
					t.Fatalf("no error expected: %s", err.Error())
				}
				if signer.Alg() != jwa.HS512 {
					t.Errorf("wrong algorithm returned: %s", signer.Alg())
				}
			},
		},
		{
			algorithm: jwa.HS512,
			opts:      &model.Opts{},
			verify: func(t *testing.T, signer model.Signer, err error) {
				if err == nil {
					t.Fatalf("an error should have been thrown")
				}
				if err.Error() != "secret key must be specified for HS algorithms" {
					t.Errorf("wrong error returned: %s", err.Error())
				}
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.algorithm.String(), func(t *testing.T) {
			signer, err := GetSigner(tt.algorithm, tt.opts)
			tt.verify(t, signer, err)
		})
	}
}
