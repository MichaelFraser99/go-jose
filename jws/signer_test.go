package jws

import (
	"github.com/MichaelFraser99/go-jose/model"
	"testing"
)

func TestGetSigner(t *testing.T) {
	secretKey := []byte("a super secret key")
	tests := []struct {
		algorithm model.Algorithm
		opts      *model.Opts
		verify    func(t *testing.T, signer model.Signer, err error)
	}{
		{
			algorithm: model.RS256,
			opts:      nil,
			verify: func(t *testing.T, signer model.Signer, err error) {
				if err != nil {
					t.Fatalf("no error expected: %s", err.Error())
				}
				if signer.Alg() != model.RS256 {
					t.Errorf("wrong algorithm returned: %s", signer.Alg())
				}
			},
		},
		{
			algorithm: model.RS256,
			opts: &model.Opts{
				BitSize: 2048,
			},
			verify: func(t *testing.T, signer model.Signer, err error) {
				if err != nil {
					t.Fatalf("no error expected: %s", err.Error())
				}
				if signer.Alg() != model.RS256 {
					t.Errorf("wrong algorithm returned: %s", signer.Alg())
				}
			},
		},
		{
			algorithm: model.RS256,
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
			algorithm: model.RS384,
			opts:      nil,
			verify: func(t *testing.T, signer model.Signer, err error) {
				if err != nil {
					t.Fatalf("no error expected: %s", err.Error())
				}
				if signer.Alg() != model.RS384 {
					t.Errorf("wrong algorithm returned: %s", signer.Alg())
				}
			},
		},
		{
			algorithm: model.RS384,
			opts: &model.Opts{
				BitSize: 2048,
			},
			verify: func(t *testing.T, signer model.Signer, err error) {
				if err != nil {
					t.Fatalf("no error expected: %s", err.Error())
				}
				if signer.Alg() != model.RS384 {
					t.Errorf("wrong algorithm returned: %s", signer.Alg())
				}
			},
		},
		{
			algorithm: model.RS384,
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
			algorithm: model.RS512,
			opts:      nil,
			verify: func(t *testing.T, signer model.Signer, err error) {
				if err != nil {
					t.Fatalf("no error expected: %s", err.Error())
				}
				if signer.Alg() != model.RS512 {
					t.Errorf("wrong algorithm returned: %s", signer.Alg())
				}
			},
		},
		{
			algorithm: model.RS512,
			opts: &model.Opts{
				BitSize: 2048,
			},
			verify: func(t *testing.T, signer model.Signer, err error) {
				if err != nil {
					t.Fatalf("no error expected: %s", err.Error())
				}
				if signer.Alg() != model.RS512 {
					t.Errorf("wrong algorithm returned: %s", signer.Alg())
				}
			},
		},
		{
			algorithm: model.RS512,
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
			algorithm: model.PS256,
			opts:      nil,
			verify: func(t *testing.T, signer model.Signer, err error) {
				if err != nil {
					t.Fatalf("no error expected: %s", err.Error())
				}
				if signer.Alg() != model.PS256 {
					t.Errorf("wrong algorithm returned: %s", signer.Alg())
				}
			},
		},
		{
			algorithm: model.PS256,
			opts: &model.Opts{
				BitSize: 2048,
			},
			verify: func(t *testing.T, signer model.Signer, err error) {
				if err != nil {
					t.Fatalf("no error expected: %s", err.Error())
				}
				if signer.Alg() != model.PS256 {
					t.Errorf("wrong algorithm returned: %s", signer.Alg())
				}
			},
		},
		{
			algorithm: model.PS256,
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
			algorithm: model.PS384,
			opts:      nil,
			verify: func(t *testing.T, signer model.Signer, err error) {
				if err != nil {
					t.Fatalf("no error expected: %s", err.Error())
				}
				if signer.Alg() != model.PS384 {
					t.Errorf("wrong algorithm returned: %s", signer.Alg())
				}
			},
		},
		{
			algorithm: model.PS384,
			opts: &model.Opts{
				BitSize: 2048,
			},
			verify: func(t *testing.T, signer model.Signer, err error) {
				if err != nil {
					t.Fatalf("no error expected: %s", err.Error())
				}
				if signer.Alg() != model.PS384 {
					t.Errorf("wrong algorithm returned: %s", signer.Alg())
				}
			},
		},
		{
			algorithm: model.PS384,
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
			algorithm: model.PS512,
			opts:      nil,
			verify: func(t *testing.T, signer model.Signer, err error) {
				if err != nil {
					t.Fatalf("no error expected: %s", err.Error())
				}
				if signer.Alg() != model.PS512 {
					t.Errorf("wrong algorithm returned: %s", signer.Alg())
				}
			},
		},
		{
			algorithm: model.PS512,
			opts: &model.Opts{
				BitSize: 2048,
			},
			verify: func(t *testing.T, signer model.Signer, err error) {
				if err != nil {
					t.Fatalf("no error expected: %s", err.Error())
				}
				if signer.Alg() != model.PS512 {
					t.Errorf("wrong algorithm returned: %s", signer.Alg())
				}
			},
		},
		{
			algorithm: model.PS512,
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
			algorithm: model.ES256,
			opts:      nil,
			verify: func(t *testing.T, signer model.Signer, err error) {
				if err != nil {
					t.Fatalf("no error expected: %s", err.Error())
				}
				if signer.Alg() != model.ES256 {
					t.Errorf("wrong algorithm returned: %s", signer.Alg())
				}
			},
		},
		{
			algorithm: model.ES256,
			opts: &model.Opts{
				BitSize: 2048,
			},
			verify: func(t *testing.T, signer model.Signer, err error) {
				if err != nil {
					t.Fatalf("no error expected: %s", err.Error())
				}
				if signer.Alg() != model.ES256 {
					t.Errorf("wrong algorithm returned: %s", signer.Alg())
				}
			},
		},
		{
			algorithm: model.ES256,
			opts: &model.Opts{
				BitSize: 1024,
			},
			verify: func(t *testing.T, signer model.Signer, err error) {
				if err != nil {
					t.Fatalf("no error expected: %s", err.Error())
				}
				if signer.Alg() != model.ES256 {
					t.Errorf("wrong algorithm returned: %s", signer.Alg())
				}
			},
		},
		{
			algorithm: model.ES384,
			opts:      nil,
			verify: func(t *testing.T, signer model.Signer, err error) {
				if err != nil {
					t.Fatalf("no error expected: %s", err.Error())
				}
				if signer.Alg() != model.ES384 {
					t.Errorf("wrong algorithm returned: %s", signer.Alg())
				}
			},
		},
		{
			algorithm: model.ES384,
			opts: &model.Opts{
				BitSize: 2048,
			},
			verify: func(t *testing.T, signer model.Signer, err error) {
				if err != nil {
					t.Fatalf("no error expected: %s", err.Error())
				}
				if signer.Alg() != model.ES384 {
					t.Errorf("wrong algorithm returned: %s", signer.Alg())
				}
			},
		},
		{
			algorithm: model.ES384,
			opts: &model.Opts{
				BitSize: 1024,
			},
			verify: func(t *testing.T, signer model.Signer, err error) {
				if err != nil {
					t.Fatalf("no error expected: %s", err.Error())
				}
				if signer.Alg() != model.ES384 {
					t.Errorf("wrong algorithm returned: %s", signer.Alg())
				}
			},
		},
		{
			algorithm: model.ES512,
			opts:      nil,
			verify: func(t *testing.T, signer model.Signer, err error) {
				if err != nil {
					t.Fatalf("no error expected: %s", err.Error())
				}
				if signer.Alg() != model.ES512 {
					t.Errorf("wrong algorithm returned: %s", signer.Alg())
				}
			},
		},
		{
			algorithm: model.ES512,
			opts: &model.Opts{
				BitSize: 2048,
			},
			verify: func(t *testing.T, signer model.Signer, err error) {
				if err != nil {
					t.Fatalf("no error expected: %s", err.Error())
				}
				if signer.Alg() != model.ES512 {
					t.Errorf("wrong algorithm returned: %s", signer.Alg())
				}
			},
		},
		{
			algorithm: model.ES512,
			opts: &model.Opts{
				BitSize: 1024,
			},
			verify: func(t *testing.T, signer model.Signer, err error) {
				if err != nil {
					t.Fatalf("no error expected: %s", err.Error())
				}
				if signer.Alg() != model.ES512 {
					t.Errorf("wrong algorithm returned: %s", signer.Alg())
				}
			},
		},
		{
			algorithm: model.HS256,
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
			algorithm: model.HS256,
			opts: &model.Opts{
				SecretKey: &secretKey,
			},
			verify: func(t *testing.T, signer model.Signer, err error) {
				if err != nil {
					t.Fatalf("no error expected: %s", err.Error())
				}
				if signer.Alg() != model.HS256 {
					t.Errorf("wrong algorithm returned: %s", signer.Alg())
				}
			},
		},
		{
			algorithm: model.HS256,
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
			algorithm: model.HS384,
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
			algorithm: model.HS384,
			opts: &model.Opts{
				SecretKey: &secretKey,
			},
			verify: func(t *testing.T, signer model.Signer, err error) {
				if err != nil {
					t.Fatalf("no error expected: %s", err.Error())
				}
				if signer.Alg() != model.HS384 {
					t.Errorf("wrong algorithm returned: %s", signer.Alg())
				}
			},
		},
		{
			algorithm: model.HS384,
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
			algorithm: model.HS512,
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
			algorithm: model.HS512,
			opts: &model.Opts{
				SecretKey: &secretKey,
			},
			verify: func(t *testing.T, signer model.Signer, err error) {
				if err != nil {
					t.Fatalf("no error expected: %s", err.Error())
				}
				if signer.Alg() != model.HS512 {
					t.Errorf("wrong algorithm returned: %s", signer.Alg())
				}
			},
		},
		{
			algorithm: model.HS512,
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
