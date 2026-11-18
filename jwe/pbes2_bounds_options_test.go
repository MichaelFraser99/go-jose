package jwe

import (
	"context"
	"errors"
	"testing"

	"github.com/MichaelFraser99/go-jose/joseerror"
	"github.com/MichaelFraser99/go-jose/jwa"
	"github.com/MichaelFraser99/go-jose/model"
)

func TestCheckOptions_RefusesPBES2BoundsNoTokenCanMeet(t *testing.T) {
	password := PasswordKey{Password: []byte("correct horse battery staple"), Count: 1000}
	decrypters := func(n int) []model.Decrypter {
		var out []model.Decrypter
		for range n {
			d, err := GetDecrypter(jwa.PBES2HS256A128KW, password)
			if err != nil {
				t.Fatal(err)
			}
			out = append(out, d)
		}
		return out
	}
	encrypter, err := GetEncrypter(jwa.PBES2HS256A128KW, password)
	if err != nil {
		t.Fatal(err)
	}
	token, err := Encrypt(encrypter, jwa.A128GCM, []byte("p"), nil)
	if err != nil {
		t.Fatal(err)
	}
	for name, tt := range map[string]struct {
		decrypters []model.Decrypter
		opts       *model.JWEOptions
		refused    bool
		belowCount bool
	}{
		"a maximum below 1000, with no decrypters":         {opts: &model.JWEOptions{RequireRecommendedPBES2Count: true, MaxPBES2Count: 999}, refused: true},
		"a maximum below 1000, with one decrypter":         {decrypters: decrypters(1), opts: &model.JWEOptions{RequireRecommendedPBES2Count: true, MaxPBES2Count: 500}, refused: true},
		"three decrypters within a maximum of 2000":        {decrypters: decrypters(3), opts: &model.JWEOptions{RequireRecommendedPBES2Count: true, MaxPBES2Count: 2000}, refused: true},
		"a maximum of exactly 1000, with one decrypter":    {decrypters: decrypters(1), opts: &model.JWEOptions{RequireRecommendedPBES2Count: true, MaxPBES2Count: 1000}},
		"two decrypters within a maximum of exactly 2000":  {decrypters: decrypters(2), opts: &model.JWEOptions{RequireRecommendedPBES2Count: true, MaxPBES2Count: 2000}},
		"a maximum below 1000, without the recommendation": {decrypters: decrypters(1), opts: &model.JWEOptions{MaxPBES2Count: 999}, belowCount: true},
		"the recommendation under the default maximum":     {decrypters: decrypters(3), opts: &model.JWEOptions{RequireRecommendedPBES2Count: true}},
	} {
		t.Run(name, func(t *testing.T) {
			err := CheckOptions(tt.decrypters, tt.opts)
			if tt.refused {
				if !errors.Is(err, joseerror.ErrInvalidOptions) {
					t.Errorf("[RFC 7518 4.8.1.2] no p2c can be at least 1000 and within the bound with %s, so want ErrInvalidOptions, got %v", name, err)
				}
				return
			}
			if err != nil {
				t.Errorf("[RFC 7518 4.8.1.2] a p2c of 1000 meets every bound with %s, so CheckOptions must accept it, got %v", name, err)
			}
			if tt.belowCount {
				return
			}
			if _, _, _, err := Decrypt(context.Background(), token, tt.decrypters, tt.opts); err != nil {
				t.Errorf("[RFC 7518 4.8.1.2] a token with a p2c of 1000 must pass with %s, got %v", name, err)
			}
		})
	}
}
