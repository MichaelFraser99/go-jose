package jwe

import (
	"context"
	"encoding/base64"
	"errors"
	"strings"
	"testing"

	"github.com/MichaelFraser99/go-jose/joseerror"
	"github.com/MichaelFraser99/go-jose/jwa"
	"github.com/MichaelFraser99/go-jose/model"
)

func TestDecryptAndParseHeader_AHeaderDecoderErrorEchoesABoundedPrefix(t *testing.T) {
	decrypter, err := GetDecrypter(jwa.A128KW, make([]byte, 16))
	if err != nil {
		t.Fatal(err)
	}
	head := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"A128KW","enc":"A128GCM","n":` + strings.Repeat("9", 1_000_000) + `}`))
	token := head + ".AAAA.AAAA.AAAA.AAAA"

	_, _, _, decryptErr := Decrypt(context.Background(), token, []model.Decrypter{decrypter}, nil)
	_, parseErr := ParseHeader(token, nil)
	for name, err := range map[string]error{"Decrypt": decryptErr, "ParseHeader": parseErr} {
		if !errors.Is(err, joseerror.ErrMalformedToken) {
			t.Errorf("[RFC 8259 6] %s must refuse a header number beyond the float64 range with ErrMalformedToken, got %v", name, err)
			continue
		}
		if len(err.Error()) > 512 || strings.Contains(err.Error(), strings.Repeat("9", 100)) {
			t.Errorf("%s must echo a bounded prefix of the peer's header, got %d bytes", name, len(err.Error()))
		}
	}
}
