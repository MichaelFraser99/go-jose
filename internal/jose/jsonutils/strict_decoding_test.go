package jsonutils

import (
	"bytes"
	"errors"
	"reflect"
	"strconv"
	"strings"
	"testing"

	"github.com/MichaelFraser99/go-jose/joseerror"
)

func TestDecodeBase64url_AcceptsOnlyTheOneEncodingRFC7515Section2Defines(t *testing.T) {
	tests := map[string]struct {
		encoded string
		want    []byte
		clause  string
	}{
		"empty":                            {"", []byte{}, "RFC 7515 2"},
		"two characters":                   {"_w", []byte{0xff}, "RFC 4648 5"},
		"three characters":                 {"-_8", []byte{0xfb, 0xff}, "RFC 4648 5"},
		"four characters":                  {"AQID", []byte{1, 2, 3}, "RFC 4648 5"},
		"non-zero pad bits after 1 octet":  {"_x", nil, "RFC 4648 3.5"},
		"non-zero pad bits after 2 octets": {"-_9", nil, "RFC 4648 3.5"},
		"LF":                               {"AQ\nID", nil, "RFC 7515 2"},
		"CR":                               {"AQ\rID", nil, "RFC 7515 2"},
		"CRLF":                             {"AQ\r\nID", nil, "RFC 7515 2"},
		"trailing LF":                      {"AQID\n", nil, "RFC 7515 2"},
		"space":                            {"AQ ID", nil, "RFC 7515 2"},
		"tab":                              {"AQ\tID", nil, "RFC 7515 2"},
		"padding":                          {"AQ==", nil, "RFC 7515 2"},
		"standard alphabet plus":           {"+w", nil, "RFC 4648 5"},
		"standard alphabet slash":          {"/w", nil, "RFC 4648 5"},
		"NUL":                              {"AQ\x00ID", nil, "RFC 7515 2"},
		"a byte above 0x7f":                {"AQ\xffID", nil, "RFC 7515 2"},
		"one character":                    {"A", nil, "RFC 4648 5"},
	}
	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			got, err := DecodeBase64url(test.encoded)
			if test.want == nil {
				if err == nil {
					t.Fatalf("[%s] %q decoded to %x", test.clause, test.encoded, got)
				}
				return
			}
			if err != nil || !bytes.Equal(got, test.want) {
				t.Fatalf("[%s] %q decoded to %x, %v; want %x", test.clause, test.encoded, got, err, test.want)
			}
		})
	}
}

func TestDecodeBase64urlMap_RequiresAUTF8JSONObject(t *testing.T) {
	tests := map[string]struct {
		encoded string
		valid   bool
		clause  string
	}{
		"object":                          {"eyJhIjoxfQ", true, "RFC 7515 5.2 step 3"},
		"empty object":                    {"e30", true, "RFC 7515 5.2 step 3"},
		"null":                            {"bnVsbA", false, "RFC 7519 7.2 step 10"},
		"null within spaces":              {"IG51bGwg", false, "RFC 7519 7.2 step 10"},
		"array":                           {"WzEsMl0", false, "RFC 7519 7.2 step 10"},
		"string holding the byte 0xff":    {"eyJhIjoiYf8ifQ", false, "RFC 8725 3.7"},
		"object with a LF in the segment": {"eyJhIjo\nxfQ", false, "RFC 7515 5.2 step 2"},
	}
	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			m, err := DecodeBase64urlMap(test.encoded)
			if test.valid != (err == nil) {
				t.Fatalf("[%s] %q gave %v, %v", test.clause, test.encoded, m, err)
			}
			if test.valid && m == nil {
				t.Fatalf("[%s] %q gave a nil object", test.clause, test.encoded)
			}
		})
	}
}

func TestDecodeJSONObject_RefusesAnUnpairedSurrogateEscape(t *testing.T) {
	tests := map[string]struct {
		text string
		want map[string]any
	}{
		"lone high surrogate":                        {`{"sub":"\ud800"}`, nil},
		"lone low surrogate":                         {`{"sub":"\udfff"}`, nil},
		"upper-case hex":                             {`{"sub":"\uD800"}`, nil},
		"low surrogate before high":                  {`{"sub":"\udc00\ud800"}`, nil},
		"high surrogate then a non-surrogate escape": {`{"sub":"\ud800\u0041"}`, nil},
		"high surrogate then another high surrogate": {`{"sub":"\ud800\ud800"}`, nil},
		"high surrogate then a plain character":      {`{"sub":"\ud800a"}`, nil},
		"high surrogate then a character then a low": {`{"sub":"\ud800zudc00"}`, nil},
		"high surrogate then an escaped quote":       {`{"sub":"\ud800\""}`, nil},
		"lone surrogate in a member name":            {`{"\ud800":"a"}`, nil},
		"lone surrogate after an escaped quote":      {`{"sub":"a\"\ud800"}`, nil},
		"lone surrogate after an escaped backslash":  {`{"sub":"\\\ud800"}`, nil},
		"lone surrogate inside an array":             {`{"aud":["a","\udfff"]}`, nil},
		"lone surrogate in a later member":           {`{"a":"\\","sub":"\ud800"}`, nil},
		"escaped replacement character":              {`{"sub":"\ufffd"}`, map[string]any{"sub": "\uFFFD"}},
		"raw replacement character":                  {"{\"sub\":\"\uFFFD\"}", map[string]any{"sub": "\uFFFD"}},
		"escaped backslash before u":                 {`{"sub":"\\ud800"}`, map[string]any{"sub": `\ud800`}},
		"escaped backslash before surrogate hex":     {`{"sub":"\\dc00"}`, map[string]any{"sub": `\dc00`}},
		"escaped quote before surrogate hex":         {`{"sub":"\"d800"}`, map[string]any{"sub": `"d800`}},
		"escaped pair":                               {`{"sub":"\ud83d\ude00"}`, map[string]any{"sub": "\U0001F600"}},
		"upper-case escaped pair":                    {`{"sub":"\uD83D\uDE00"}`, map[string]any{"sub": "\U0001F600"}},
		"raw supplementary character":                {"{\"sub\":\"\U0001F600\"}", map[string]any{"sub": "\U0001F600"}},
		"escapes either side of the surrogate range": {`{"sub":"\u0041\ud7ff\ue000"}`, map[string]any{"sub": "A\ud7ff\ue000"}},
		"escaped quote then an escaped backslash":    {`{"sub":"\"\\","b":"\\ud800"}`, map[string]any{"sub": `"\`, "b": `\ud800`}},
	}
	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			got, err := DecodeJSONObject([]byte(test.text))
			if test.want == nil {
				if err == nil {
					t.Fatalf("[RFC 8259 8.2] %s decoded to %q", test.text, got)
				}
				return
			}
			if err != nil || !reflect.DeepEqual(got, test.want) {
				t.Fatalf("[RFC 8259 7] %s decoded to %q, %v; want %q", test.text, got, err, test.want)
			}
		})
	}
}

func TestExtractAndDecodeBase64urlString_IsStrict(t *testing.T) {
	for _, value := range []string{"_x", "AQ\r\nID", "AQ=="} {
		t.Run(strconv.Quote(value), func(t *testing.T) {
			got, err := ExtractAndDecodeBase64urlString(map[string]any{"x": value}, "x")
			if !errors.Is(err, joseerror.ErrMalformedClaim) {
				t.Fatalf("[RFC 7515 2] %q decoded to %x, %v", value, got, err)
			}
		})
	}
}

func TestValidateBase64Url_IsStrict(t *testing.T) {
	for _, value := range []string{"_x", "AQ\r\nID", "AQ ID"} {
		t.Run(strconv.Quote(value), func(t *testing.T) {
			if err := ValidateBase64Url(nil, value); !errors.Is(err, joseerror.ErrMalformedClaim) {
				t.Fatalf("[RFC 7515 2] %q was accepted as base64url: %v", value, err)
			}
		})
	}
}

func TestQuoteBounded_QuotesAndKeepsAtMostMaxEchoedRunes(t *testing.T) {
	tests := map[string]struct {
		value string
		want  string
	}{
		"empty":                    {"", strconv.Quote("")},
		"CR LF":                    {"a\r\nb", strconv.Quote("a\r\nb")},
		"exactly the cap":          {strings.Repeat("A", 64), strconv.Quote(strings.Repeat("A", 64))},
		"one over the cap":         {strings.Repeat("A", 65), strconv.Quote(strings.Repeat("A", 64)) + "..."},
		"multi-byte runes":         {strings.Repeat("é", 65), strconv.Quote(strings.Repeat("é", 64)) + "..."},
		"bytes that are not UTF-8": {strings.Repeat("\xff", 65), strconv.Quote(strings.Repeat("\xff", 64)) + "..."},
	}
	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			if got := QuoteBounded(test.value); got != test.want {
				t.Fatalf("[robustness] QuoteBounded gave %s, want %s", got, test.want)
			}
		})
	}
}
