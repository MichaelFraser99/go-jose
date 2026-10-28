package model

import (
	"encoding/json"
	"errors"
	"testing"

	"github.com/MichaelFraser99/go-jose/joseerror"
)

func TestJwks_UnmarshalJSON(t *testing.T) {
	a := `{"kty":"EC","kid":"a"}`
	b := `{"kty":"EC","kid":"b"}`
	tests := map[string]struct {
		doc      string
		wantKids []string
		refuse   bool
		clause   string
	}{
		"a keys member holding keys":               {doc: `{"keys":[` + a + `,` + b + `]}`, wantKids: []string{"a", "b"}, clause: "RFC 7517 5"},
		"a keys member holding no keys":            {doc: `{"keys":[]}`, wantKids: []string{}, clause: "RFC 7517 5"},
		"a keys member beside an unknown member":   {doc: `{"other":1,"keys":[` + a + `]}`, wantKids: []string{"a"}, clause: "RFC 7517 5"},
		"a keys member whose name is escaped":      {doc: `{"\u006beys":[` + a + `]}`, wantKids: []string{"a"}, clause: "RFC 8259 8.3"},
		"a duplicated keys member keeps the last":  {doc: `{"keys":[` + a + `],"keys":[` + b + `]}`, wantKids: []string{"b"}, clause: "RFC 7517 5"},
		"keys followed by Keys":                    {doc: `{"keys":[` + a + `],"Keys":[` + b + `]}`, wantKids: []string{"a"}, clause: "RFC 7515 5.3"},
		"Keys followed by keys":                    {doc: `{"Keys":[` + b + `],"keys":[` + a + `]}`, wantKids: []string{"a"}, clause: "RFC 7515 5.3"},
		"keys followed by Keys with a Kelvin sign": {doc: `{"keys":[` + a + `],"Keys":[` + b + `]}`, wantKids: []string{"a"}, clause: "RFC 7515 5.3"},
		"keys followed by keys with a long s":      {doc: `{"keys":[` + a + `],"key` + "ſ" + `":[` + b + `]}`, wantKids: []string{"a"}, clause: "RFC 7515 5.3"},
		"only KEYS":                                {doc: `{"KEYS":[` + b + `]}`, refuse: true, clause: "RFC 7517 5"},
		"only keys spelt with a long s":            {doc: `{"key` + "ſ" + `":[` + b + `]}`, refuse: true, clause: "RFC 7517 5"},
		"no keys member":                           {doc: `{"foo":[]}`, refuse: true, clause: "RFC 7517 5"},
		"a keys member that is null":               {doc: `{"keys":null}`, refuse: true, clause: "RFC 7517 5"},
		"a keys member that is an object":          {doc: `{"keys":{"0":` + a + `}}`, refuse: true, clause: "RFC 7517 5"},
		"a keys member that is a string":           {doc: `{"keys":"` + "[]" + `"}`, refuse: true, clause: "RFC 7517 5"},
		"a keys member holding a value not a jwk":  {doc: `{"keys":[` + a + `,7]}`, refuse: true, clause: "RFC 7517 5.1"},
		"a document that is null":                  {doc: `null`, refuse: true, clause: "RFC 7517 5"},
		"a document that is an array":              {doc: `[` + a + `]`, refuse: true, clause: "RFC 7517 5"},
	}
	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			var set Jwks
			err := json.Unmarshal([]byte(tc.doc), &set)
			if tc.refuse {
				if err == nil {
					t.Fatalf("[%s] a JWK Set MUST have a \"keys\" member holding an array, yet %s decoded to %d keys", tc.clause, tc.doc, len(set.Keys))
				}
				if !errors.Is(err, joseerror.ErrKeystoreError) {
					t.Errorf("[%s] expected ErrKeystoreError, got %v", tc.clause, err)
				}
				return
			}
			if err != nil {
				t.Fatalf("[%s] expected %s to decode, got %v", tc.clause, tc.doc, err)
			}
			if set.Keys == nil {
				t.Fatalf("[%s] a JWK Set's keys must decode to a non-nil slice", tc.clause)
			}
			if len(set.Keys) != len(tc.wantKids) {
				t.Fatalf("[%s] expected %d keys, got %d", tc.clause, len(tc.wantKids), len(set.Keys))
			}
			for i, kid := range tc.wantKids {
				if got := set.Keys[i]["kid"]; got != kid {
					t.Errorf("[%s] key %d must carry kid %q from the \"keys\" member, got %v", tc.clause, i, kid, got)
				}
			}
		})
	}
}

func TestJwks_UnmarshalJSONKeepsOptions(t *testing.T) {
	set := Jwks{}
	set.Opts.EnforceUniqueKIDs = true
	if err := json.Unmarshal([]byte(`{"keys":[]}`), &set); err != nil {
		t.Fatalf("[RFC 7517 5] expected the set to decode, got %v", err)
	}
	if !set.Opts.EnforceUniqueKIDs {
		t.Error("[RFC 7517 5] decoding a JWK Set must not reset options that are not part of the document")
	}
}

func TestJwks_MarshalJSONWritesWhatItReads(t *testing.T) {
	a := map[string]any{"kty": "EC", "kid": "a"}
	tests := map[string]struct {
		set      Jwks
		wantDoc  string
		wantKids []string
	}{
		"a set with no keys":    {set: Jwks{}, wantDoc: `{"keys":[]}`, wantKids: []string{}},
		"a set with empty keys": {set: Jwks{Keys: []map[string]any{}}, wantDoc: `{"keys":[]}`, wantKids: []string{}},
		"a set with a key":      {set: Jwks{Keys: []map[string]any{a}}, wantDoc: `{"keys":[{"kid":"a","kty":"EC"}]}`, wantKids: []string{"a"}},
	}
	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			for _, form := range []struct {
				name  string
				value any
			}{{"value", tc.set}, {"pointer", &tc.set}, {"field", struct{ Set Jwks }{tc.set}}} {
				doc, err := json.Marshal(form.value)
				if err != nil {
					t.Fatalf("[RFC 7517 5] expected the %s to encode, got %v", form.name, err)
				}
				if form.name == "field" {
					var wrapper map[string]json.RawMessage
					if err := json.Unmarshal(doc, &wrapper); err != nil {
						t.Fatalf("[RFC 7517 5] expected a JSON object, got %s", doc)
					}
					doc = wrapper["Set"]
				}
				if string(doc) != tc.wantDoc {
					t.Errorf("[RFC 7517 5] the %s must encode the \"keys\" member as an array, expected %s, got %s", form.name, tc.wantDoc, doc)
				}
				var read Jwks
				if err := json.Unmarshal(doc, &read); err != nil {
					t.Fatalf("[RFC 7517 5] a set this library writes must read back, got %v", err)
				}
				if len(read.Keys) != len(tc.wantKids) {
					t.Fatalf("[RFC 7517 5] expected %d keys after the round trip, got %d", len(tc.wantKids), len(read.Keys))
				}
				for i, kid := range tc.wantKids {
					if got := read.Keys[i]["kid"]; got != kid {
						t.Errorf("[RFC 7517 5] key %d must carry kid %q after the round trip, got %v", i, kid, got)
					}
				}
			}
		})
	}
}
