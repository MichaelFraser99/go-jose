package jws_test

import (
	"bytes"
	"context"
	"crypto"
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"

	"github.com/MichaelFraser99/go-jose/jwa"
	"github.com/MichaelFraser99/go-jose/jwk"
	"github.com/MichaelFraser99/go-jose/jws"
	"github.com/MichaelFraser99/go-jose/model"
)

const (
	rfc7515A1JWS = "eyJ0eXAiOiJKV1QiLA0KICJhbGciOiJIUzI1NiJ9.eyJpc3MiOiJqb2UiLA0KICJleHAiOjEzMDA4MTkzODAsDQogImh0dHA6Ly9leGFtcGxlLmNvbS9pc19yb290Ijp0cnVlfQ.dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
	rfc7515A1Key = `{"kty":"oct","k":"AyM1SysPpbyDfgZld3umj1qzKObwVMkoqQ-EstJQLr_T-1qS0gZH75aKtMN3Yj0iPS4hcgUuTwjAzZr1Z9CAow"}`
	rfc7515A3JWS = "eyJhbGciOiJFUzI1NiJ9.eyJpc3MiOiJqb2UiLA0KICJleHAiOjEzMDA4MTkzODAsDQogImh0dHA6Ly9leGFtcGxlLmNvbS9pc19yb290Ijp0cnVlfQ.DtEhU3ljbEg8L38VWAfUAqOyKAM6-Xx-F4GawxaepmXFCgfTjDxw5djxLa8ISlSApmWQxfKTUJqPP3-Kg6NU1Q"
	rfc7515A3Key = `{"kty":"EC","crv":"P-256","x":"f83OJ3D2xF1Bg8vub9tLe1gHMzV76e8Tus9uPHvRVEU","y":"x_FEzRu9m36HLN_tue659LNpXW6pCyStikYjKIWI5a0","d":"jpsQnnGQmL-YBIffH1136cspYG6-0iY7X1fCE9-E9LI"}`
	rfc7515A4JWS = "eyJhbGciOiJFUzUxMiJ9.UGF5bG9hZA.AdwMgeerwtHoh-l192l60hp9wAHZFVJbLfD_UxMi70cwnZOYaRI1bKPWROc-mZZqwqT2SI-KGDKB34XO0aw_7XdtAG8GaSwFKdCAPZgoXD2YBJZCPEX3xKpRwcdOO8KpEHwJjyqOgzDO7iKvU8vcnwNrmxYbSW9ERBXukOXolLzeO_Jn"
	rfc7515A4Key = `{"kty":"EC","crv":"P-521","x":"AekpBQ8ST8a8VcfVOTNl353vSrDCLLJXmPk06wTjxrrjcBpXp5EOnYG_NjFZ6OvLFV1jSfS9tsz4qUxcWceqwQGk","y":"ADSmRA43Z1DSNx_RvcLI87cdL07l6jQyyBXMoxVg_l2Th-x3S1WDhjDly79ajL4Kkd0AZMaZmh9ubmf63e3kyMj2","d":"AY5pb7A0UFiB3RELSD64fTLOSV_jazdF7fLYyuTw8lOfRhWg6Y6rUrPAxerEzgdRhajnu0ferB0d53vM9mE15j2C"}`

	rfc7520Figure1  = `{"kty":"EC","kid":"bilbo.baggins@hobbiton.example","use":"sig","crv":"P-521","x":"AHKZLLOsCOzz5cY97ewNUajB957y-C-U88c3v13nmGZx6sYl_oJXu9A5RkTKqjqvjyekWF-7ytDyRXYgCF5cj0Kt","y":"AdymlHvOiLxXkEhayXQnNCvDX4h9htZaCJN34kfmC6pV5OhQHiraVySsUdaQkAgDPrwQrJmbnX9cwlGfP-HqHZR1"}`
	rfc7520Figure2  = `{"kty":"EC","kid":"bilbo.baggins@hobbiton.example","use":"sig","crv":"P-521","x":"AHKZLLOsCOzz5cY97ewNUajB957y-C-U88c3v13nmGZx6sYl_oJXu9A5RkTKqjqvjyekWF-7ytDyRXYgCF5cj0Kt","y":"AdymlHvOiLxXkEhayXQnNCvDX4h9htZaCJN34kfmC6pV5OhQHiraVySsUdaQkAgDPrwQrJmbnX9cwlGfP-HqHZR1","d":"AAhRON2r9cqXX1hg-RoI6R1tX5p2rUAYdmpHZoC1XNM56KtscrX6zbKipQrCW9CGZH3T4ubpnoTKLDYJ_fF3_rJt"}`
	rfc7520Figure3  = `{"kty":"RSA","kid":"bilbo.baggins@hobbiton.example","use":"sig","n":"n4EPtAOCc9AlkeQHPzHStgAbgs7bTZLwUBZdR8_KuKPEHLd4rHVTeT-O-XV2jRojdNhxJWTDvNd7nqQ0VEiZQHz_AJmSCpMaJMRBSFKrKb2wqVwGU_NsYOYL-QtiWN2lbzcEe6XC0dApr5ydQLrHqkHHig3RBordaZ6Aj-oBHqFEHYpPe7Tpe-OfVfHd1E6cS6M1FZcD1NNLYD5lFHpPI9bTwJlsde3uhGqC0ZCuEHg8lhzwOHrtIQbS0FVbb9k3-tVTU4fg_3L_vniUFAKwuCLqKnS2BYwdq_mzSnbLY7h_qixoR7jig3__kRhuaxwUkRz5iaiQkqgc5gHdrNP5zw","e":"AQAB"}`
	rfc7520Figure4  = `{"kty":"RSA","kid":"bilbo.baggins@hobbiton.example","use":"sig","n":"n4EPtAOCc9AlkeQHPzHStgAbgs7bTZLwUBZdR8_KuKPEHLd4rHVTeT-O-XV2jRojdNhxJWTDvNd7nqQ0VEiZQHz_AJmSCpMaJMRBSFKrKb2wqVwGU_NsYOYL-QtiWN2lbzcEe6XC0dApr5ydQLrHqkHHig3RBordaZ6Aj-oBHqFEHYpPe7Tpe-OfVfHd1E6cS6M1FZcD1NNLYD5lFHpPI9bTwJlsde3uhGqC0ZCuEHg8lhzwOHrtIQbS0FVbb9k3-tVTU4fg_3L_vniUFAKwuCLqKnS2BYwdq_mzSnbLY7h_qixoR7jig3__kRhuaxwUkRz5iaiQkqgc5gHdrNP5zw","e":"AQAB","d":"bWUC9B-EFRIo8kpGfh0ZuyGPvMNKvYWNtB_ikiH9k20eT-O1q_I78eiZkpXxXQ0UTEs2LsNRS-8uJbvQ-A1irkwMSMkK1J3XTGgdrhCku9gRldY7sNA_AKZGh-Q661_42rINLRCe8W-nZ34ui_qOfkLnK9QWDDqpaIsA-bMwWWSDFu2MUBYwkHTMEzLYGqOe04noqeq1hExBTHBOBdkMXiuFhUq1BU6l-DqEiWxqg82sXt2h-LMnT3046AOYJoRioz75tSUQfGCshWTBnP5uDjd18kKhyv07lhfSJdrPdM5Plyl21hsFf4L_mHCuoFau7gdsPfHPxxjVOcOpBrQzwQ","p":"3Slxg_DwTXJcb6095RoXygQCAZ5RnAvZlno1yhHtnUex_fp7AZ_9nRaO7HX_-SFfGQeutao2TDjDAWU4Vupk8rw9JR0AzZ0N2fvuIAmr_WCsmGpeNqQnev1T7IyEsnh8UMt-n5CafhkikzhEsrmndH6LxOrvRJlsPp6Zv8bUq0k","q":"uKE2dh-cTf6ERF4k4e_jy78GfPYUIaUyoSSJuBzp3Cubk3OCqs6grT8bR_cu0Dm1MZwWmtdqDyI95HrUeq3MP15vMMON8lHTeZu2lmKvwqW7anV5UzhM1iZ7z4yMkuUwFWoBvyY898EXvRD-hdqRxHlSqAZ192zB3pVFJ0s7pFc","dp":"B8PVvXkvJrj2L-GYQ7v3y9r6Kw5g9SahXBwsWUzp19TVlgI-YV85q1NIb1rxQtD-IsXXR3-TanevuRPRt5OBOdiMGQp8pbt26gljYfKU_E9xn-RULHz0-ed9E9gXLKD4VGngpz-PfQ_q29pk5xWHoJp009Qf1HvChixRX59ehik","dq":"CLDmDGduhylc9o7r84rEUVn7pzQ6PF83Y-iBZx5NT-TpnOZKF1pErAMVeKzFEl41DlHHqqBLSM0W1sOFbwTxYWZDm6sI6og5iTbwQGIC3gnJKbi_7k_vJgGHwHxgPaX2PnvP-zyEkDERuf-ry4c_Z11Cq9AqC2yeL6kdKT1cYF8","qi":"3PiqvXQN0zwMeE-sBvZgi289XP9XCQF3VWqPzMKnIgQp7_Tugo6-NZBKCQsMf3HaEGBjTVJs_jcK8-TRXvaKe-7ZMaQj8VfBdYkssbu0NKDDhjJ-GtiseaDVWt7dcH0cfwxgFUHpQh7FoCrjFJ6h6ZEpMF6xmujs4qMpPz8aaI4"}`
	rfc7520Figure5  = `{"kty":"oct","kid":"018c0ae5-4d9b-471b-bfd6-eef314bc7037","use":"sig","alg":"HS256","k":"hJtXIZ2uSN5kbQfbtTNWbpdmhkV8FJG-Onbc6mxCcYg"}`
	rfc7520Figure13 = "eyJhbGciOiJSUzI1NiIsImtpZCI6ImJpbGJvLmJhZ2dpbnNAaG9iYml0b24uZXhhbXBsZSJ9.SXTigJlzIGEgZGFuZ2Vyb3VzIGJ1c2luZXNzLCBGcm9kbywgZ29pbmcgb3V0IHlvdXIgZG9vci4gWW91IHN0ZXAgb250byB0aGUgcm9hZCwgYW5kIGlmIHlvdSBkb24ndCBrZWVwIHlvdXIgZmVldCwgdGhlcmXigJlzIG5vIGtub3dpbmcgd2hlcmUgeW91IG1pZ2h0IGJlIHN3ZXB0IG9mZiB0by4.MRjdkly7_-oTPTS3AXP41iQIGKa80A0ZmTuV5MEaHoxnW2e5CZ5NlKtainoFmKZopdHM1O2U4mwzJdQx996ivp83xuglII7PNDi84wnB-BDkoBwA78185hX-Es4JIwmDLJK3lfWRa-XtL0RnltuYv746iYTh_qHRD68BNt1uSNCrUCTJDt5aAE6x8wW1Kt9eRo4QPocSadnHXFxnt8Is9UzpERV0ePPQdLuW3IS_de3xyIrDaLGdjluPxUAhb6L2aXic1U12podGU0KLUQSE_oI-ZnmKJ3F4uOZDnd6QZWJushZ41Axf_fcIe8u9ipH84ogoree7vjbU5y18kDquDg"
	rfc7520Figure20 = "eyJhbGciOiJQUzM4NCIsImtpZCI6ImJpbGJvLmJhZ2dpbnNAaG9iYml0b24uZXhhbXBsZSJ9.SXTigJlzIGEgZGFuZ2Vyb3VzIGJ1c2luZXNzLCBGcm9kbywgZ29pbmcgb3V0IHlvdXIgZG9vci4gWW91IHN0ZXAgb250byB0aGUgcm9hZCwgYW5kIGlmIHlvdSBkb24ndCBrZWVwIHlvdXIgZmVldCwgdGhlcmXigJlzIG5vIGtub3dpbmcgd2hlcmUgeW91IG1pZ2h0IGJlIHN3ZXB0IG9mZiB0by4.cu22eBqkYDKgIlTpzDXGvaFfz6WGoz7fUDcfT0kkOy42miAh2qyBzk1xEsnk2IpN6-tPid6VrklHkqsGqDqHCdP6O8TTB5dDDItllVo6_1OLPpcbUrhiUSMxbbXUvdvWXzg-UD8biiReQFlfz28zGWVsdiNAUf8ZnyPEgVFn442ZdNqiVJRmBqrYRXe8P_ijQ7p8Vdz0TTrxUeT3lm8d9shnr2lfJT8ImUjvAA2Xez2Mlp8cBE5awDzT0qI0n6uiP1aCN_2_jLAeQTlqRHtfa64QQSUmFAAjVKPbByi7xho0uTOcbH510a6GYmJUAfmWjwZ6oD4ifKo8DYM-X72Eaw"
	rfc7520Figure27 = "eyJhbGciOiJFUzUxMiIsImtpZCI6ImJpbGJvLmJhZ2dpbnNAaG9iYml0b24uZXhhbXBsZSJ9.SXTigJlzIGEgZGFuZ2Vyb3VzIGJ1c2luZXNzLCBGcm9kbywgZ29pbmcgb3V0IHlvdXIgZG9vci4gWW91IHN0ZXAgb250byB0aGUgcm9hZCwgYW5kIGlmIHlvdSBkb24ndCBrZWVwIHlvdXIgZmVldCwgdGhlcmXigJlzIG5vIGtub3dpbmcgd2hlcmUgeW91IG1pZ2h0IGJlIHN3ZXB0IG9mZiB0by4.AE_R_YZCChjn4791jSQCrdPZCNYqHXCTZH0-JZGYNlaAjP2kqaluUIIUnC9qvbu9Plon7KRTzoNEuT4Va2cmL1eJAQy3mtPBu_u_sDDyYjnAMDxXPn7XrT0lw-kvAD890jl8e2puQens_IEKBpHABlsbEPX6sFY8OcGDqoRuBomu9xQ2"
	rfc7520Figure34 = "eyJhbGciOiJIUzI1NiIsImtpZCI6IjAxOGMwYWU1LTRkOWItNDcxYi1iZmQ2LWVlZjMxNGJjNzAzNyJ9.SXTigJlzIGEgZGFuZ2Vyb3VzIGJ1c2luZXNzLCBGcm9kbywgZ29pbmcgb3V0IHlvdXIgZG9vci4gWW91IHN0ZXAgb250byB0aGUgcm9hZCwgYW5kIGlmIHlvdSBkb24ndCBrZWVwIHlvdXIgZmVldCwgdGhlcmXigJlzIG5vIGtub3dpbmcgd2hlcmUgeW91IG1pZ2h0IGJlIHN3ZXB0IG9mZiB0by4.s0h6KThzkfBBBkLspW1h84VsJZFTsPPqMDA7g1Md7p0"
)

type rfcVector struct {
	clause        string
	alg           jwa.Algorithm
	compact       string
	private       string
	public        string
	deterministic bool
}

func rfcVectors() map[string]rfcVector {
	return map[string]rfcVector{
		"RFC 7515 A.1 HS256": {"RFC 7515 A.1", jwa.HS256, rfc7515A1JWS, rfc7515A1Key, "", true},
		"RFC 7515 A.3 ES256": {"RFC 7515 A.3", jwa.ES256, rfc7515A3JWS, rfc7515A3Key, "", false},
		"RFC 7515 A.4 ES512": {"RFC 7515 A.4", jwa.ES512, rfc7515A4JWS, rfc7515A4Key, "", false},
		"RFC 7520 4.1 RS256": {"RFC 7520 4.1", jwa.RS256, rfc7520Figure13, rfc7520Figure4, rfc7520Figure3, true},
		"RFC 7520 4.2 PS384": {"RFC 7520 4.2", jwa.PS384, rfc7520Figure20, rfc7520Figure4, rfc7520Figure3, false},
		"RFC 7520 4.3 ES512": {"RFC 7520 4.3", jwa.ES512, rfc7520Figure27, rfc7520Figure2, rfc7520Figure1, false},
		"RFC 7520 4.4 HS256": {"RFC 7520 4.4", jwa.HS256, rfc7520Figure34, rfc7520Figure5, "", true},
	}
}

func rfcJwk(t *testing.T, encoded string) map[string]any {
	t.Helper()
	var key map[string]any
	if err := json.Unmarshal([]byte(encoded), &key); err != nil {
		t.Fatal(err)
	}
	return key
}

func rfcSegment(t *testing.T, compact string, index int) []byte {
	t.Helper()
	decoded, err := base64.RawURLEncoding.DecodeString(strings.Split(compact, ".")[index])
	if err != nil {
		t.Fatal(err)
	}
	return decoded
}

func rfcSigner(t *testing.T, v rfcVector) model.Signer {
	t.Helper()
	key := rfcJwk(t, v.private)
	if key["kty"] == "oct" {
		secret, err := base64.RawURLEncoding.DecodeString(key["k"].(string))
		if err != nil {
			t.Fatal(err)
		}
		signer, err := jws.GetSigner(v.alg, &model.Opts{SecretKey: &secret})
		if err != nil {
			t.Fatalf("[%s] the published key must build a signer, got %v", v.clause, err)
		}
		return signer
	}
	private, err := jwk.PrivateFromJwk(key)
	if err != nil {
		t.Fatalf("[%s] the published private key must be read, got %v", v.clause, err)
	}
	signer, err := jws.GetSignerFromPrivateKey(v.alg, private)
	if err != nil {
		t.Fatalf("[%s] the published private key must build a signer, got %v", v.clause, err)
	}
	return signer
}

func rfcPublicKey(t *testing.T, v rfcVector) crypto.PublicKey {
	t.Helper()
	if rfcJwk(t, v.private)["kty"] == "oct" {
		return rfcSigner(t, v).Public()
	}
	var key map[string]any
	if v.public == "" {
		key = rfcJwk(t, v.private)
		delete(key, "d")
	} else {
		key = rfcJwk(t, v.public)
	}
	public, err := jwk.PublicFromJwk(key)
	if err != nil {
		t.Fatalf("[%s] the published public key must be read, got %v", v.clause, err)
	}
	return public
}

func TestVerify_AcceptsThePublishedRFCExamples(t *testing.T) {
	for name, v := range rfcVectors() {
		t.Run(name, func(t *testing.T) {
			public := rfcPublicKey(t, v)
			retriever := func() ([]crypto.PublicKey, error) { return []crypto.PublicKey{public}, nil }
			_, payload, err := jws.Verify(context.Background(), v.compact, retriever, nil)
			if err != nil {
				t.Fatalf("[%s] the published JWS must verify under the published key, got %v", v.clause, err)
			}
			if !bytes.Equal(payload, rfcSegment(t, v.compact, 1)) {
				t.Errorf("[%s] the payload returned must be the published payload, got %q", v.clause, payload)
			}
			segments := strings.Split(v.compact, ".")
			signature := rfcSegment(t, v.compact, 2)
			signature[len(signature)/2] ^= 1
			altered := segments[0] + "." + segments[1] + "." + base64.RawURLEncoding.EncodeToString(signature)
			if _, _, err := jws.Verify(context.Background(), altered, retriever, nil); err == nil {
				t.Errorf("[RFC 7515 5.2 step 8] the published JWS with one signature bit flipped must not verify under %s", v.clause)
			}
		})
	}
}

func TestSign_ReproducesOrVerifiesThePublishedRFCExamples(t *testing.T) {
	for name, v := range rfcVectors() {
		t.Run(name, func(t *testing.T) {
			signingInput := v.compact[:strings.LastIndex(v.compact, ".")]
			signature, err := rfcSigner(t, v).Sign(nil, []byte(signingInput), nil)
			if err != nil {
				t.Fatalf("[%s] the published key must sign the published signing input, got %v", v.clause, err)
			}
			if v.deterministic {
				if want := rfcSegment(t, v.compact, 2); !bytes.Equal(signature, want) {
					t.Errorf("[%s] %s is deterministic, so signing must reproduce the published signature\n got %x\nwant %x", v.clause, v.alg, signature, want)
				}
				return
			}
			validator, err := jws.GetValidator(v.alg, rfcPublicKey(t, v))
			if err != nil {
				t.Fatal(err)
			}
			if valid, err := validator.ValidateSignature([]byte(signingInput), signature); err != nil || !valid {
				t.Errorf("[%s] %s is randomised, so a fresh signature by the published private key must verify under the published public key, got %v and %v", v.clause, v.alg, valid, err)
			}
		})
	}
}
