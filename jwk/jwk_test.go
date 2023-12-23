package jwk

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"log"
	"runtime"
	"testing"
)

var ecdsaPrivateKey = `-----BEGIN EC PRIVATE KEY-----
MEECAQAwEwYHKoZIzj0CAQYIKoZIzj0DAQcEJzAlAgEBBCAt0NU0VJof4aloFLzr
lqTbKSKcNe7lLDfJiqChvsD1fQ==
-----END EC PRIVATE KEY-----`

var rsaPrivateKey = `-----BEGIN PRIVATE KEY-----
MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQCz7uGCQPeFzf9w
Fwb1QM2R68XIkytCXxXN6TvvSvosUNLYRWCQRnlB5IO6I4aeOcXbYSwfJN0h6L6e
llE7LKigHo0lHkNfQFlr/SOQ67DXmEfLWyo5LIfTaFAs2JGHyid8fLhOaSKRpsB/
UK3HEawtpEtxJRUvmdE13cHghGA0okYGR79OP1v/G0Oj62gb7E/7UcDGvDDn7x5w
aJVLLR5IDyJ08nC2nnuPPsPQq534K2C6s6+lopuy54BxcXn2nnyCq0j0HgygTVWU
nPo//gjT/H/GsKt3ClEYZQnXulpmtP/HLCx3kXhnjhduED4Biu14S5b7m0EaWtoG
94wIQsAfAgMBAAECggEANp/25kxC2ORJAAZ9nkcmIX6qdNH4+BVV0UVVZLgmav2+
hNnLDwHWHiL5urC+VZrEbm15r5rJZ1n5RLvtvUE5kCK2RuaBHZGzlA0tlvl2nn0k
jqAGmYTjV1L7xCGbTNYaVrimW2efjwhIuF4N47mBw/l0zcysOd9AnFHOYhLOAiwe
5oJGQdjNxuzYCLdSlt11gWcHhlIfnbR0Y3ubZFiAOtoQBknwIPV4MzaDpj9/reqx
DZnV6O8+guiJF7bd0HAMjkrK74BpYLkMtrdtNcJ0jMuquLrs1yCI4g8UOREBivhc
iUu2tdZNvy4H+riE7lriKeNUPxpacBWShHAmF6yCQQKBgQDl7ZalAGcrJYNapYGJ
jU02whc9pY+2ntOu9c/dJqi1YQsQ86Pe/GfKW+Ua+EI1c+lj3O7IzY0lBSXNGPzy
yDvcfWdk99oEyNa8KL7RjOBXvtUSJv5ffO8qf1IpalEbLkXn30WAzvnqfzytobdG
WdJiaO0ytjkCfl+kjHt9rSM+rQKBgQDIVgau/hTtbk0W7y/6KsYOBKxYwR0quATd
ntRvrUSiTBGea0DmMzGHz9QQcJzMtLWzQ4jyv7mMrd8xBrmhITyuPznj2ltiuAlr
ACTtjFBOYJpPaD6g+aAKQeNXujyKGy0D6kPuCCeDv9DbooylN++BA5A8gbjLFaaQ
CR5aOLWPewKBgEAmispck2xRWhW3aa3kE6/8dRmJENDF/Y+qG6W7PITmn3zKTWVQ
jPDDtOdSbr6VKX/oS2MRHpk+l25i02g1f6YkAu4DzPtawbbbs2mp4Yn5v18CLCSe
Keh0f4r4k8p+nZh1DeJDXS0U9OwI26awNueoGM32U2+jrLGvVGEbJmM9AoGATW+T
HcjwZeYgviCuNtCZxYlg5N2gXIbMuq1OB+y9fs5QcR+b8l8PYiOfIMumkCm5ohUU
tmANZKdAgj7LOdETF3cw9TXN5Ral7Uoc/AUkdWc5vj/ZFXfnuI9HRP2jsO5YNA81
OqjEPVTDcmIeYy5/0SqDch/iQf2YaExeAxmwdEkCgYEAjzbACrO+ahr7nRLxEsSF
g4cPlB5jy95FtR3eGDifdisneqNLU+nMKfHfYKgvflRqB4B5b3Rvo+jen8GlIrXB
oYPPUHrEtYucXcOIoTfMAQnLgx+VNbff78g9E1EZbCAEMcKlucKMLkHS/DlUI9P6
/o4YTEqI6kycFn2alb/2Mhw=
-----END PRIVATE KEY-----`

func TestPublicJwk(t *testing.T) {
	tests := []struct {
		name     string
		key      func(t *testing.T) crypto.PublicKey
		validate func(t *testing.T, input map[string]any)
	}{
		{
			name: "valid new P-256 ecdsa public key",
			key: func(t *testing.T) crypto.PublicKey {
				key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
				if err != nil {
					t.Fatalf("error generating key: %s", err.Error())
				}
				return key.Public()
			},
			validate: func(t *testing.T, input map[string]any) {
				CheckPresenceAndValue(t, input, "crv", "P-256")
				CheckPresenceAndValue(t, input, "kty", "EC")
			},
		},
		{
			name: "valid new P-384 ecdsa public key",
			key: func(t *testing.T) crypto.PublicKey {
				key, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
				if err != nil {
					t.Fatalf("error generating key: %s", err.Error())
				}
				return key.Public()
			},
			validate: func(t *testing.T, input map[string]any) {
				CheckPresenceAndValue(t, input, "crv", "P-384")
				CheckPresenceAndValue(t, input, "kty", "EC")
			},
		},
		{
			name: "valid new P-521 ecdsa public key",
			key: func(t *testing.T) crypto.PublicKey {
				key, err := ecdsa.GenerateKey(elliptic.P521(), rand.Reader)
				if err != nil {
					t.Fatalf("error generating key: %s", err.Error())
				}
				return key.Public()
			},
			validate: func(t *testing.T, input map[string]any) {
				CheckPresenceAndValue(t, input, "crv", "P-521")
				CheckPresenceAndValue(t, input, "kty", "EC")

				for _, val := range []string{CheckPresence(t, input, "x").(string), CheckPresence(t, input, "y").(string)} {
					b, err := base64.RawURLEncoding.DecodeString(val)
					if err != nil {
						t.Fatalf("error decoding base64url value: %s", err.Error())
					}
					if len(b) != 66 {
						t.Errorf("incorrect byte length returned: %d", len(b))
					}
				}

			},
		},
		{
			name: "valid existing P-256 ecdsa public key",
			key: func(t *testing.T) crypto.PublicKey {
				block, _ := pem.Decode([]byte(ecdsaPrivateKey))
				if block == nil {
					log.Fatal("not able to decode the PEM block")
				}

				pk, err := x509.ParsePKCS8PrivateKey(block.Bytes)
				if err != nil {
					log.Fatal("not able to parse to ECDSA private key: ", err)
				}
				return pk.(*ecdsa.PrivateKey).Public()
			},
			validate: func(t *testing.T, input map[string]any) {
				CheckPresenceAndValue(t, input, "crv", "P-256")
				CheckPresenceAndValue(t, input, "kty", "EC")
				CheckPresenceAndValue(t, input, "x", "GebV5rfS6sf2fpXynjjgK3m0ajarKvAgS2HzJ-pRm2Q")
				CheckPresenceAndValue(t, input, "y", "a-NG2HsWygs2uIusEc_XsnQHska40CunYw0XJ0byxQQ")
			},
		},
		{
			name: "valid new rsa public key",
			key: func(t *testing.T) crypto.PublicKey {
				key, err := rsa.GenerateKey(rand.Reader, 2048)
				if err != nil {
					t.Fatalf("error generating key: %s", err.Error())
				}
				return key.Public()
			},
			validate: func(t *testing.T, input map[string]any) {
				CheckPresenceAndValue(t, input, "kty", "RSA")
				CheckPresence(t, input, "n")
				CheckPresenceAndValue(t, input, "e", "AQAB")
			},
		},
		{
			name: "valid existing rsa public key",
			key: func(t *testing.T) crypto.PublicKey {
				block, _ := pem.Decode([]byte(rsaPrivateKey))
				if block == nil {
					log.Fatal("not able to decode the PEM block")
				}

				pk, err := x509.ParsePKCS8PrivateKey(block.Bytes)
				if err != nil {
					log.Fatal("not able to parse to RSA private key: ", err)
				}
				return pk.(*rsa.PrivateKey).Public()
			},
			validate: func(t *testing.T, input map[string]any) {
				CheckPresenceAndValue(t, input, "kty", "RSA")
				CheckPresenceAndValue(t, input, "n", "s-7hgkD3hc3_cBcG9UDNkevFyJMrQl8Vzek770r6LFDS2EVgkEZ5QeSDuiOGnjnF22EsHyTdIei-npZROyyooB6NJR5DX0BZa_0jkOuw15hHy1sqOSyH02hQLNiRh8onfHy4TmkikabAf1CtxxGsLaRLcSUVL5nRNd3B4IRgNKJGBke_Tj9b_xtDo-toG-xP-1HAxrww5-8ecGiVSy0eSA8idPJwtp57jz7D0Kud-CtgurOvpaKbsueAcXF59p58gqtI9B4MoE1VlJz6P_4I0_x_xrCrdwpRGGUJ17paZrT_xywsd5F4Z44XbhA-AYrteEuW-5tBGlraBveMCELAHw")
				CheckPresenceAndValue(t, input, "e", "AQAB")
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			pk := tt.key(t)
			output, err := PublicJwk(pk)
			if err != nil {
				t.Fatalf("no error should be thrown: %s", err.Error())
			}
			tt.validate(t, *output)
		})
	}
}

func TestPrivateJwk(t *testing.T) {
	tests := []struct {
		name     string
		key      func(t *testing.T) crypto.PrivateKey
		validate func(t *testing.T, input map[string]any)
	}{
		{
			name: "valid new P-256 ecdsa private key",
			key: func(t *testing.T) crypto.PrivateKey {
				key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
				if err != nil {
					t.Fatalf("error generating key: %s", err.Error())
				}
				return key
			},
			validate: func(t *testing.T, input map[string]any) {
				CheckPresenceAndValue(t, input, "crv", "P-256")
				CheckPresenceAndValue(t, input, "kty", "EC")
			},
		},
		{
			name: "valid new P-384 ecdsa private key",
			key: func(t *testing.T) crypto.PrivateKey {
				key, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
				if err != nil {
					t.Fatalf("error generating key: %s", err.Error())
				}
				return key
			},
			validate: func(t *testing.T, input map[string]any) {
				CheckPresenceAndValue(t, input, "crv", "P-384")
				CheckPresenceAndValue(t, input, "kty", "EC")
			},
		},
		{
			name: "valid new P-521 ecdsa private key",
			key: func(t *testing.T) crypto.PrivateKey {
				key, err := ecdsa.GenerateKey(elliptic.P521(), rand.Reader)
				if err != nil {
					t.Fatalf("error generating key: %s", err.Error())
				}
				return key
			},
			validate: func(t *testing.T, input map[string]any) {
				CheckPresenceAndValue(t, input, "crv", "P-521")
				CheckPresenceAndValue(t, input, "kty", "EC")

				for _, val := range []string{CheckPresence(t, input, "x").(string), CheckPresence(t, input, "y").(string)} {
					b, err := base64.RawURLEncoding.DecodeString(val)
					if err != nil {
						t.Fatalf("error decoding base64url value: %s", err.Error())
					}
					if len(b) != 66 {
						t.Errorf("incorrect byte length returned: %d", len(b))
					}
				}

			},
		},
		{
			name: "valid existing P-256 ecdsa private key",
			key: func(t *testing.T) crypto.PrivateKey {
				block, _ := pem.Decode([]byte(ecdsaPrivateKey))
				if block == nil {
					log.Fatal("not able to decode the PEM block")
				}

				pk, err := x509.ParsePKCS8PrivateKey(block.Bytes)
				if err != nil {
					log.Fatal("not able to parse to ECDSA private key: ", err)
				}
				return pk.(*ecdsa.PrivateKey)
			},
			validate: func(t *testing.T, input map[string]any) {
				CheckPresenceAndValue(t, input, "crv", "P-256")
				CheckPresenceAndValue(t, input, "kty", "EC")
				CheckPresenceAndValue(t, input, "d", "LdDVNFSaH-GpaBS865ak2ykinDXu5Sw3yYqgob7A9X0")
				CheckPresenceAndValue(t, input, "x", "GebV5rfS6sf2fpXynjjgK3m0ajarKvAgS2HzJ-pRm2Q")
				CheckPresenceAndValue(t, input, "y", "a-NG2HsWygs2uIusEc_XsnQHska40CunYw0XJ0byxQQ")
			},
		},
		{
			name: "valid new rsa private key",
			key: func(t *testing.T) crypto.PrivateKey {
				key, err := rsa.GenerateKey(rand.Reader, 2048)
				if err != nil {
					t.Fatalf("error generating key: %s", err.Error())
				}
				return key
			},
			validate: func(t *testing.T, input map[string]any) {
				CheckPresenceAndValue(t, input, "kty", "RSA")
				CheckPresence(t, input, "n")
				CheckPresenceAndValue(t, input, "e", "AQAB")
			},
		},
		{
			name: "valid existing rsa private key",
			key: func(t *testing.T) crypto.PrivateKey {
				block, _ := pem.Decode([]byte(rsaPrivateKey))
				if block == nil {
					log.Fatal("not able to decode the PEM block")
				}

				pk, err := x509.ParsePKCS8PrivateKey(block.Bytes)
				if err != nil {
					log.Fatal("not able to parse to RSA private key: ", err)
				}
				return pk.(*rsa.PrivateKey)
			},
			validate: func(t *testing.T, input map[string]any) {
				CheckPresenceAndValue(t, input, "kty", "RSA")
				CheckPresenceAndValue(t, input, "p", "5e2WpQBnKyWDWqWBiY1NNsIXPaWPtp7TrvXP3SaotWELEPOj3vxnylvlGvhCNXPpY9zuyM2NJQUlzRj88sg73H1nZPfaBMjWvCi-0YzgV77VEib-X3zvKn9SKWpRGy5F599FgM756n88raG3RlnSYmjtMrY5An5fpIx7fa0jPq0")
				CheckPresenceAndValue(t, input, "n", "s-7hgkD3hc3_cBcG9UDNkevFyJMrQl8Vzek770r6LFDS2EVgkEZ5QeSDuiOGnjnF22EsHyTdIei-npZROyyooB6NJR5DX0BZa_0jkOuw15hHy1sqOSyH02hQLNiRh8onfHy4TmkikabAf1CtxxGsLaRLcSUVL5nRNd3B4IRgNKJGBke_Tj9b_xtDo-toG-xP-1HAxrww5-8ecGiVSy0eSA8idPJwtp57jz7D0Kud-CtgurOvpaKbsueAcXF59p58gqtI9B4MoE1VlJz6P_4I0_x_xrCrdwpRGGUJ17paZrT_xywsd5F4Z44XbhA-AYrteEuW-5tBGlraBveMCELAHw")
				CheckPresenceAndValue(t, input, "e", "AQAB")
				CheckPresenceAndValue(t, input, "dq", "TW-THcjwZeYgviCuNtCZxYlg5N2gXIbMuq1OB-y9fs5QcR-b8l8PYiOfIMumkCm5ohUUtmANZKdAgj7LOdETF3cw9TXN5Ral7Uoc_AUkdWc5vj_ZFXfnuI9HRP2jsO5YNA81OqjEPVTDcmIeYy5_0SqDch_iQf2YaExeAxmwdEk")
				CheckPresenceAndValue(t, input, "dp", "QCaKylyTbFFaFbdpreQTr_x1GYkQ0MX9j6obpbs8hOaffMpNZVCM8MO051JuvpUpf-hLYxEemT6XbmLTaDV_piQC7gPM-1rBttuzaanhifm_XwIsJJ4p6HR_iviTyn6dmHUN4kNdLRT07AjbprA256gYzfZTb6Ossa9UYRsmYz0")
				CheckPresenceAndValue(t, input, "qi", "jzbACrO-ahr7nRLxEsSFg4cPlB5jy95FtR3eGDifdisneqNLU-nMKfHfYKgvflRqB4B5b3Rvo-jen8GlIrXBoYPPUHrEtYucXcOIoTfMAQnLgx-VNbff78g9E1EZbCAEMcKlucKMLkHS_DlUI9P6_o4YTEqI6kycFn2alb_2Mhw")
				CheckPresenceAndValue(t, input, "d", "Np_25kxC2ORJAAZ9nkcmIX6qdNH4-BVV0UVVZLgmav2-hNnLDwHWHiL5urC-VZrEbm15r5rJZ1n5RLvtvUE5kCK2RuaBHZGzlA0tlvl2nn0kjqAGmYTjV1L7xCGbTNYaVrimW2efjwhIuF4N47mBw_l0zcysOd9AnFHOYhLOAiwe5oJGQdjNxuzYCLdSlt11gWcHhlIfnbR0Y3ubZFiAOtoQBknwIPV4MzaDpj9_reqxDZnV6O8-guiJF7bd0HAMjkrK74BpYLkMtrdtNcJ0jMuquLrs1yCI4g8UOREBivhciUu2tdZNvy4H-riE7lriKeNUPxpacBWShHAmF6yCQQ")
				CheckPresenceAndValue(t, input, "q", "yFYGrv4U7W5NFu8v-irGDgSsWMEdKrgE3Z7Ub61EokwRnmtA5jMxh8_UEHCczLS1s0OI8r-5jK3fMQa5oSE8rj8549pbYrgJawAk7YxQTmCaT2g-oPmgCkHjV7o8ihstA-pD7ggng7_Q26KMpTfvgQOQPIG4yxWmkAkeWji1j3s")
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			pk := tt.key(t)
			output, err := PrivateJwk(pk)
			if err != nil {
				t.Fatalf("no error should be thrown: %s", err.Error())
			}
			tt.validate(t, *output)
		})
	}
}

func CheckPresenceAndValue(t *testing.T, input map[string]any, key string, value string) any {
	v, ok := input[key]
	_, file, line, _ := runtime.Caller(1)
	if !ok {
		t.Errorf("no %s specified\nat %s:%d", key, file, line)
	}
	if v != value {
		t.Errorf("incorrect %s specified. Expected: %s, got: %s\nat %s:%d", key, value, v, file, line)
	}
	return v
}

func CheckPresence(t *testing.T, input map[string]any, key string) any {
	v, ok := input[key]
	_, file, line, _ := runtime.Caller(1)
	if !ok {
		t.Errorf("no %s specified\nat %s:%d\nat %s:%d", key, file, line, file, line)
	}
	return v
}
