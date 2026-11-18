package jws_test

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/mldsa"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/gob"
	"encoding/hex"
	"encoding/json"
	"encoding/xml"
	"fmt"
	"html"
	"html/template"
	"log/slog"
	"slices"
	"strings"
	"testing"

	"github.com/MichaelFraser99/go-jose/jwa"
	"github.com/MichaelFraser99/go-jose/jws"
	"github.com/MichaelFraser99/go-jose/model"
)

type printRoute struct {
	name  string
	print func(any) string
}

func printRoutes() []printRoute {
	var routes []printRoute
	for _, verb := range []string{"%v", "%+v", "%#v", "%s", "%q", "%x", "%X", "%d"} {
		routes = append(routes, printRoute{"fmt " + verb, func(v any) string { return fmt.Sprintf(verb, v) }})
	}
	for _, verb := range []string{"%w", "%p"} {
		routes = append(routes, printRoute{"fmt bad verb " + verb, func(v any) string { return fmt.Sprintf(verb, v) }})
	}
	for _, verb := range []string{"%v", "%+v", "%s", "%q", "%x"} {
		routes = append(routes, printRoute{"unexported field " + verb, func(v any) string {
			return fmt.Sprintf(verb, struct{ held any }{v})
		}})
	}
	routes = append(routes,
		printRoute{"html/template", func(v any) string {
			var out bytes.Buffer
			if err := template.Must(template.New("t").Parse(`{{.}}`)).Execute(&out, v); err != nil {
				return err.Error()
			}
			return html.UnescapeString(out.String())
		}},
		printRoute{"slog text", func(v any) string {
			var out bytes.Buffer
			slog.New(slog.NewTextHandler(&out, nil)).Info("m", "key", v)
			return out.String()
		}},
		printRoute{"slog json", func(v any) string {
			var out bytes.Buffer
			slog.New(slog.NewJSONHandler(&out, nil)).Info("m", "key", v)
			return out.String()
		}},
		printRoute{"encoding/json", func(v any) string {
			out, _ := json.Marshal(v)
			return string(out)
		}},
		printRoute{"encoding/gob", func(v any) string {
			var out bytes.Buffer
			_ = gob.NewEncoder(&out).Encode(v)
			return out.String()
		}},
		printRoute{"encoding/xml", func(v any) string {
			out, _ := xml.Marshal(v)
			return string(out)
		}},
	)
	return routes
}

var labelled = map[string]bool{"fmt %v": true, "fmt %+v": true, "fmt %#v": true, "fmt %s": true, "fmt %q": true, "fmt %x": true, "fmt %X": true, "fmt %d": true, "html/template": true, "slog text": true}

func keyIn(printed string, key []byte) string {
	forms := map[string]string{
		"decimal":   strings.Trim(fmt.Sprintf("%v", key), "[]"),
		"hex":       hex.EncodeToString(key),
		"HEX":       strings.ToUpper(hex.EncodeToString(key)),
		"raw":       string(key),
		"base64url": base64.RawURLEncoding.EncodeToString(key),
		"base64":    base64.StdEncoding.EncodeToString(key),
	}
	for name, form := range forms {
		if strings.Contains(printed, form) {
			return name
		}
	}
	return ""
}

func TestFormat_ASignerOrHMACValidatorNeverPrintsItsKey(t *testing.T) {
	secrets := map[jwa.Algorithm][]byte{jwa.HS256: make([]byte, 32), jwa.HS384: make([]byte, 48), jwa.HS512: make([]byte, 64)}
	for _, secret := range secrets {
		if _, err := rand.Read(secret); err != nil {
			t.Fatal(err)
		}
	}
	type holder struct {
		name    string
		names   string
		value   any
		key     []byte
		exposed []string
	}
	var holders []holder
	for alg, secret := range secrets {
		signer, err := jws.GetSigner(alg, &model.Opts{SecretKey: &secret})
		if err != nil {
			t.Fatal(err)
		}
		validator, err := jws.GetValidator(alg, signer.Public())
		if err != nil {
			t.Fatal(err)
		}
		holders = append(holders,
			holder{alg.String() + " signer", alg.String(), signer, secret, nil},
			holder{alg.String() + " validator", alg.String(), validator, secret, nil},
			holder{alg.String() + " signer.Public()", "secret key", signer.Public(), secret, nil},
		)
	}
	_, edKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	edSigner, err := jws.GetSignerFromPrivateKey(jwa.Ed25519, edKey)
	if err != nil {
		t.Fatal(err)
	}
	holders = append(holders, holder{"Ed25519 signer", "Ed25519", edSigner, edKey.Seed(), nil})
	for alg, curve := range map[jwa.Algorithm]elliptic.Curve{jwa.ES256: elliptic.P256(), jwa.ES384: elliptic.P384(), jwa.ES512: elliptic.P521()} {
		key, err := ecdsa.GenerateKey(curve, rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		signer, err := jws.GetSignerFromPrivateKey(alg, key)
		if err != nil {
			t.Fatal(err)
		}
		d, err := key.Bytes()
		if err != nil {
			t.Fatal(err)
		}
		holders = append(holders, holder{alg.String() + " signer", alg.String(), signer, d[1:], nil})
	}
	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	for _, alg := range []jwa.Algorithm{jwa.RS256, jwa.RS384, jwa.RS512, jwa.PS256, jwa.PS384, jwa.PS512} {
		signer, err := jws.GetSignerFromPrivateKey(alg, rsaKey)
		if err != nil {
			t.Fatal(err)
		}
		holders = append(holders, holder{alg.String() + " signer", alg.String(), signer, rsaKey.D.Bytes(), nil})
	}
	for alg, params := range map[jwa.Algorithm]mldsa.Parameters{jwa.MLDSA44: mldsa.MLDSA44(), jwa.MLDSA65: mldsa.MLDSA65(), jwa.MLDSA87: mldsa.MLDSA87()} {
		key, err := mldsa.GenerateKey(params)
		if err != nil {
			t.Fatal(err)
		}
		signer, err := jws.GetSignerFromPrivateKey(alg, key)
		if err != nil {
			t.Fatal(err)
		}
		holders = append(holders, holder{alg.String() + " signer", alg.String(), signer, key.Bytes(), nil})
	}

	for _, h := range holders {
		for _, route := range printRoutes() {
			t.Run(h.name+" "+route.name, func(t *testing.T) {
				printed := route.print(h.value)
				exposed := slices.ContainsFunc(h.exposed, func(prefix string) bool { return strings.HasPrefix(route.name, prefix) })
				if form := keyIn(printed, h.key); form != "" && !exposed {
					t.Errorf("[README Errors] %s of a %s must not show its key, but it shows it in %s form: %s", route.name, h.name, form, printed)
				}
				if labelled[route.name] && !strings.Contains(printed, h.names) {
					t.Errorf("[README Errors] %s of a %s must name %s, got %s", route.name, h.name, h.names, printed)
				}
				if _, logged, _ := strings.Cut(printed, " key="); route.name == "slog text" && !strings.Contains(logged, h.names) {
					t.Errorf("[README Errors] %s of a %s must name %s, got %s", route.name, h.name, h.names, printed)
				}
			})
		}
	}
}
