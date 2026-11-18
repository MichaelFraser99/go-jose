package jwe

import (
	"bytes"
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/elliptic"
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

func randomKey(t *testing.T, size int) []byte {
	key := make([]byte, size)
	if _, err := rand.Read(key); err != nil {
		t.Fatal(err)
	}
	return key
}

func TestFormat_ADecrypterOrSharedKeyEncrypterNeverPrintsItsKey(t *testing.T) {
	type holder struct {
		name    string
		names   string
		value   any
		key     []byte
		exposed []string
	}
	var holders []holder
	add := func(name, names string, value any, err error, key []byte, exposed ...string) {
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		holders = append(holders, holder{name, names, value, key, exposed})
	}
	fieldsExposed := []string{"fmt bad verb", "unexported field", "encoding/"}
	for alg, size := range map[jwa.Algorithm]int{jwa.A128KW: 16, jwa.A192KW: 24, jwa.A256KW: 32, jwa.A128GCMKW: 16, jwa.A192GCMKW: 24, jwa.A256GCMKW: 32} {
		key := randomKey(t, size)
		encrypter, err := GetEncrypter(alg, key)
		add(alg.String()+" encrypter", alg.String(), encrypter, err, key)
		decrypter, err := GetDecrypter(alg, key)
		add(alg.String()+" decrypter", alg.String(), decrypter, err, key)
		add(alg.String()+" decrypter.Public()", "secret key", decrypter.Public(), nil, key)
	}
	direct := DirectKey{Key: randomKey(t, 32), Enc: jwa.A256GCM}
	directEncrypter, err := GetEncrypter(jwa.Dir, direct)
	add("dir encrypter", "dir", directEncrypter, err, direct.Key)
	directDecrypter, err := GetDecrypter(jwa.Dir, direct)
	add("dir decrypter", "dir", directDecrypter, err, direct.Key)
	add("dir decrypter.Public()", "DirectKey", directDecrypter.Public(), nil, direct.Key, fieldsExposed...)
	add("DirectKey", "DirectKey", direct, nil, direct.Key, fieldsExposed...)
	add("*DirectKey", "DirectKey", &direct, nil, direct.Key, fieldsExposed...)
	password := PasswordKey{Password: randomKey(t, 24), Count: 1000}
	for _, alg := range []jwa.Algorithm{jwa.PBES2HS256A128KW, jwa.PBES2HS384A192KW, jwa.PBES2HS512A256KW} {
		encrypter, err := GetEncrypter(alg, password)
		add(alg.String()+" encrypter", alg.String(), encrypter, err, password.Password)
		decrypter, err := GetDecrypter(alg, password)
		add(alg.String()+" decrypter", alg.String(), decrypter, err, password.Password)
		add(alg.String()+" decrypter.Public()", "PasswordKey", decrypter.Public(), nil, password.Password, fieldsExposed...)
	}
	add("PasswordKey", "PasswordKey", password, nil, password.Password, fieldsExposed...)
	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	for _, alg := range []jwa.Algorithm{jwa.RSAOAEP, jwa.RSAOAEP256, jwa.RSAOAEP384, jwa.RSAOAEP512} {
		decrypter, err := GetDecrypter(alg, rsaKey)
		add(alg.String()+" decrypter", alg.String(), decrypter, err, rsaKey.D.Bytes())
	}
	ecKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	d, err := ecKey.Bytes()
	if err != nil {
		t.Fatal(err)
	}
	xKey, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	for _, alg := range []jwa.Algorithm{jwa.ECDHES, jwa.ECDHESA128KW, jwa.ECDHESA192KW, jwa.ECDHESA256KW} {
		decrypter, err := GetDecrypter(alg, ecKey)
		add(alg.String()+" decrypter on P-256", alg.String(), decrypter, err, d[1:])
		decrypter, err = GetDecrypter(alg, xKey)
		add(alg.String()+" decrypter on X25519", alg.String(), decrypter, err, xKey.Bytes())
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
