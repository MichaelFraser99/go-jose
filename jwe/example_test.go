package jwe_test

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"fmt"
	"strings"

	"github.com/MichaelFraser99/go-jose/jwa"
	"github.com/MichaelFraser99/go-jose/jwe"
	"github.com/MichaelFraser99/go-jose/jws"
	"github.com/MichaelFraser99/go-jose/jwt"
	"github.com/MichaelFraser99/go-jose/model"
)

func ExampleEncrypt() {
	recipient, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		panic(err)
	}
	encrypter, err := jwe.GetEncrypter(jwa.RSAOAEP256, &recipient.PublicKey)
	if err != nil {
		panic(err)
	}
	token, err := jwe.Encrypt(encrypter, jwa.A256GCM, []byte(`{"order":42}`), map[string]any{"kid": "recipient-key-1"})
	if err != nil {
		panic(err)
	}
	fmt.Println(strings.Count(token, "."))
	// Output: 4
}

func ExampleDecrypt() {
	recipient, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		panic(err)
	}
	encrypter, err := jwe.GetEncrypter(jwa.RSAOAEP256, &recipient.PublicKey)
	if err != nil {
		panic(err)
	}
	token, err := jwe.Encrypt(encrypter, jwa.A256GCM, []byte(`{"order":42}`), nil)
	if err != nil {
		panic(err)
	}

	decrypter, err := jwe.GetDecrypter(jwa.RSAOAEP256, recipient)
	if err != nil {
		panic(err)
	}
	opts := &model.JoseOptions{
		AllowedKeyManagementAlgorithms:     []jwa.Algorithm{jwa.RSAOAEP256},
		AllowedContentEncryptionAlgorithms: []jwa.Encryption{jwa.A256GCM},
	}
	head, plaintext, _, err := jwe.Decrypt(context.Background(), token, []model.Decrypter{decrypter}, opts)
	if err != nil {
		panic(err)
	}
	fmt.Println(head["alg"], head["enc"], string(plaintext))
	// Output: RSA-OAEP-256 A256GCM {"order":42}
}

func ExampleDecrypt_identifyTheSender() {
	tenantAKey, tenantBKey := make([]byte, 32), make([]byte, 32)
	if _, err := rand.Read(tenantAKey); err != nil {
		panic(err)
	}
	if _, err := rand.Read(tenantBKey); err != nil {
		panic(err)
	}
	tenantA, err := jwe.GetDecrypter(jwa.A256KW, tenantAKey)
	if err != nil {
		panic(err)
	}
	tenantB, err := jwe.GetDecrypter(jwa.A256KW, tenantBKey)
	if err != nil {
		panic(err)
	}
	tenants := map[model.Decrypter]string{tenantA: "tenant A", tenantB: "tenant B"}

	sentByB, err := jwe.GetEncrypter(jwa.A256KW, tenantBKey)
	if err != nil {
		panic(err)
	}
	token, err := jwe.Encrypt(sentByB, jwa.A128CBCHS256, []byte("payload"), map[string]any{"kid": "tenant A"})
	if err != nil {
		panic(err)
	}

	head, _, used, err := jwe.Decrypt(context.Background(), token, []model.Decrypter{tenantA, tenantB}, nil)
	if err != nil {
		panic(err)
	}
	fmt.Printf("kid says %s, sent by %s\n", head["kid"], tenants[used])
	// Output: kid says tenant A, sent by tenant B
}

func ExampleParseHeader() {
	keys := map[string][]byte{"tenant-a": make([]byte, 16), "tenant-b": make([]byte, 16)}
	encrypter, err := jwe.GetEncrypter(jwa.A128KW, keys["tenant-b"])
	if err != nil {
		panic(err)
	}
	token, err := jwe.Encrypt(encrypter, jwa.A128GCM, []byte("payload"), map[string]any{"kid": "tenant-b"})
	if err != nil {
		panic(err)
	}

	head, err := jwe.ParseHeader(token, nil)
	if err != nil {
		panic(err)
	}
	kid, _ := head["kid"].(string)
	key, known := keys[kid]
	if !known {
		panic("unknown kid")
	}
	decrypter, err := jwe.GetDecrypter(jwa.A128KW, key)
	if err != nil {
		panic(err)
	}
	_, plaintext, _, err := jwe.Decrypt(context.Background(), token, []model.Decrypter{decrypter}, nil)
	if err != nil {
		panic(err)
	}
	fmt.Println(kid, string(plaintext))
	// Output: tenant-b payload
}

func Example_signThenEncrypt() {
	signer, err := jws.GetSigner(jwa.ES256, nil)
	if err != nil {
		panic(err)
	}
	recipient, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		panic(err)
	}
	encrypter, err := jwe.GetEncrypter(jwa.RSAOAEP256, &recipient.PublicKey)
	if err != nil {
		panic(err)
	}
	signed, err := jwt.New(signer, nil, map[string]any{"sub": "alice"}, jwt.Opts{})
	if err != nil {
		panic(err)
	}
	token, err := jwe.Encrypt(encrypter, jwa.A256GCM, []byte(*signed), map[string]any{"cty": "JWT"})
	if err != nil {
		panic(err)
	}

	decrypter, err := jwe.GetDecrypter(jwa.RSAOAEP256, recipient)
	if err != nil {
		panic(err)
	}
	head, plaintext, _, err := jwe.Decrypt(context.Background(), token, []model.Decrypter{decrypter}, nil)
	if err != nil {
		panic(err)
	}
	if cty, _ := head["cty"].(string); !strings.EqualFold(cty, "JWT") {
		panic("not a nested JWT")
	}
	retriever := func() ([]crypto.PublicKey, error) { return []crypto.PublicKey{signer.Public()}, nil }
	_, claims, err := jwt.Validate(context.Background(), string(plaintext), retriever, nil)
	if err != nil {
		panic(err)
	}
	fmt.Println(claims["sub"])
	// Output: alice
}
