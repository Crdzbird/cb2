package cb2_test

import (
	"errors"
	"fmt"
	"log"
	"time"

	cb2 "github.com/Crdzbird/cb2/bindings/go"
)

func Example() {
	key, err := cb2.GenerateLocalKey()
	if err != nil {
		log.Fatal(err)
	}
	defer key.Close()

	token, err := cb2.TokenSeal(key, map[string]any{
		"iss": "https://issuer.example",
		"aud": "api",
		"sub": "user-1",
		"exp": time.Now().Add(time.Hour).UTC().Format(time.RFC3339),
	}, nil)
	if err != nil {
		log.Fatal(err)
	}

	claims, err := cb2.TokenOpen(key, token, cb2.Rules{
		Issuer:   cb2.String("https://issuer.example"),
		Audience: cb2.String("api"),
	}, nil)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println(claims["sub"])
	// Output: user-1
}

func ExampleTokenOpen_expired() {
	key, err := cb2.GenerateLocalKey()
	if err != nil {
		log.Fatal(err)
	}
	defer key.Close()

	token, err := cb2.TokenSeal(key, map[string]any{
		"iss": "https://issuer.example",
		"aud": "api",
		"exp": "2024-01-01T00:00:00Z",
	}, nil)
	if err != nil {
		log.Fatal(err)
	}

	_, err = cb2.TokenOpen(key, token, cb2.Rules{
		Issuer:   cb2.String("https://issuer.example"),
		Audience: cb2.String("api"),
	}, nil)
	fmt.Println(errors.Is(err, cb2.ErrExpired))
	// Output: true
}

func ExampleTokenOpen_replay() {
	key, err := cb2.GenerateLocalKey()
	if err != nil {
		log.Fatal(err)
	}
	defer key.Close()

	token, err := cb2.TokenSeal(key, map[string]any{
		"iss": "https://issuer.example",
		"aud": "api",
		"jti": "id-1",
		"exp": time.Now().Add(time.Hour).UTC().Format(time.RFC3339),
	}, nil)
	if err != nil {
		log.Fatal(err)
	}

	seen := map[string]bool{}
	rules := cb2.Rules{
		Issuer:   cb2.String("https://issuer.example"),
		Audience: cb2.String("api"),
		Replay: func(jti string) bool {
			if seen[jti] {
				return false
			}
			seen[jti] = true
			return true
		},
	}
	for range 2 {
		_, err := cb2.TokenOpen(key, token, rules, nil)
		fmt.Println(err)
	}
	// Output:
	// <nil>
	// cb2: replayed
}

func ExampleError() {
	_, err := cb2.LocalKeyFromPaserk("kcb2.local.not-a-key")

	var e *cb2.Error
	if errors.As(err, &e) {
		fmt.Println(e.Code, e.Name)
	}
	// Output: 3 argument
}

func ExampleHolderProveLocal() {
	tokenKey, err := cb2.GenerateLocalKey()
	if err != nil {
		log.Fatal(err)
	}
	defer tokenKey.Close()

	proofKey, err := cb2.GenerateLocalKey()
	if err != nil {
		log.Fatal(err)
	}
	defer proofKey.Close()
	cnf, err := proofKey.ToPaserk()
	if err != nil {
		log.Fatal(err)
	}

	access, err := cb2.TokenSeal(tokenKey, map[string]any{
		"iss": "https://issuer.example",
		"aud": "api",
		"exp": time.Now().Add(time.Hour).UTC().Format(time.RFC3339),
		"cnf": cnf,
	}, nil)
	if err != nil {
		log.Fatal(err)
	}

	proof, err := cb2.HolderProveLocal(proofKey, "GET", "https://api.example/v1/me", nil,
		access, "proof-1", time.Now().Unix(), 60)
	if err != nil {
		log.Fatal(err)
	}

	used := map[string]bool{}
	rules := cb2.Rules{
		Issuer:   cb2.String("https://issuer.example"),
		Audience: cb2.String("api"),
		Proof:    proof,
		Request:  &cb2.HolderRequest{HTM: "GET", HTU: "https://api.example/v1/me"},
		ProofReplay: func(jti string) bool {
			if used[jti] {
				return false
			}
			used[jti] = true
			return true
		},
	}
	_, err = cb2.TokenOpen(tokenKey, access, rules, nil)
	fmt.Println(err)
	_, err = cb2.TokenOpen(tokenKey, access, rules, nil)
	fmt.Println(errors.Is(err, cb2.ErrProofReplayed))

	rules.Proof = ""
	_, err = cb2.TokenOpen(tokenKey, access, rules, nil)
	fmt.Println(errors.Is(err, cb2.ErrMissingProof))
	// Output:
	// <nil>
	// true
	// true
}

func ExampleNormalizeTarget() {
	htu, err := cb2.NormalizeTarget("HTTPS://API.Example:443/v1/me?page=2#top")
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println(htu)
	// Output: https://api.example/v1/me
}

func ExampleLocalKey_Close() {
	key, err := cb2.GenerateLocalKey()
	if err != nil {
		log.Fatal(err)
	}
	key.Close()

	_, err = cb2.LocalSeal(key, []byte("hello"), nil, nil)
	fmt.Println(errors.Is(err, cb2.ErrClosed), errors.Is(err, cb2.ErrArgument))
	// Output: true true
}

func ExampleLocalKey_SetKeyID() {
	key, err := cb2.GenerateLocalKey()
	if err != nil {
		log.Fatal(err)
	}
	defer key.Close()
	if err := key.SetKeyID("2026-11"); err != nil {
		log.Fatal(err)
	}

	token, err := cb2.TokenSeal(key, map[string]any{
		"iss": "https://issuer.example",
		"aud": "api",
		"exp": time.Now().Add(time.Hour).UTC().Format(time.RFC3339),
	}, nil)
	if err != nil {
		log.Fatal(err)
	}
	id, ok, err := cb2.PeekKeyID(token)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println(id, ok)
	// Output: 2026-11 true
}

func ExampleLocalSeal() {
	key, err := cb2.GenerateLocalKey()
	if err != nil {
		log.Fatal(err)
	}
	defer key.Close()

	footer := []byte(`{"purpose":"demo"}`)
	token, err := cb2.LocalSeal(key, []byte("any bytes"), footer, nil)
	if err != nil {
		log.Fatal(err)
	}
	msg, err := cb2.LocalOpen(key, token, footer, nil, 0)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println(string(msg))
	// Output: any bytes
}

func ExampleWrap() {
	wrapping, err := cb2.GenerateLocalKey()
	if err != nil {
		log.Fatal(err)
	}
	defer wrapping.Close()
	key, err := cb2.GenerateLocalKey()
	if err != nil {
		log.Fatal(err)
	}
	defer key.Close()

	wrapped, err := cb2.Wrap(wrapping, key)
	if err != nil {
		log.Fatal(err)
	}
	back, err := cb2.Unwrap(wrapped, wrapping)
	if err != nil {
		log.Fatal(err)
	}
	defer back.Close()

	a, _ := key.PaserkID()
	b, _ := back.PaserkID()
	fmt.Println(a == b)
	// Output: true
}

func ExampleTokenSign() {
	secret, err := cb2.GenerateSecretKey()
	if errors.Is(err, cb2.ErrUnavailable) {
		return
	}
	if err != nil {
		log.Fatal(err)
	}
	defer secret.Close()
	public, err := secret.PublicKey()
	if err != nil {
		log.Fatal(err)
	}
	defer public.Close()

	token, err := cb2.TokenSign(secret, map[string]any{
		"iss": "https://issuer.example",
		"aud": "api",
		"sub": "user-1",
		"exp": time.Now().Add(time.Hour).UTC().Format(time.RFC3339),
	}, nil)
	if err != nil {
		log.Fatal(err)
	}
	claims, err := cb2.TokenVerify(public, token, cb2.Rules{
		Issuer:   cb2.String("https://issuer.example"),
		Audience: cb2.String("api"),
	}, nil)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println(claims["sub"])
}
