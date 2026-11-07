// Command cb2cli is the client half of the example service: it makes
// the holder proof a request to the service must carry.
//
// Usage:
//
//	cb2cli prove -session login.json -method GET -url http://127.0.0.1:8080/me
//	cb2cli keygen
//	cb2cli normalize URL
//
// prove reads the JSON the service answered POST /login with and prints
// the two request headers, Authorization and CB2-Proof, in the format
// curl reads with -H @file. Each run makes a new proof with a fresh id.
// keygen prints a new kcb2.local key for CB2_EXAMPLE_KEY; normalize
// prints the target a proof for URL commits to.
package main

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	cb2 "github.com/Crdzbird/cb2/bindings/go"
)

type session struct {
	AccessToken string `json:"access_token"`
	ProofKey    string `json:"proof_key"`
}

func main() {
	if err := run(os.Args[1:], os.Stdout); err != nil {
		fmt.Fprintln(os.Stderr, "cb2cli:", err)
		os.Exit(1)
	}
}

func run(args []string, out io.Writer) error {
	if len(args) == 0 {
		return errors.New("usage: cb2cli prove|keygen|normalize")
	}
	switch args[0] {
	case "prove":
		return prove(args[1:], out)
	case "keygen":
		return keygen(out)
	case "normalize":
		if len(args) != 2 {
			return errors.New("usage: cb2cli normalize URL")
		}
		htu, err := cb2.NormalizeTarget(args[1])
		if err != nil {
			return err
		}
		_, err = fmt.Fprintln(out, htu)
		return err
	}
	return fmt.Errorf("unknown command %q", args[0])
}

func prove(args []string, out io.Writer) error {
	fs := flag.NewFlagSet("prove", flag.ContinueOnError)
	path := fs.String("session", "", "file holding the JSON answer of POST /login")
	method := fs.String("method", "GET", "HTTP method of the request")
	target := fs.String("url", "", "URL of the request")
	lifetime := fs.Duration("lifetime", time.Minute, "proof lifetime")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *path == "" || *target == "" {
		return errors.New("prove needs -session and -url")
	}
	raw, err := os.ReadFile(*path)
	if err != nil {
		return err
	}
	var s session
	if err := json.Unmarshal(raw, &s); err != nil {
		return fmt.Errorf("%s: %w", *path, err)
	}
	proofKey, err := cb2.LocalKeyFromPaserk(s.ProofKey)
	if err != nil {
		return fmt.Errorf("proof_key: %w", err)
	}
	defer proofKey.Close()
	htu, err := cb2.NormalizeTarget(*target)
	if err != nil {
		return fmt.Errorf("url: %w", err)
	}
	proof, err := cb2.HolderProveLocal(proofKey, strings.ToUpper(*method), htu, nil,
		s.AccessToken, randomID(), time.Now().Unix(), int64(lifetime.Seconds()))
	if err != nil {
		return err
	}
	_, err = fmt.Fprintf(out, "Authorization: CB2 %s\nCB2-Proof: %s\n", s.AccessToken, proof)
	return err
}

func keygen(out io.Writer) error {
	key, err := cb2.GenerateLocalKey()
	if err != nil {
		return err
	}
	defer key.Close()
	text, err := key.ToPaserk()
	if err != nil {
		return err
	}
	_, err = fmt.Fprintln(out, text)
	return err
}

func randomID() string {
	b := make([]byte, 16)
	_, _ = rand.Read(b)
	return base64.RawURLEncoding.EncodeToString(b)
}
