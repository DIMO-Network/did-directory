package main

import (
	"bytes"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"time"

	dimocrypto "github.com/DIMO-Network/did-directory/internal/crypto"
)

// runSignin drives dauth's DID sign-in for a DID whose key is in the local
// keystore: it asks for a challenge, signs it with the DID's #signing key (the
// same r||s signature the directory checks on operations) and prints the
// identity token, which is what the org host and dauth's /exchange take.
func runSignin(args []string) {
	fs := flag.NewFlagSet("signin", flag.ExitOnError)
	dauth := fs.String("dauth", defaultDauth(), "dauth base URL")
	didFlag := fs.String("did", "", "DID to sign in as (its key must be in the keystore)")
	key := fs.String("key", "signing", "verification method fragment to sign with")
	audience := fs.String("audience", "", "audience to request for the token (comma-separated)")
	fs.Parse(args)

	if *didFlag == "" {
		fmt.Fprintln(os.Stderr, "Error: --did is required")
		os.Exit(1)
	}
	priv, err := LoadKey(*didFlag)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}

	base := strings.TrimRight(*dauth, "/")
	challengeReq := map[string]any{"did": *didFlag}
	if *audience != "" {
		challengeReq["audience"] = strings.Split(*audience, ",")
	}
	var challenge struct {
		Challenge string `json:"challenge"`
		Nonce     string `json:"nonce"`
	}
	if err := postJSON(base+"/signin/challenge", challengeReq, &challenge); err != nil {
		fmt.Fprintf(os.Stderr, "Error: challenge: %v\n", err)
		os.Exit(1)
	}

	sig, err := dimocrypto.SignOperation(priv, []byte(challenge.Challenge))
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: sign challenge: %v\n", err)
		os.Exit(1)
	}

	var token struct {
		Token     string `json:"token"`
		ExpiresIn int    `json:"expires_in"`
	}
	if err := postJSON(base+"/signin/token", map[string]any{"nonce": challenge.Nonce, "signature": sig, "key": *key}, &token); err != nil {
		fmt.Fprintf(os.Stderr, "Error: token: %v\n", err)
		os.Exit(1)
	}
	if isVerbose() {
		fmt.Fprintf(os.Stderr, "Signed in as %s (expires in %ds)\n", *didFlag, token.ExpiresIn)
	}
	fmt.Println(token.Token)
}

func defaultDauth() string {
	if v := os.Getenv("DAUTH_URL"); v != "" {
		return v
	}
	return "http://localhost:8080"
}

// postJSON posts body as JSON and decodes a 2xx response into out; any other
// status is an error carrying the response body.
func postJSON(url string, body, out any) error {
	payload, err := json.Marshal(body)
	if err != nil {
		return err
	}
	client := &http.Client{Timeout: 30 * time.Second}
	resp, err := client.Post(url, "application/json", bytes.NewReader(payload))
	if err != nil {
		return err
	}
	defer func() { _ = resp.Body.Close() }()
	data, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return err
	}
	if resp.StatusCode/100 != 2 {
		return fmt.Errorf("%s: %s", resp.Status, strings.TrimSpace(string(data)))
	}
	return json.Unmarshal(data, out)
}
