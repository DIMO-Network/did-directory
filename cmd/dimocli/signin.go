package main

import (
	"bytes"
	"crypto/ecdsa"
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
	var aud []string
	if *audience != "" {
		aud = strings.Split(*audience, ",")
	}
	token, expiresIn, err := signIn(*dauth, *didFlag, priv, *key, aud)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}
	if isVerbose() {
		fmt.Fprintf(os.Stderr, "Signed in as %s (expires in %ds)\n", *didFlag, expiresIn)
	}
	fmt.Println(token)
}

// signIn runs dauth's challenge and token round trip for did with priv, the
// private half of the verification method key names, and returns the identity
// token and its lifetime in seconds.
func signIn(dauth, did string, priv *ecdsa.PrivateKey, key string, audience []string) (string, int, error) {
	base := strings.TrimRight(dauth, "/")
	challengeReq := map[string]any{"did": did}
	if len(audience) > 0 {
		challengeReq["audience"] = audience
	}
	var challenge struct {
		Challenge string `json:"challenge"`
		Nonce     string `json:"nonce"`
	}
	if err := postJSON(base+"/signin/challenge", challengeReq, &challenge); err != nil {
		return "", 0, fmt.Errorf("challenge: %w", err)
	}

	sig, err := dimocrypto.SignOperation(priv, []byte(challenge.Challenge))
	if err != nil {
		return "", 0, fmt.Errorf("sign challenge: %w", err)
	}

	var token struct {
		Token     string `json:"token"`
		ExpiresIn int    `json:"expires_in"`
	}
	if err := postJSON(base+"/signin/token", map[string]any{"nonce": challenge.Nonce, "signature": sig, "key": key}, &token); err != nil {
		return "", 0, fmt.Errorf("token: %w", err)
	}
	return token.Token, token.ExpiresIn, nil
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
	return sendJSON(http.MethodPost, url, nil, body, out)
}

// sendJSON sends body as JSON with the given headers and decodes a 2xx
// response into out; any other status is an *httpError carrying the response
// body.
func sendJSON(method, url string, headers map[string]string, body, out any) error {
	payload, err := json.Marshal(body)
	if err != nil {
		return err
	}
	req, err := http.NewRequest(method, url, bytes.NewReader(payload))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	client := &http.Client{Timeout: 30 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer func() { _ = resp.Body.Close() }()
	data, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return err
	}
	if resp.StatusCode/100 != 2 {
		return &httpError{Status: resp.StatusCode, StatusText: resp.Status, Body: strings.TrimSpace(string(data))}
	}
	if out == nil {
		return nil
	}
	return json.Unmarshal(data, out)
}

// httpError is a non-2xx answer, with the body the service sent, so a refusal
// such as dauth's {"error": "exclusive_hold", ...} reaches the caller intact.
type httpError struct {
	Status     int
	StatusText string
	Body       string
}

func (e *httpError) Error() string {
	return fmt.Sprintf("%s: %s", e.StatusText, e.Body)
}
