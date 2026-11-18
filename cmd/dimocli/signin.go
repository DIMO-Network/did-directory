package main

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/DIMO-Network/did-directory/pkg/signin"
)

// runSignin drives dauth's DID sign-in for a DID whose key is in the local
// keystore: it asks for a challenge, signs it with the DID's #signing key (the
// same r||s signature the directory checks on operations) and prints the
// identity token, which is what the org host and dauth's /exchange take. The
// token is bound to that same key as its DPoP key, so every request that
// presents it carries a proof from the keystore (see `dimocli dpop`).
func runSignin(args []string) {
	fs := flag.NewFlagSet("signin", flag.ExitOnError)
	dauth := fs.String("dauth", defaultDauth(), "dauth base URL")
	didFlag := fs.String("did", "", "DID to sign in as (its key must be in the keystore)")
	key := fs.String("key", "signing", "verification method fragment to sign with")
	audience := fs.String("audience", "", "audience to request for the token (comma-separated)")
	scope := fs.String("scope", "read", `what the token may do, space-separated: "read", "write", "approve"`)
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
	token, expiresIn, err := signIn(*dauth, *didFlag, priv, *key, aud, *scope)
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
// token and its lifetime in seconds (see pkg/signin).
func signIn(dauth, did string, priv *ecdsa.PrivateKey, key string, audience []string, scope string) (string, int, error) {
	t, err := signin.SignIn(context.Background(), signin.Request{
		Dauth: dauth, DID: did, Key: priv, KeyFragment: key, Audience: audience, Scope: scope,
	})
	return t.Token, t.ExpiresIn, err
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
