package main

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/DIMO-Network/did-directory/pkg/client"
	"github.com/DIMO-Network/did-directory/pkg/signin"
)

// runSignin drives dauth's DID sign-in: it asks for a challenge, signs it with
// the DID's #signing key (the same r||s signature the directory checks on
// operations) and prints the identity token, which is what the org host and
// dauth's /exchange take. Every request that presents the token carries a
// proof from its DPoP key (see `dimocli dpop`). For a key in the local
// keystore, a P-256 key is the DPoP key too. For a key in Turnkey (the
// --turnkey flags) or a secp256k1 keystore root, the challenge is signed with
// it and the token is bound to a P-256 key stored as <did>.dpop.json, made on
// the first sign-in; the onboarding credential is refused.
func runSignin(args []string) {
	fs := flag.NewFlagSet("signin", flag.ExitOnError)
	dauth := fs.String("dauth", defaultDauth(), "dauth base URL")
	didFlag := fs.String("did", "", "DID to sign in as (its key is in the keystore, or in Turnkey with the --turnkey flags)")
	key := fs.String("key", "signing", "verification method fragment to sign with")
	audience := fs.String("audience", "", "audience to request for the token (comma-separated)")
	scope := fs.String("scope", "read", `what the token may do, space-separated: "read", "write", "approve"`)
	server := fs.String("server", defaultServer(), "directory server URL, to find the Turnkey account behind the DID's key")
	tk := bindTurnkeyFlags(fs)
	fs.Parse(args)

	if *didFlag == "" {
		fmt.Fprintln(os.Stderr, "Error: --did is required")
		os.Exit(1)
	}
	if err := tk.validate(); err != nil {
		fatal(err)
	}
	var aud []string
	if *audience != "" {
		aud = strings.Split(*audience, ",")
	}
	c := client.New(*server)
	c.SetVerbose(isVerbose())
	token, expiresIn, err := executeSignin(context.Background(), *dauth, *didFlag, *key, aud, *scope, tk, c)
	if err != nil {
		fatal(err)
	}
	if isVerbose() {
		fmt.Fprintf(os.Stderr, "Signed in as %s (expires in %ds)\n", *didFlag, expiresIn)
	}
	fmt.Println(token)
}

// executeSignin signs in as didStr. With Turnkey flags the DID's key is a
// Turnkey account (secp256k1): the challenge is signed through it, and the
// token is bound to the P-256 DPoP key stored as <did>.dpop.json (made on the
// first sign-in). A keystore secp256k1 root (a local org's) goes the same way;
// a keystore P-256 key does both, as before.
func executeSignin(ctx context.Context, dauth, didStr, key string, aud []string, scope string, tk *turnkeyFlags, c *client.Client) (string, int, error) {
	if !tk.enabled() {
		local, err := loadSigner(didStr)
		if err != nil {
			return "", 0, err
		}
		if local.key != nil {
			return signIn(dauth, didStr, local.key, key, aud, scope)
		}
		// A secp256k1 root (a local org's) cannot make ES256 proofs, so the
		// token is bound to a fresh P-256 key, as for a Turnkey root.
		return signInBound(ctx, dauth, didStr, key, aud, scope, local.Sign)
	}
	if err := tk.refuseOnboarding(errOnboardingSignin); err != nil {
		return "", 0, err
	}
	_, current, err := getLatestCIDAndOp(ctx, c, didStr)
	if err != nil {
		return "", 0, fmt.Errorf("getting latest state: %w", err)
	}
	vm, ok := current.VerificationMethods[key]
	if !ok {
		return "", 0, fmt.Errorf("%s has no #%s verification method", didStr, key)
	}
	signer, err := tk.existingSigner(ctx, vm)
	if err != nil {
		return "", 0, err
	}
	return signInBound(ctx, dauth, didStr, key, aud, scope, signer.Sign)
}

// signInBound signs in as didStr with sign signing the challenge, and binds
// the token to the P-256 DPoP key stored as <did>.dpop.json, making and
// storing one on the first sign-in. Every token is bound to the same key, so
// dimocli dpop proves any of them, as it does for a keystore P-256 root.
func signInBound(ctx context.Context, dauth, didStr, key string, aud []string, scope string, sign func(context.Context, []byte) (string, error)) (string, int, error) {
	dpopKey, err := LoadDPoPKey(didStr)
	fresh := errors.Is(err, os.ErrNotExist)
	switch {
	case fresh:
		if dpopKey, err = ecdsa.GenerateKey(elliptic.P256(), rand.Reader); err != nil {
			return "", 0, err
		}
	case err != nil:
		return "", 0, fmt.Errorf("DPoP key: %w", err)
	}
	t, err := signin.SignIn(ctx, signin.Request{
		Dauth: dauth, DID: didStr, Signer: sign, DPoPKey: dpopKey, KeyFragment: key, Audience: aud, Scope: scope,
	})
	if err != nil {
		return "", 0, err
	}
	if fresh {
		if err := SaveDPoPKey(didStr, dpopKey); err != nil {
			return "", 0, fmt.Errorf("save DPoP key: %w", err)
		}
	}
	return t.Token, t.ExpiresIn, nil
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
