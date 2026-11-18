// Package signin drives dauth's DID sign-in for a service that holds its own
// DID key: it asks for a challenge, signs it with the DID's key and trades it
// for an identity token bound to that same key as its DPoP key. dimocli uses
// it for people at a terminal, and services such as din use Client to keep a
// token for calling the org host.
package signin

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"
	"time"

	dimocrypto "github.com/DIMO-Network/did-directory/internal/crypto"
	"github.com/DIMO-Network/did-directory/pkg/dpop"
)

// Request is one sign-in.
type Request struct {
	// Dauth is dauth's base URL.
	Dauth string
	// DID signs in, with Key, the private half of its verification method
	// KeyFragment ("signing" when empty).
	DID         string
	Key         *ecdsa.PrivateKey
	KeyFragment string
	// Audience and Scope are what the token is asked for.
	Audience []string
	Scope    string
	// HTTP is the client to send with; nil means a 30s-timeout client.
	HTTP *http.Client
}

// Token is an identity token and when it expires.
type Token struct {
	Token     string
	ExpiresIn int
}

// SignIn runs the challenge and token round trip. The token carries the
// scope asked for and is bound to Key: the challenge names the key's
// thumbprint, and /signin/token takes a proof from it.
func SignIn(ctx context.Context, r Request) (Token, error) {
	key, err := dpop.NewKey(r.Key)
	if err != nil {
		return Token{}, err
	}
	frag := r.KeyFragment
	if frag == "" {
		frag = "signing"
	}
	base := strings.TrimRight(r.Dauth, "/")
	client := r.HTTP
	if client == nil {
		client = &http.Client{Timeout: 30 * time.Second}
	}

	challengeReq := map[string]any{"did": r.DID, "scope": r.Scope, "jkt": key.Thumbprint()}
	if len(r.Audience) > 0 {
		challengeReq["audience"] = r.Audience
	}
	var challenge struct {
		Challenge string `json:"challenge"`
		Nonce     string `json:"nonce"`
	}
	if err := send(ctx, client, base+"/signin/challenge", nil, challengeReq, &challenge); err != nil {
		return Token{}, fmt.Errorf("challenge: %w", err)
	}

	sig, err := dimocrypto.SignOperation(r.Key, []byte(challenge.Challenge))
	if err != nil {
		return Token{}, fmt.Errorf("sign challenge: %w", err)
	}
	tokenURL := base + "/signin/token"
	proof, err := key.Proof(http.MethodPost, tokenURL, "", time.Now())
	if err != nil {
		return Token{}, fmt.Errorf("DPoP proof: %w", err)
	}
	var token struct {
		Token     string `json:"token"`
		ExpiresIn int    `json:"expires_in"`
	}
	body := map[string]any{"nonce": challenge.Nonce, "signature": sig, "key": frag}
	if err := send(ctx, client, tokenURL, map[string]string{dpop.HeaderName: proof}, body, &token); err != nil {
		return Token{}, fmt.Errorf("token: %w", err)
	}
	return Token{Token: token.Token, ExpiresIn: token.ExpiresIn}, nil
}

// Client keeps one identity token and signs in again when it is about to
// expire. It is safe for concurrent use.
type Client struct {
	Request Request
	// Margin is how long before expiry a token is replaced; 30s when zero.
	Margin time.Duration

	mu      sync.Mutex
	token   string
	expires time.Time
}

// Token returns a token with at least Margin left on it.
func (c *Client) Token(ctx context.Context) (string, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	margin := c.Margin
	if margin == 0 {
		margin = 30 * time.Second
	}
	if c.token != "" && time.Until(c.expires) > margin {
		return c.token, nil
	}
	t, err := SignIn(ctx, c.Request)
	if err != nil {
		return "", err
	}
	c.token, c.expires = t.Token, time.Now().Add(time.Duration(t.ExpiresIn)*time.Second)
	return c.token, nil
}

// HTTPError is a non-2xx answer, with the body dauth sent.
type HTTPError struct {
	Status int
	Body   string
}

func (e *HTTPError) Error() string {
	return fmt.Sprintf("%d %s: %s", e.Status, http.StatusText(e.Status), e.Body)
}

func send(ctx context.Context, client *http.Client, url string, headers map[string]string, body, out any) error {
	payload, err := json.Marshal(body)
	if err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(payload))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	for k, v := range headers {
		req.Header.Set(k, v)
	}
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
		return &HTTPError{Status: resp.StatusCode, Body: strings.TrimSpace(string(data))}
	}
	return json.Unmarshal(data, out)
}
