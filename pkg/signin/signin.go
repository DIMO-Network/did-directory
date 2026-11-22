// Package signin drives dauth's DID sign-in for a service that holds its own
// DID key: it asks for a challenge, signs it with the DID's key and trades it
// for an identity token bound to that same key as its DPoP key. dimocli uses
// it for people at a terminal, and services such as din use Client to keep a
// token for calling the org host.
//
// The key signs only a challenge it has checked. A sign-in signature has the
// same form as the signature on a directory operation (SHA-256, ECDSA r||s,
// base64url), and a DID's #signing key is often its rotation key too, so a
// hostile or spoofed dauth that passed off an operation payload as the
// challenge would get a rotation to its own key signed. SignIn signs the
// challenge only when it is dauth's sign-in text for exactly this request:
// this DID, this DPoP key, the nonce dauth returned, and the scope and
// audience asked for. Anything else fails with ErrInvalidChallenge before the
// key is used.
//
// A DID whose key is not an in-process P-256 key (secp256k1 in Turnkey, a KMS)
// sets Signer, which signs the challenge text, and DPoPKey, a separate P-256 key
// for the DPoP proofs. dauth only needs the DPoP proof's key to match the
// thumbprint the challenge names, and checks the challenge signature against the
// DID's verification method on its own. The challenge is checked before Signer
// is called, as it is before Key signs.
//
// dauth answers 503 (directory or store unavailable, replay cache full) and
// 429 (rate limit) without spending the challenge, so SignIn tries each call
// up to three times, waiting for the answer's Retry-After (at most 5s, 1s
// without one). The challenge is signed once: every /signin/token attempt
// sends the same nonce and signature, with a fresh DPoP proof, since dauth
// accepts a proof once.
package signin

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	dimocrypto "github.com/DIMO-Network/did-directory/internal/crypto"
	"github.com/DIMO-Network/did-directory/pkg/dpop"
	"github.com/DIMO-Network/did-directory/pkg/identity"
)

// ErrInvalidChallenge is wrapped by the error SignIn returns when dauth's
// challenge is not its sign-in text for the request. The key has signed
// nothing when SignIn returns it.
var ErrInvalidChallenge = errors.New("invalid sign-in challenge")

// Retries: a call answered 503 or 429 is tried up to maxAttempts times in
// all, waiting the answer's Retry-After capped at maxRetryAfter, or
// defaultRetryAfter when it names none.
const (
	maxAttempts       = 3
	defaultRetryAfter = time.Second
	maxRetryAfter     = 5 * time.Second
)

// sleep waits d, or until ctx is done. Tests replace it.
var sleep = func(ctx context.Context, d time.Duration) error {
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-t.C:
		return nil
	}
}

// Request is one sign-in.
type Request struct {
	// Dauth is dauth's base URL.
	Dauth string
	// DID signs in, with Key, the private half of its verification method
	// KeyFragment ("signing" when empty).
	DID         string
	Key         *ecdsa.PrivateKey
	KeyFragment string
	// Signer, when set, signs the challenge in place of Key (base64url r||s
	// over the SHA-256 of the data, as dimocrypto.SignOperation does), and
	// DPoPKey is then required: the DPoP proofs come from it, not from Key.
	Signer  func(ctx context.Context, data []byte) (string, error)
	DPoPKey *ecdsa.PrivateKey
	// Audience and Scope are what the token is asked for. An empty Audience
	// takes dauth's default. Scope is a scope claim (see identity.ParseScope);
	// one that does not parse fails before dauth is called.
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
// thumbprint, and /signin/token takes a proof from it. A challenge that is
// not the sign-in text for this request is refused unsigned, with an error
// wrapping ErrInvalidChallenge.
func SignIn(ctx context.Context, r Request) (Token, error) {
	dpopPriv := r.Key
	if r.Signer != nil {
		if r.DPoPKey == nil {
			return Token{}, errors.New("a Signer needs a DPoPKey for the DPoP proofs")
		}
		dpopPriv = r.DPoPKey
	}
	key, err := dpop.NewKey(dpopPriv)
	if err != nil {
		return Token{}, err
	}
	scopes, err := identity.ParseScope(r.Scope)
	if err != nil {
		return Token{}, fmt.Errorf("scope: %w", err)
	}
	scope := identity.FormatScope(scopes)
	frag := r.KeyFragment
	if frag == "" {
		frag = "signing"
	}
	base := strings.TrimRight(r.Dauth, "/")
	client := r.HTTP
	if client == nil {
		client = &http.Client{Timeout: 30 * time.Second}
	}

	challengeReq := map[string]any{"did": r.DID, "scope": scope, "jkt": key.Thumbprint()}
	if len(r.Audience) > 0 {
		challengeReq["audience"] = r.Audience
	}
	var challenge struct {
		Challenge string `json:"challenge"`
		Nonce     string `json:"nonce"`
	}
	if err := post(ctx, client, base+"/signin/challenge", nil, challengeReq, &challenge); err != nil {
		return Token{}, fmt.Errorf("challenge: %w", err)
	}
	if err := checkChallenge(challenge.Challenge, challenge.Nonce, r.DID, key.Thumbprint(), scope, r.Audience); err != nil {
		return Token{}, err
	}

	var sig string
	if r.Signer != nil {
		sig, err = r.Signer(ctx, []byte(challenge.Challenge))
	} else {
		sig, err = dimocrypto.SignOperation(r.Key, []byte(challenge.Challenge))
	}
	if err != nil {
		return Token{}, fmt.Errorf("sign challenge: %w", err)
	}
	tokenURL := base + "/signin/token"
	proof := func() (map[string]string, error) {
		p, err := key.Proof(http.MethodPost, tokenURL, "", time.Now())
		if err != nil {
			return nil, fmt.Errorf("DPoP proof: %w", err)
		}
		return map[string]string{dpop.HeaderName: p}, nil
	}
	var token struct {
		Token     string `json:"token"`
		ExpiresIn int    `json:"expires_in"`
	}
	body := map[string]any{"nonce": challenge.Nonce, "signature": sig, "key": frag}
	if err := post(ctx, client, tokenURL, proof, body, &token); err != nil {
		return Token{}, fmt.Errorf("token: %w", err)
	}
	return Token{Token: token.Token, ExpiresIn: token.ExpiresIn}, nil
}

// checkChallenge refuses text unless it is dauth's sign-in text for this
// request. dauth writes it as
//
//	<domain> wants you to sign in as
//	<did>
//
//	For: <audience, joined by ", ">
//	Scope: <scope>
//	Key: <DPoP key thumbprint>
//
//	Nonce: <nonce>
//	Issued At: <time>
//	Expiration Time: <time>
//
// The domain and times are dauth's own; everything else must be what was
// asked and what dauth answered. The first line rules out a directory
// operation payload, which is JSON. An empty audience asks for dauth's
// default, so then any For: line will do.
func checkChallenge(text, nonce, did, jkt, scope string, audience []string) error {
	bad := func(why string) error { return fmt.Errorf("%w: %s", ErrInvalidChallenge, why) }
	lines := strings.Split(text, "\n")
	if len(lines) < 2 || strings.HasPrefix(lines[0], "{") || !strings.HasSuffix(lines[0], " wants you to sign in as") {
		return bad("it does not start with the sign-in preamble")
	}
	if lines[1] != did {
		return bad("it names a different DID")
	}
	if nonce == "" {
		return bad("dauth sent no nonce")
	}
	body := "\n" + strings.Join(lines[2:], "\n") + "\n"
	if !strings.Contains(body, "\nKey: "+jkt+"\n") {
		return bad("it names a different key")
	}
	if !strings.Contains(body, "\nNonce: "+nonce+"\n") {
		return bad("it names a different nonce")
	}
	if !strings.Contains(body, "\nScope: "+scope+"\n") {
		return bad("it names a different scope")
	}
	forLine, found := "", false
	for _, l := range lines[2:] {
		if strings.HasPrefix(l, "For: ") {
			forLine, found = l, true
			break
		}
	}
	if !found {
		return bad("it names no audience")
	}
	if len(audience) > 0 && forLine != "For: "+strings.Join(audience, ", ") {
		return bad("it names a different audience")
	}
	return nil
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

// HTTPError is a non-2xx answer, with the body dauth sent. A 503 or 429 that
// lasts through every attempt is returned as the last one.
type HTTPError struct {
	Status int
	Body   string
	// RetryAfter is the answer's Retry-After in delta-seconds; zero when it
	// had none (or an HTTP date).
	RetryAfter time.Duration
}

func (e *HTTPError) Error() string {
	return fmt.Sprintf("%d %s: %s", e.Status, http.StatusText(e.Status), e.Body)
}

// wait is how long to wait before trying again after e.
func (e *HTTPError) wait() time.Duration {
	if e.RetryAfter <= 0 {
		return defaultRetryAfter
	}
	return min(e.RetryAfter, maxRetryAfter)
}

// retryAfter reads a Retry-After header given in delta-seconds; anything else
// is zero.
func retryAfter(v string) time.Duration {
	n, err := strconv.ParseUint(strings.TrimSpace(v), 10, 32)
	if err != nil && !errors.Is(err, strconv.ErrRange) {
		return 0
	}
	return time.Duration(n) * time.Second
}

// post sends body as JSON and decodes a 2xx answer into out. A 503 or 429 is
// tried again, up to maxAttempts in all, after its Retry-After; any other
// answer is final. headers, when not nil, is called for every attempt, so a
// DPoP proof is fresh each time.
func post(ctx context.Context, client *http.Client, url string, headers func() (map[string]string, error), body, out any) error {
	payload, err := json.Marshal(body)
	if err != nil {
		return err
	}
	for attempt := 1; ; attempt++ {
		var h map[string]string
		if headers != nil {
			if h, err = headers(); err != nil {
				return err
			}
		}
		err := postOnce(ctx, client, url, h, payload, out)
		var httpErr *HTTPError
		if attempt == maxAttempts || !errors.As(err, &httpErr) ||
			(httpErr.Status != http.StatusServiceUnavailable && httpErr.Status != http.StatusTooManyRequests) {
			return err
		}
		if err := sleep(ctx, httpErr.wait()); err != nil {
			return err
		}
	}
}

func postOnce(ctx context.Context, client *http.Client, url string, headers map[string]string, payload []byte, out any) error {
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
		return &HTTPError{
			Status:     resp.StatusCode,
			Body:       strings.TrimSpace(string(data)),
			RetryAfter: retryAfter(resp.Header.Get("Retry-After")),
		}
	}
	return json.Unmarshal(data, out)
}
