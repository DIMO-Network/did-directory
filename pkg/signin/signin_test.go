package signin

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	dimocrypto "github.com/DIMO-Network/did-directory/internal/crypto"
	"github.com/DIMO-Network/did-directory/internal/did"
	"github.com/DIMO-Network/did-directory/pkg/didkey"
	"github.com/DIMO-Network/did-directory/pkg/dpop"
	"github.com/DIMO-Network/did-directory/pkg/identity"
	"github.com/decred/dcrd/dcrec/secp256k1/v4"
	dcrecdsa "github.com/decred/dcrd/dcrec/secp256k1/v4/ecdsa"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const (
	testDID   = "did:dimo:member1"
	testNonce = "nonce-1"
	orgHost   = "https://org.test"
)

// defaultAudience is what the fake dauth names when none is asked for.
var defaultAudience = []string{"https://accounts.test"}

// failure is a non-2xx answer the fake dauth gives before answering properly.
type failure struct {
	status     int
	retryAfter string
}

type challengeRequest struct {
	DID      string   `json:"did"`
	Scope    string   `json:"scope"`
	JKT      string   `json:"jkt"`
	Audience []string `json:"audience"`
}

type tokenAttempt struct {
	Nonce     string `json:"nonce"`
	Signature string `json:"signature"`
	Key       string `json:"key"`
	jti       string
}

// fakeDauth is dauth's sign-in surface as SignIn sees it. Each route answers
// its queued failures first. /signin/token checks the DPoP proof (a proof is
// accepted once) before anything else, as dauth does, then the nonce and the
// signature over the challenge it issued.
type fakeDauth struct {
	url   string
	pub   *dimocrypto.PublicKey
	proof *dpop.Verifier
	// text, when set, writes the challenge in place of dauthText.
	text func(req challengeRequest, nonce string) string

	mu             sync.Mutex
	challengeFails []failure
	tokenFails     []failure
	challenges     []challengeRequest
	tokens         []tokenAttempt
	issued         string
}

// dauthText is dauth's challengeText (internal/signin/server in dauth).
func dauthText(req challengeRequest, nonce string) string {
	aud := req.Audience
	if len(aud) == 0 {
		aud = defaultAudience
	}
	scopes, _ := identity.ParseScope(req.Scope)
	return fmt.Sprintf("%s wants you to sign in as\n%s\n\nFor: %s\nScope: %s\nKey: %s\n\nNonce: %s\nIssued At: %s\nExpiration Time: %s",
		"auth.test", req.DID, strings.Join(aud, ", "), identity.FormatScope(scopes), req.JKT,
		nonce, "2026-11-21T00:00:00Z", "2026-11-21T00:05:00Z")
}

func newFakeDauth(t *testing.T, key *ecdsa.PrivateKey) *fakeDauth {
	t.Helper()
	pub, err := dimocrypto.FromECDSA(&key.PublicKey)
	require.NoError(t, err)
	f := &fakeDauth{pub: pub, proof: dpop.NewVerifier()}
	mux := http.NewServeMux()
	mux.HandleFunc("POST /signin/challenge", f.challenge)
	mux.HandleFunc("POST /signin/token", f.token)
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	f.url = srv.URL
	return f
}

func (f *fakeDauth) challenge(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	defer f.mu.Unlock()
	var req challengeRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		answer(w, http.StatusBadRequest, "", map[string]any{"error": "invalid_request"})
		return
	}
	f.challenges = append(f.challenges, req)
	if failNext(w, &f.challengeFails) {
		return
	}
	text := dauthText
	if f.text != nil {
		text = f.text
	}
	f.issued = text(req, testNonce)
	answer(w, http.StatusOK, "", map[string]any{"challenge": f.issued, "nonce": testNonce, "expires_at": "2026-11-21T00:05:00Z"})
}

func (f *fakeDauth) token(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	defer f.mu.Unlock()
	var att tokenAttempt
	if err := json.NewDecoder(r.Body).Decode(&att); err != nil {
		answer(w, http.StatusBadRequest, "", map[string]any{"error": "invalid_request"})
		return
	}
	proof := r.Header.Get(dpop.HeaderName)
	att.jti = jti(proof)
	f.tokens = append(f.tokens, att)
	jkt, err := f.proof.Verify(proof, http.MethodPost, f.url+"/signin/token", "")
	if err != nil || len(f.challenges) == 0 || jkt != f.challenges[len(f.challenges)-1].JKT {
		answer(w, http.StatusUnauthorized, "", map[string]any{"error": "invalid_dpop_proof"})
		return
	}
	if failNext(w, &f.tokenFails) {
		return
	}
	if att.Nonce != testNonce || f.pub.Verify([]byte(f.issued), att.Signature) != nil {
		answer(w, http.StatusUnauthorized, "", map[string]any{"error": "invalid_grant"})
		return
	}
	answer(w, http.StatusOK, "", map[string]any{"token": "id-token", "token_type": "DPoP", "expires_in": 600})
}

// failNext answers the first queued failure, if any.
func failNext(w http.ResponseWriter, queue *[]failure) bool {
	if len(*queue) == 0 {
		return false
	}
	next := (*queue)[0]
	*queue = (*queue)[1:]
	answer(w, next.status, next.retryAfter, map[string]any{"error": "server_error", "error_description": "retry shortly"})
	return true
}

func answer(w http.ResponseWriter, status int, retryAfter string, body any) {
	w.Header().Set("Content-Type", "application/json")
	if retryAfter != "" {
		w.Header().Set("Retry-After", retryAfter)
	}
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(body)
}

// jti reads a proof's jti without checking it.
func jti(proof string) string {
	parts := strings.Split(proof, ".")
	if len(parts) != 3 {
		return ""
	}
	raw, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return ""
	}
	var claims struct {
		JTI string `json:"jti"`
	}
	_ = json.Unmarshal(raw, &claims)
	return claims.JTI
}

func newKey(t *testing.T) *ecdsa.PrivateKey {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	return key
}

// stubSleep records every wait instead of sleeping.
func stubSleep(t *testing.T) *[]time.Duration {
	t.Helper()
	var waits []time.Duration
	orig := sleep
	sleep = func(ctx context.Context, d time.Duration) error {
		waits = append(waits, d)
		return ctx.Err()
	}
	t.Cleanup(func() { sleep = orig })
	return &waits
}

func TestSignIn(t *testing.T) {
	t.Run("audience asked", func(t *testing.T) {
		waits := stubSleep(t)
		key := newKey(t)
		f := newFakeDauth(t, key)
		tok, err := SignIn(context.Background(), Request{
			Dauth: f.url + "/", DID: testDID, Key: key, Audience: []string{orgHost, "https://din.test"}, Scope: "write  read",
		})
		require.NoError(t, err)
		assert.Equal(t, Token{Token: "id-token", ExpiresIn: 600}, tok)
		require.Len(t, f.challenges, 1)
		assert.Equal(t, "read write", f.challenges[0].Scope, "the scope is sent in its canonical form")
		assert.Equal(t, []string{orgHost, "https://din.test"}, f.challenges[0].Audience)
		require.Len(t, f.tokens, 1)
		assert.Equal(t, testNonce, f.tokens[0].Nonce)
		assert.Equal(t, "signing", f.tokens[0].Key)
		assert.Empty(t, *waits)
	})
	t.Run("default audience", func(t *testing.T) {
		stubSleep(t)
		key := newKey(t)
		f := newFakeDauth(t, key)
		_, err := SignIn(context.Background(), Request{Dauth: f.url, DID: testDID, Key: key, KeyFragment: "wallet", Scope: "read"})
		require.NoError(t, err)
		require.Len(t, f.challenges, 1)
		assert.Nil(t, f.challenges[0].Audience, "no audience is sent, so dauth names its default")
		require.Len(t, f.tokens, 1)
		assert.Equal(t, "wallet", f.tokens[0].Key)
	})
}

// A hostile dauth that hands back a directory operation, here a rotation to
// its own key, as the challenge gets nothing signed.
func TestSignInRefusesOperationPayload(t *testing.T) {
	stubSleep(t)
	key := newKey(t)
	attacker, err := dimocrypto.EncodeDIDKey(&newKey(t).PublicKey)
	require.NoError(t, err)
	prev := "bafyreiprevious"
	payload, err := json.Marshal(did.UnsignedOperation{
		Type:                did.OpTypeCreate,
		RotationKeys:        []string{attacker},
		VerificationMethods: map[string]string{"signing": attacker},
		AlsoKnownAs:         []string{},
		Services:            map[string]did.Service{},
		Prev:                &prev,
	})
	require.NoError(t, err)

	f := newFakeDauth(t, key)
	f.text = func(challengeRequest, string) string { return string(payload) }
	_, err = SignIn(context.Background(), Request{Dauth: f.url, DID: testDID, Key: key, Scope: "read"})
	require.ErrorIs(t, err, ErrInvalidChallenge)
	assert.Len(t, f.challenges, 1)
	assert.Empty(t, f.tokens, "nothing is signed or sent to /signin/token")
}

func TestSignInRefusesMismatchedChallenge(t *testing.T) {
	other, err := dpop.NewKey(newKey(t))
	require.NoError(t, err)

	cases := []struct {
		name     string
		audience []string
		scope    string
		mutate   func(text string, req challengeRequest) string
	}{
		{name: "no preamble", mutate: func(s string, _ challengeRequest) string {
			return strings.Replace(s, " wants you to sign in as", " wants you to sign", 1)
		}},
		{name: "JSON preamble", mutate: func(s string, _ challengeRequest) string { return `{"type":"x"}` + s }},
		{name: "wrong DID", mutate: func(s string, _ challengeRequest) string {
			return strings.Replace(s, "\n"+testDID+"\n", "\ndid:dimo:other\n", 1)
		}},
		{name: "DID moved down a line", mutate: func(s string, _ challengeRequest) string {
			return strings.Replace(s, "sign in as\n", "sign in as\n\n", 1)
		}},
		{name: "wrong key", mutate: func(s string, req challengeRequest) string {
			return strings.Replace(s, "Key: "+req.JKT, "Key: "+other.Thumbprint(), 1)
		}},
		{name: "wrong nonce", mutate: func(s string, _ challengeRequest) string {
			return strings.Replace(s, "Nonce: "+testNonce, "Nonce: nonce-2", 1)
		}},
		{name: "wrong scope", mutate: func(s string, _ challengeRequest) string {
			return strings.Replace(s, "Scope: read\n", "Scope: read write\n", 1)
		}},
		{name: "scope widened by suffix", mutate: func(s string, _ challengeRequest) string {
			return strings.Replace(s, "Scope: read\n", "Scope: read approve\n", 1)
		}},
		{name: "wrong audience", audience: []string{orgHost}, mutate: func(s string, _ challengeRequest) string {
			return strings.Replace(s, "For: "+orgHost, "For: https://evil.test", 1)
		}},
		{name: "audience added", audience: []string{orgHost}, mutate: func(s string, _ challengeRequest) string {
			return strings.Replace(s, "For: "+orgHost, "For: "+orgHost+", https://evil.test", 1)
		}},
		{name: "no audience line", mutate: func(s string, _ challengeRequest) string {
			return strings.Replace(s, "For: "+strings.Join(defaultAudience, ", ")+"\n", "", 1)
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			stubSleep(t)
			key := newKey(t)
			f := newFakeDauth(t, key)
			f.text = func(req challengeRequest, n string) string { return tc.mutate(dauthText(req, n), req) }
			_, err := SignIn(context.Background(), Request{Dauth: f.url, DID: testDID, Key: key, Audience: tc.audience, Scope: "read"})
			require.ErrorIs(t, err, ErrInvalidChallenge)
			assert.Empty(t, f.tokens, "nothing is signed or sent to /signin/token")
		})
	}
}

func TestSignInRefusesBadScopeBeforeCallingDauth(t *testing.T) {
	for _, scope := range []string{"", "admin", "read read"} {
		key := newKey(t)
		f := newFakeDauth(t, key)
		_, err := SignIn(context.Background(), Request{Dauth: f.url, DID: testDID, Key: key, Scope: scope})
		require.Error(t, err, "%q", scope)
		assert.NotErrorIs(t, err, ErrInvalidChallenge)
		assert.Empty(t, f.challenges, "%q", scope)
	}
}

// A 503 at /signin/token is tried again with the same nonce and signature
// and a fresh proof: the fake's verifier refuses a replayed one.
func TestSignInRetriesTokenWithFreshProof(t *testing.T) {
	waits := stubSleep(t)
	key := newKey(t)
	f := newFakeDauth(t, key)
	f.tokenFails = []failure{{status: http.StatusServiceUnavailable, retryAfter: "2"}}

	tok, err := SignIn(context.Background(), Request{Dauth: f.url, DID: testDID, Key: key, Scope: "read"})
	require.NoError(t, err)
	assert.Equal(t, "id-token", tok.Token)
	assert.Len(t, f.challenges, 1, "the challenge is asked for once")
	require.Len(t, f.tokens, 2)
	assert.NotEmpty(t, f.tokens[0].jti)
	assert.NotEqual(t, f.tokens[0].jti, f.tokens[1].jti, "each attempt carries its own proof")
	assert.Equal(t, f.tokens[0].Nonce, f.tokens[1].Nonce)
	// ECDSA signatures are randomized, so equal signatures mean one signing.
	assert.Equal(t, f.tokens[0].Signature, f.tokens[1].Signature, "the challenge is signed once")
	assert.Equal(t, []time.Duration{2 * time.Second}, *waits)
}

func TestSignInRetriesChallengeOn429(t *testing.T) {
	waits := stubSleep(t)
	key := newKey(t)
	f := newFakeDauth(t, key)
	f.challengeFails = []failure{{status: http.StatusTooManyRequests}}

	_, err := SignIn(context.Background(), Request{Dauth: f.url, DID: testDID, Key: key, Scope: "read"})
	require.NoError(t, err)
	assert.Len(t, f.challenges, 2)
	assert.Len(t, f.tokens, 1)
	assert.Equal(t, []time.Duration{time.Second}, *waits, "1s without a Retry-After")
}

func TestSignInGivesUpAfterThreeAttempts(t *testing.T) {
	waits := stubSleep(t)
	key := newKey(t)
	f := newFakeDauth(t, key)
	busy := failure{status: http.StatusServiceUnavailable, retryAfter: "30"}
	f.tokenFails = []failure{busy, busy, busy, busy}

	_, err := SignIn(context.Background(), Request{Dauth: f.url, DID: testDID, Key: key, Scope: "read"})
	var httpErr *HTTPError
	require.ErrorAs(t, err, &httpErr)
	assert.Equal(t, http.StatusServiceUnavailable, httpErr.Status)
	assert.Equal(t, 30*time.Second, httpErr.RetryAfter, "the server's Retry-After, unclamped")
	require.Len(t, f.tokens, 3)
	assert.Equal(t, f.tokens[0].Signature, f.tokens[2].Signature)
	assert.Equal(t, []time.Duration{5 * time.Second, 5 * time.Second}, *waits, "the wait is capped at 5s")
}

func TestSignInDoesNotRetry401(t *testing.T) {
	waits := stubSleep(t)
	key := newKey(t)
	f := newFakeDauth(t, key)
	f.tokenFails = []failure{{status: http.StatusUnauthorized, retryAfter: "1"}}

	_, err := SignIn(context.Background(), Request{Dauth: f.url, DID: testDID, Key: key, Scope: "read"})
	var httpErr *HTTPError
	require.ErrorAs(t, err, &httpErr)
	assert.Equal(t, http.StatusUnauthorized, httpErr.Status)
	assert.Len(t, f.tokens, 1)
	assert.Empty(t, *waits)
}

// Cancelling ctx ends the wait between attempts.
func TestSignInStopsWaitingWhenCancelled(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	orig := sleep
	sleep = func(ctx context.Context, _ time.Duration) error {
		cancel()
		return orig(ctx, time.Hour)
	}
	t.Cleanup(func() { sleep = orig })

	key := newKey(t)
	f := newFakeDauth(t, key)
	f.tokenFails = []failure{{status: http.StatusServiceUnavailable}}
	done := make(chan error, 1)
	go func() {
		_, err := SignIn(ctx, Request{Dauth: f.url, DID: testDID, Key: key, Scope: "read"})
		done <- err
	}()
	select {
	case err := <-done:
		require.ErrorIs(t, err, context.Canceled)
	case <-time.After(10 * time.Second):
		t.Fatal("SignIn kept waiting after ctx was cancelled")
	}
	assert.Len(t, f.tokens, 1)
}

func TestRetryAfter(t *testing.T) {
	for in, want := range map[string]time.Duration{
		"":                              0,
		"3":                             3 * time.Second,
		" 7 ":                           7 * time.Second,
		"-1":                            0,
		"1.5":                           0,
		"Wed, 21 Oct 2026 07:28:00 GMT": 0,
		"99999999999":                   (1<<32 - 1) * time.Second,
	} {
		assert.Equal(t, want, retryAfter(in), "%q", in)
	}
}

// A DID whose key is secp256k1 and held elsewhere signs the challenge through
// Signer; DPoP uses its own P-256 key.
func TestSignInWithSignerAndSeparateDPoPKey(t *testing.T) {
	stubSleep(t)
	k1, err := secp256k1.GeneratePrivateKey()
	require.NoError(t, err)
	f := newFakeDauth(t, newKey(t))
	f.pub = didkey.FromSecp256k1(k1.PubKey())

	var signed []string
	signer := func(_ context.Context, data []byte) (string, error) {
		signed = append(signed, string(data))
		h := sha256.Sum256(data)
		sig := dcrecdsa.Sign(k1, h[:])
		r, s := sig.R(), sig.S()
		rb, sb := r.Bytes(), s.Bytes()
		return base64.RawURLEncoding.EncodeToString(append(rb[:], sb[:]...)), nil
	}
	dpopKey := newKey(t)
	tok, err := SignIn(context.Background(), Request{
		Dauth: f.url, DID: testDID, Signer: signer, DPoPKey: dpopKey, Scope: "read",
	})
	require.NoError(t, err)
	assert.Equal(t, "id-token", tok.Token)
	require.Len(t, signed, 1)
	assert.Equal(t, f.issued, signed[0])
	jkt, err := dpop.NewKey(dpopKey)
	require.NoError(t, err)
	assert.Equal(t, jkt.Thumbprint(), f.challenges[0].JKT, "the challenge names the DPoP key's thumbprint")
}

func TestSignInSignerNotCalledForHostileChallenge(t *testing.T) {
	stubSleep(t)
	f := newFakeDauth(t, newKey(t))
	f.text = func(challengeRequest, string) string { return `{"type":"create"}` }
	called := false
	_, err := SignIn(context.Background(), Request{
		Dauth: f.url, DID: testDID, DPoPKey: newKey(t), Scope: "read",
		Signer: func(context.Context, []byte) (string, error) { called = true; return "", nil },
	})
	require.ErrorIs(t, err, ErrInvalidChallenge)
	assert.False(t, called)
	assert.Empty(t, f.tokens)
}

func TestSignInSignerNeedsDPoPKey(t *testing.T) {
	f := newFakeDauth(t, newKey(t))
	_, err := SignIn(context.Background(), Request{
		Dauth: f.url, DID: testDID, Scope: "read",
		Signer: func(context.Context, []byte) (string, error) { return "", nil },
	})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "DPoPKey")
	assert.Empty(t, f.challenges, "fails before dauth is called")
}
