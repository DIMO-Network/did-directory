package signin

import (
	"context"
	"crypto/ecdsa"
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	dimocrypto "github.com/DIMO-Network/did-directory/internal/crypto"
	"github.com/DIMO-Network/did-directory/pkg/dpop"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// gatedDauth is fakeDauth with /signin/challenge held until open is closed,
// so a test can keep a sign-in in flight.
type gatedDauth struct {
	*fakeDauth
	arrived atomic.Int64
	open    chan struct{}
	once    sync.Once
}

func newGatedDauth(t *testing.T, key *ecdsa.PrivateKey) *gatedDauth {
	t.Helper()
	pub, err := dimocrypto.FromECDSA(&key.PublicKey)
	require.NoError(t, err)
	g := &gatedDauth{fakeDauth: &fakeDauth{pub: pub, proof: dpop.NewVerifier()}, open: make(chan struct{})}
	mux := http.NewServeMux()
	mux.HandleFunc("POST /signin/challenge", func(w http.ResponseWriter, r *http.Request) {
		g.arrived.Add(1)
		<-g.open
		g.challenge(w, r)
	})
	mux.HandleFunc("POST /signin/token", g.token)
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	t.Cleanup(g.release) // runs first: held handlers finish before Close waits on them
	g.url = srv.URL
	return g
}

func (g *gatedDauth) release() { g.once.Do(func() { close(g.open) }) }

// waitArrived waits until n challenge requests are held.
func (g *gatedDauth) waitArrived(t *testing.T, n int64) {
	t.Helper()
	require.Eventually(t, func() bool { return g.arrived.Load() >= n }, 5*time.Second, time.Millisecond)
}

func newClient(g *gatedDauth, key *ecdsa.PrivateKey) *Client {
	return &Client{Request: Request{Dauth: g.url, DID: testDID, Key: key, Scope: "read"}}
}

// tokenResult is one Token call's answer.
type tokenResult struct {
	token string
	err   error
}

func callToken(ctx context.Context, c *Client) <-chan tokenResult {
	out := make(chan tokenResult, 1)
	go func() {
		tok, err := c.Token(ctx)
		out <- tokenResult{tok, err}
	}()
	return out
}

func await(t *testing.T, ch <-chan tokenResult, within time.Duration) tokenResult {
	t.Helper()
	select {
	case r := <-ch:
		return r
	case <-time.After(within):
		t.Fatalf("Token did not return within %v", within)
		return tokenResult{}
	}
}

// R3-F8: concurrent callers share one sign-in.
func TestClientToken_OneSignInForConcurrentCallers(t *testing.T) {
	stubSleep(t)
	key := newKey(t)
	g := newGatedDauth(t, key)
	c := newClient(g, key)

	results := make([]<-chan tokenResult, 10)
	for i := range results {
		results[i] = callToken(context.Background(), c)
	}
	g.waitArrived(t, 1)
	time.Sleep(50 * time.Millisecond)
	assert.Equal(t, int64(1), g.arrived.Load(), "one sign-in in flight")
	g.release()
	for _, ch := range results {
		r := await(t, ch, 5*time.Second)
		require.NoError(t, r.err)
		assert.Equal(t, "id-token", r.token)
	}
	assert.Len(t, g.challenges, 1)
}

// R3-F8: a caller waiting on someone else's sign-in gives up on its own
// deadline. Before, it queued on the mutex for the whole sign-in (up to three
// 30 s attempts) and its deadline could not fire.
func TestClientToken_WaiterHonoursItsOwnContext(t *testing.T) {
	stubSleep(t)
	key := newKey(t)
	g := newGatedDauth(t, key)
	c := newClient(g, key)

	first := callToken(context.Background(), c)
	g.waitArrived(t, 1)

	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()
	r := await(t, callToken(ctx, c), 2*time.Second)
	assert.ErrorIs(t, r.err, context.DeadlineExceeded)

	g.release()
	r = await(t, first, 5*time.Second)
	require.NoError(t, r.err)
	assert.Equal(t, "id-token", r.token)
}

// R3-F8: the sign-in does not run under the first caller's context, so that
// caller giving up does not fail, or restart, the sign-in the others wait on.
func TestClientToken_FirstCallerCancellingDoesNotFailOthers(t *testing.T) {
	stubSleep(t)
	key := newKey(t)
	g := newGatedDauth(t, key)
	c := newClient(g, key)

	ctx, cancel := context.WithCancel(context.Background())
	first := callToken(ctx, c)
	g.waitArrived(t, 1)
	second := callToken(context.Background(), c)
	cancel()
	r := await(t, first, 2*time.Second)
	assert.ErrorIs(t, r.err, context.Canceled)

	time.Sleep(50 * time.Millisecond)
	g.release()
	r = await(t, second, 5*time.Second)
	require.NoError(t, r.err)
	assert.Equal(t, "id-token", r.token)
	assert.Equal(t, int64(1), g.arrived.Load(), "the first caller's sign-in carried on for the second")
}

// R3-F8: inside Margin the current token is still served, at once, while the
// replacement is fetched; the next call after the refresh gets the new one.
func TestClientToken_ServesTheValidTokenDuringRefresh(t *testing.T) {
	stubSleep(t)
	key := newKey(t)
	g := newGatedDauth(t, key)
	c := newClient(g, key)
	c.token, c.expires = "old-token", time.Now().Add(20*time.Second) // inside the 30s margin

	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()
	for range 3 {
		r := await(t, callToken(ctx, c), time.Second)
		require.NoError(t, r.err)
		assert.Equal(t, "old-token", r.token)
	}
	g.waitArrived(t, 1)
	assert.Equal(t, int64(1), g.arrived.Load())

	g.release()
	require.Eventually(t, func() bool {
		tok, err := c.Token(context.Background())
		return err == nil && tok == "id-token"
	}, 5*time.Second, 10*time.Millisecond)
	assert.Equal(t, int64(1), g.arrived.Load())
}

// An expired token is not served: the caller waits for the sign-in.
func TestClientToken_ExpiredTokenWaits(t *testing.T) {
	stubSleep(t)
	key := newKey(t)
	g := newGatedDauth(t, key)
	c := newClient(g, key)
	c.token, c.expires = "old-token", time.Now().Add(-time.Second)

	ch := callToken(context.Background(), c)
	g.waitArrived(t, 1)
	select {
	case r := <-ch:
		t.Fatalf("returned %+v before the sign-in finished", r)
	case <-time.After(50 * time.Millisecond):
	}
	g.release()
	r := await(t, ch, 5*time.Second)
	require.NoError(t, r.err)
	assert.Equal(t, "id-token", r.token)
}

// A failed sign-in reaches every waiter, and the next call tries again.
func TestClientToken_FailureReachesWaitersAndIsRetried(t *testing.T) {
	stubSleep(t)
	key := newKey(t)
	g := newGatedDauth(t, key)
	g.challengeFails = []failure{{status: http.StatusUnauthorized}}
	c := newClient(g, key)

	a, b := callToken(context.Background(), c), callToken(context.Background(), c)
	g.waitArrived(t, 1)
	g.release()
	for _, ch := range []<-chan tokenResult{a, b} {
		r := await(t, ch, 5*time.Second)
		var httpErr *HTTPError
		require.ErrorAs(t, r.err, &httpErr)
		assert.Equal(t, http.StatusUnauthorized, httpErr.Status)
	}

	tok, err := c.Token(context.Background())
	require.NoError(t, err)
	assert.Equal(t, "id-token", tok)
	assert.Len(t, g.challenges, 2)
}

// A sign-in that never answers is abandoned after refreshTimeout, so a later
// call can start another rather than wait on it forever.
func TestClientToken_StuckSignInIsBounded(t *testing.T) {
	stubSleep(t)
	orig := refreshTimeout
	refreshTimeout = 100 * time.Millisecond
	t.Cleanup(func() { refreshTimeout = orig })
	key := newKey(t)
	g := newGatedDauth(t, key)
	c := newClient(g, key)

	r := await(t, callToken(context.Background(), c), 5*time.Second)
	assert.ErrorIs(t, r.err, context.DeadlineExceeded)

	_ = callToken(context.Background(), c)
	g.waitArrived(t, 2)
}

// A misconfigured Request (no key) makes SignIn panic. The sign-in runs in its
// own goroutine, where a panic would kill the process, so it comes back as an
// error instead.
func TestClientToken_PanicIsAnError(t *testing.T) {
	stubSleep(t)
	g := newGatedDauth(t, newKey(t))
	g.release()
	c := &Client{Request: Request{Dauth: g.url, DID: testDID, Scope: "read"}}
	r := await(t, callToken(context.Background(), c), 5*time.Second)
	require.Error(t, r.err)
	assert.Contains(t, r.err.Error(), "panic")
}
