package orghost

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// keySet serves the JWKS of the given issuers, as dauth's /signin/keys does
// across a rotation.
func keySet(t *testing.T, issuers ...*issuer) []byte {
	t.Helper()
	var keys []json.RawMessage
	for _, iss := range issuers {
		var set struct {
			Keys []json.RawMessage `json:"keys"`
		}
		require.NoError(t, json.Unmarshal(iss.jwks(), &set))
		keys = append(keys, set.Keys...)
	}
	out, err := json.Marshal(map[string]any{"keys": keys})
	require.NoError(t, err)
	return out
}

// jwksFixture is an authenticator over a key set the test swaps, on a clock
// the test moves.
type jwksFixture struct {
	auth    *JWKSAuthenticator
	mu      sync.Mutex
	set     []byte
	err     error
	fetches atomic.Int32
	clock   time.Time
}

func newJWKSFixture(t *testing.T, initial []byte) *jwksFixture {
	t.Helper()
	f := &jwksFixture{set: initial, clock: time.Date(2026, 11, 22, 12, 0, 0, 0, time.UTC)}
	auth, err := NewJWKSAuthenticator(initial, "https://auth.test", hostAudience)
	require.NoError(t, err)
	auth.now = func() time.Time {
		f.mu.Lock()
		defer f.mu.Unlock()
		return f.clock
	}
	auth.attemptedAt = f.clock
	auth.fetch = func(context.Context) ([]byte, error) {
		f.fetches.Add(1)
		f.mu.Lock()
		defer f.mu.Unlock()
		return f.set, f.err
	}
	f.auth = auth
	return f
}

func (f *jwksFixture) serve(set []byte, err error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.set, f.err = set, err
}

func (f *jwksFixture) advance(d time.Duration) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.clock = f.clock.Add(d)
}

// authenticates reports whether a token from iss (with iss's kid) for did is
// accepted. All tokens are bound to holder, whose proofs the caller makes.
func (f *jwksFixture) authenticates(t *testing.T, iss *issuer, holder *issuer) bool {
	t.Helper()
	const path = "/orgs/did:dimo:org"
	claims := iss.claims("did:dimo:org", "read")
	claims["cnf"] = map[string]string{"jkt": holder.holder.Thumbprint()}
	token := iss.token(t, claims)
	proof, err := holder.holder.Proof(http.MethodGet, hostAudience+path, token, time.Now())
	require.NoError(t, err)
	_, err = f.auth.Authenticate(t.Context(), Credentials{Authorization: "DPoP " + token, Proof: proof, Method: http.MethodGet, Path: path})
	return err == nil
}

// R5-F4 / R4-F9, V3's probe: dauth's rotation adds the new key, then removes
// the old one. The host must stop accepting the removed key within the JWKS
// TTL even though no request ever names an unknown kid again.
func TestJWKS_RemovedKeyDropsWithinTheTTL(t *testing.T) {
	old := newIssuer(t)
	next := newIssuer(t)
	next.kid = "k2"
	f := newJWKSFixture(t, keySet(t, old))
	require.True(t, f.authenticates(t, old, old))

	// Step 3: the new key is published beside the old; its first token fetches.
	f.serve(keySet(t, next, old), nil)
	f.advance(2 * time.Minute)
	assert.True(t, f.authenticates(t, next, old))
	assert.True(t, f.authenticates(t, old, old))

	// Step 4: the old key is removed. Only known kids arrive from here on.
	f.serve(keySet(t, next), nil)
	f.advance(time.Minute)
	assert.True(t, f.authenticates(t, old, old), "inside the TTL the cached set still holds it")
	f.advance(5 * time.Minute)
	assert.False(t, f.authenticates(t, old, old), "past the TTL the set is fetched again and the removed key is gone")
	assert.True(t, f.authenticates(t, next, old))
}

// R4-F9 / R5-F8: a failed fetch counts as an attempt, so garbage kids while
// dauth is down cost one fetch a minute, not one per request; and a failed
// refresh keeps the keys the host has.
func TestJWKS_FailedFetchIsAnAttempt(t *testing.T) {
	good := newIssuer(t)
	stranger := newIssuer(t)
	stranger.kid = "random"
	f := newJWKSFixture(t, keySet(t, good))
	f.serve(nil, errors.New("dauth is down"))
	f.advance(2 * time.Minute)

	for range 20 {
		assert.False(t, f.authenticates(t, stranger, good))
	}
	assert.Equal(t, int32(1), f.fetches.Load(), "one attempt, however many requests")
	assert.True(t, f.authenticates(t, good, good), "the keys it had are kept")

	f.advance(61 * time.Second)
	assert.False(t, f.authenticates(t, stranger, good))
	assert.Equal(t, int32(2), f.fetches.Load(), "the next attempt a minute after the last one")

	// The TTL refetch fails too: the known key still verifies.
	f.advance(6 * time.Minute)
	assert.True(t, f.authenticates(t, good, good))
}

// R4-F9 / R5-F8: concurrent requests share one fetch.
func TestJWKS_RefetchIsSingleFlight(t *testing.T) {
	good := newIssuer(t)
	next := newIssuer(t)
	next.kid = "k2"
	f := newJWKSFixture(t, keySet(t, good))
	release := make(chan struct{})
	f.auth.fetch = func(context.Context) ([]byte, error) {
		f.fetches.Add(1)
		<-release
		return keySet(t, good, next), nil
	}
	f.advance(2 * time.Minute)

	var wg sync.WaitGroup
	var ok atomic.Int32
	for range 20 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if f.authenticates(t, next, good) {
				ok.Add(1)
			}
		}()
	}
	time.Sleep(50 * time.Millisecond)
	close(release)
	wg.Wait()
	assert.Equal(t, int32(1), f.fetches.Load())
	assert.Equal(t, int32(20), ok.Load(), "every request waited for the one fetch and got the new key")
}

// R4-F9 / R5-F8: the fetch has its own timeout, so a hung dauth cannot park
// goroutines without limit.
func TestJWKS_FetchTimesOut(t *testing.T) {
	assert.Equal(t, 5*time.Second, jwksFetchTimeout)
	hang := make(chan struct{})
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		select {
		case <-hang:
		case <-r.Context().Done():
		}
	}))
	defer srv.Close()
	defer close(hang)
	defer func(d time.Duration) { jwksFetchTimeout = d }(jwksFetchTimeout)
	jwksFetchTimeout = 100 * time.Millisecond

	start := time.Now()
	_, err := NewJWKSAuthenticatorFromURL(context.Background(), srv.URL, "https://auth.test", hostAudience)
	require.Error(t, err)
	assert.Less(t, time.Since(start), 2*time.Second)
}
