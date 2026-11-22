package orghost

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
	"time"

	"github.com/DIMO-Network/did-directory/internal/orghost/store"
	"github.com/gofiber/fiber/v2"
	"github.com/rs/zerolog"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// credFor presents a fresh token for did with a fresh proof for a GET of path.
func credFor(t *testing.T, iss *issuer, did, path string) Credentials {
	t.Helper()
	token := iss.identity(t, did)
	proof, err := iss.holder.Proof(http.MethodGet, hostAudience+path, token, time.Now())
	require.NoError(t, err)
	return Credentials{Authorization: "DPoP " + token, Proof: proof, Method: http.MethodGet, Path: path}
}

// R5-F6: a proof one replica accepted is refused by every other replica on the
// same database, so a captured request cannot be replayed on another pod with
// another body.
func TestReplay_RefusedOnAnotherReplica(t *testing.T) {
	shared := map[string]store.ProofStore{"memory": store.NewMemoryProofs(0)}
	if url := os.Getenv(store.TestDatabaseURLEnv); url != "" {
		pg, err := store.NewPostgresStore(t.Context(), url, zerolog.Nop())
		require.NoError(t, err)
		t.Cleanup(func() { _ = pg.Close() })
		shared["postgres"] = pg
	}
	for name, ps := range shared {
		t.Run(name, func(t *testing.T) {
			iss := newIssuer(t)
			replica := func() *JWKSAuthenticator {
				a, err := NewJWKSAuthenticator(iss.jwks(), "https://auth.test", hostAudience)
				require.NoError(t, err)
				a.UseProofStore(ps, 0, nil)
				return a
			}
			one, two := replica(), replica()
			c := credFor(t, iss, "did:dimo:org", "/orgs/did:dimo:org/network.dimo.org.role/founder")
			_, err := one.Authenticate(t.Context(), c)
			require.NoError(t, err)
			_, err = two.Authenticate(t.Context(), c)
			assert.ErrorIs(t, err, ErrUnauthenticated, "the second replica knows the proof was used")
			_, err = one.Authenticate(t.Context(), c)
			assert.ErrorIs(t, err, ErrUnauthenticated)
		})
	}
}

// R4-F10: one caller can hold only so many live proofs, so a flood from one
// signed-in DID is refused for that DID (429) and nobody else; the issuer
// (dauth, calling /authorize) is not capped.
func TestReplay_PerSubjectCap(t *testing.T) {
	iss := newIssuer(t)
	a, err := NewJWKSAuthenticator(iss.jwks(), "https://auth.test", hostAudience)
	require.NoError(t, err)
	a.UseProofStore(store.NewMemoryProofs(0), 3, []string{dauthDID})
	const path = "/orgs/did:dimo:org"
	for i := range 3 {
		_, err := a.Authenticate(t.Context(), credFor(t, iss, "did:dimo:flood", path))
		require.NoError(t, err, i)
	}
	_, err = a.Authenticate(t.Context(), credFor(t, iss, "did:dimo:flood", path))
	assert.ErrorIs(t, err, ErrRateLimited)
	assert.NotErrorIs(t, err, ErrUnauthenticated)
	_, err = a.Authenticate(t.Context(), credFor(t, iss, "did:dimo:other", path))
	assert.NoError(t, err, "another caller is untouched")
	for i := range 5 {
		_, err := a.Authenticate(t.Context(), credFor(t, iss, dauthDID, "/authorize"))
		require.NoError(t, err, "the issuer is not capped (%d)", i)
	}
}

func TestReplay_PerSubjectCapIs429(t *testing.T) {
	h := newHost(t, store.NewMemoryStore())
	h.auth.UseProofStore(store.NewMemoryProofs(0), 1, nil)
	org := newOrgDID()
	h.publish(org)
	status, body := h.do(http.MethodPost, "/orgs/"+org, org, nil)
	require.Equal(t, http.StatusCreated, status, body)

	req := httptest.NewRequest(http.MethodGet, "/orgs/"+org, nil)
	require.NoError(t, h.issuer.present(req, h.issuer.identity(t, org)))
	resp, err := h.app.Test(req, -1)
	require.NoError(t, err)
	defer func() { _ = resp.Body.Close() }()
	assert.Equal(t, http.StatusTooManyRequests, resp.StatusCode)
	assert.NotEmpty(t, resp.Header.Get(fiber.HeaderRetryAfter))
	assert.Empty(t, resp.Header.Get(fiber.HeaderWWWAuthenticate), "not an authentication failure")
	var out map[string]any
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&out))
	assert.Equal(t, "too_many_requests", out["code"])
}

// dauth adds a vm claim to sign-in tokens, and its own token for /authorize
// carries none: the host requires neither.
func TestJWKSAuthenticator_VMClaimIsOptional(t *testing.T) {
	iss := newIssuer(t)
	a, err := NewJWKSAuthenticator(iss.jwks(), "https://auth.test", hostAudience)
	require.NoError(t, err)
	const path = "/authorize"
	for _, vm := range []any{nil, "signing", "wallet"} {
		claims := iss.claims(dauthDID, "read")
		if vm != nil {
			claims["vm"] = vm
		}
		token := iss.token(t, claims)
		proof, err := iss.holder.Proof(http.MethodPost, hostAudience+path, token, time.Now())
		require.NoError(t, err)
		_, err = a.Authenticate(t.Context(), Credentials{Authorization: "DPoP " + token, Proof: proof, Method: http.MethodPost, Path: path})
		assert.NoError(t, err, "vm %v", vm)
	}
}

// countingProofs counts sweeps.
type countingProofs struct {
	store.ProofStore
	sweeps chan struct{}
}

func (c *countingProofs) DeleteExpiredProofs(ctx context.Context, now time.Time) (int64, error) {
	select {
	case c.sweeps <- struct{}{}:
	default:
	}
	return c.ProofStore.DeleteExpiredProofs(ctx, now)
}

// Postgres keeps no expiry of its own, so the host deletes expired proofs on a
// timer until it stops.
func TestSweepProofs(t *testing.T) {
	ps := &countingProofs{ProofStore: store.NewMemoryProofs(0), sweeps: make(chan struct{}, 1)}
	ctx, cancel := context.WithCancel(t.Context())
	done := make(chan struct{})
	go func() {
		SweepProofs(ctx, ps, 10*time.Millisecond, zerolog.Nop())
		close(done)
	}()
	select {
	case <-ps.sweeps:
	case <-time.After(2 * time.Second):
		t.Fatal("no sweep")
	}
	cancel()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("the sweeper did not stop")
	}
}
