package orghost

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
	"time"

	"github.com/DIMO-Network/did-directory/internal/orghost/store"
	"github.com/DIMO-Network/did-directory/pkg/dpop"
	"github.com/gofiber/fiber/v2"
	"github.com/golang-jwt/jwt/v5"
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

// proofWithJTI is a DPoP proof by priv with a chosen jti, which dpop.Key does
// not offer: two proofs sharing one are how a test sees what was recorded.
func proofWithJTI(t *testing.T, priv *ecdsa.PrivateKey, method, url, token, jti string) (proof, jkt string) {
	t.Helper()
	b64 := base64.RawURLEncoding.EncodeToString
	jwk := map[string]any{"kty": "EC", "crv": "P-256", "x": b64(priv.X.FillBytes(make([]byte, 32))), "y": b64(priv.Y.FillBytes(make([]byte, 32)))}
	jkt, err := dpop.Thumbprint(jwk)
	require.NoError(t, err)
	ath := sha256.Sum256([]byte(token))
	tok := jwt.NewWithClaims(jwt.SigningMethodES256, jwt.MapClaims{
		"jti": jti, "htm": method, "htu": url, "iat": time.Now().Unix(), "ath": b64(ath[:]),
	})
	tok.Header["typ"] = "dpop+jwt"
	tok.Header["jwk"] = jwk
	proof, err = tok.SignedString(priv)
	require.NoError(t, err)
	return proof, jkt
}

// Fix round 1, item 7: the host's dpop.Verifier keeps no replay cache of its
// own; only the proof store records, and only for a request that passed every
// check. So a proof refused because its key is not the token's (cnf mismatch)
// spends nothing: its key and jti still work with the right token.
func TestReplay_RefusedProofIsNotRecorded(t *testing.T) {
	iss := newIssuer(t)
	a, err := NewJWKSAuthenticator(iss.jwks(), "https://auth.test", hostAudience)
	require.NoError(t, err)
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	const path = "/orgs/did:dimo:org"
	url := hostAudience + path

	// A token bound to the tests' shared holder, presented with a proof from key.
	wrong := iss.identity(t, "did:dimo:org")
	proof, jkt := proofWithJTI(t, key, http.MethodGet, url, wrong, "same-jti")
	_, err = a.Authenticate(t.Context(), Credentials{Authorization: "DPoP " + wrong, Proof: proof, Method: http.MethodGet, Path: path})
	require.ErrorIs(t, err, ErrUnauthenticated)
	assert.Contains(t, err.Error(), "not from the key the token is bound to")

	// The right token, bound to key, with a proof reusing that key and jti.
	claims := iss.claims("did:dimo:org", "read")
	claims["cnf"] = map[string]string{"jkt": jkt}
	right := iss.token(t, claims)
	proof, _ = proofWithJTI(t, key, http.MethodGet, url, right, "same-jti")
	_, err = a.Authenticate(t.Context(), Credentials{Authorization: "DPoP " + right, Proof: proof, Method: http.MethodGet, Path: path})
	require.NoError(t, err, "nothing was recorded for the refused proof")

	// And that one is now spent.
	_, err = a.Authenticate(t.Context(), Credentials{Authorization: "DPoP " + right, Proof: proof, Method: http.MethodGet, Path: path})
	assert.ErrorIs(t, err, ErrUnauthenticated)
}

// failingProofs is a proof store that cannot be reached.
type failingProofs struct{}

func (failingProofs) RecordProof(context.Context, store.Proof, time.Time, int) error {
	return errors.New("db: connection refused")
}

func (failingProofs) DeleteExpiredProofs(context.Context, time.Time) (int64, error) { return 0, nil }

// Fix round 1, item 7: when the proof store cannot record a proof, the request
// is not let through unprotected: it fails closed with 503, retryable.
func TestReplay_FailingProofStoreIs503(t *testing.T) {
	h := newHost(t, store.NewMemoryStore())
	org := newOrgDID()
	h.publish(org)
	status, body := h.do(http.MethodPost, "/orgs/"+org, org, nil)
	require.Equal(t, http.StatusCreated, status, body)
	h.auth.UseProofStore(failingProofs{}, 0, nil)

	status, body = h.do(http.MethodGet, "/orgs/"+org, org, nil)
	assert.Equal(t, http.StatusServiceUnavailable, status, body)
	assert.Equal(t, "temporarily_unavailable", body["code"])
	_, err := h.auth.Authenticate(t.Context(), credFor(t, h.issuer, org, "/orgs/"+org))
	assert.ErrorIs(t, err, ErrUnavailable)
	assert.NotErrorIs(t, err, ErrUnauthenticated)
}
