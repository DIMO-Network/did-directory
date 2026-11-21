package orghost

import (
	"bytes"
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"net/http/httptest"
	"os"
	"sync"
	"testing"
	"time"

	dimocrypto "github.com/DIMO-Network/did-directory/internal/crypto"
	"github.com/DIMO-Network/did-directory/internal/orghost/store"
	"github.com/DIMO-Network/did-directory/pkg/agreement"
	"github.com/DIMO-Network/did-directory/pkg/client"
	"github.com/DIMO-Network/did-directory/pkg/control"
	"github.com/DIMO-Network/did-directory/pkg/delegation"
	"github.com/DIMO-Network/did-directory/pkg/dpop"
	"github.com/DIMO-Network/did-directory/pkg/odrl"
	"github.com/DIMO-Network/did-directory/pkg/repo"
	"github.com/gofiber/fiber/v2"
	"github.com/rs/zerolog"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// issuer stands in for dauth: an RS256 key published as a JWKS, minting
// identity tokens whose sub is a DID. Every token it mints is bound to holder,
// the one DPoP key the tests' callers share.
type issuer struct {
	key    *rsa.PrivateKey
	kid    string
	holder *dpop.Key
}

func newIssuer(t *testing.T) *issuer {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	holder, err := dpop.GenerateKey()
	require.NoError(t, err)
	return &issuer{key: key, kid: "k1", holder: holder}
}

func (i *issuer) jwks() []byte {
	b64 := base64.RawURLEncoding.EncodeToString
	set := map[string]any{"keys": []map[string]string{{
		"kty": "RSA", "kid": i.kid, "use": "sig", "alg": "RS256",
		"n": b64(i.key.N.Bytes()), "e": b64(big.NewInt(int64(i.key.E)).Bytes()),
	}}}
	out, _ := json.Marshal(set)
	return out
}

func (i *issuer) token(t *testing.T, claims map[string]any) string {
	t.Helper()
	return i.tokenWithHeader(t, map[string]any{"alg": "RS256", "typ": "JWT", "kid": i.kid}, claims)
}

func (i *issuer) tokenWithHeader(t *testing.T, header, claims map[string]any) string {
	t.Helper()
	b64 := base64.RawURLEncoding.EncodeToString
	h, _ := json.Marshal(header)
	c, _ := json.Marshal(claims)
	signingInput := b64(h) + "." + b64(c)
	digest := sha256.Sum256([]byte(signingInput))
	sig, err := rsa.SignPKCS1v15(rand.Reader, i.key, crypto.SHA256, digest[:])
	require.NoError(t, err)
	return signingInput + "." + b64(sig)
}

// allScopes is what the tests' callers sign in with unless a test is about
// scope.
const allScopes = "read write approve"

// identity mints a fresh token for did with every scope, valid for an hour.
func (i *issuer) identity(t *testing.T, did string) string {
	return i.scoped(t, did, allScopes)
}

// scoped mints a fresh token for did carrying scope, valid for an hour.
func (i *issuer) scoped(t *testing.T, did, scope string) string {
	return i.token(t, i.claims(did, scope))
}

func (i *issuer) claims(did, scope string) map[string]any {
	now := time.Now().Unix()
	return map[string]any{"iss": "https://auth.test", "aud": hostAudience, "sub": did, "iat": now, "nbf": now, "exp": now + 3600,
		"scope": scope, "cnf": map[string]string{"jkt": i.holder.Thumbprint()}}
}

// present sets req's credentials: token under the DPoP scheme with a fresh
// proof from the holder key.
func (i *issuer) present(req *http.Request, token string) error {
	proof, err := i.holder.Proof(req.Method, hostAudience+req.URL.Path, token, time.Now())
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "DPoP "+token)
	req.Header.Set("DPoP", proof)
	return nil
}

type host struct {
	t      *testing.T
	app    *fiber.App
	issuer *issuer
	// auth is the host's authenticator, for tests that reach into its DPoP
	// verifier.
	auth *JWKSAuthenticator
	repo *Repository
	// directory is what the resolver reads control state from.
	directory *fakeDirectory
	// clock is the host's time; tests move it to commit and evaluate at fixed
	// points.
	clock time.Time
}

// Privileged callers in tests: the one DID allowed to call /authorize and the
// one allowed to set parties.
const (
	dauthDID = "did:dimo:dauth"
	dimoDID  = "did:dimo:dimo"
)

// fakeDirectory answers control lookups for the vehicles a test registers.
type fakeDirectory struct {
	mu     sync.Mutex
	states map[string]*control.State
	calls  int
}

func (d *fakeDirectory) Control(_ context.Context, did string) (*control.State, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.calls++
	st, ok := d.states[did]
	if !ok {
		return nil, fmt.Errorf("%w: %s", client.ErrNotFound, did)
	}
	return st, nil
}

func (d *fakeDirectory) set(did string, st *control.State) {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.states == nil {
		d.states = map[string]*control.State{}
	}
	d.states[did] = st
}

func stores(t *testing.T) map[string]store.Store {
	t.Helper()
	out := map[string]store.Store{"memory": store.NewMemoryStore()}
	if url := os.Getenv(store.TestDatabaseURLEnv); url != "" {
		pg, err := store.NewPostgresStore(t.Context(), url, zerolog.Nop())
		require.NoError(t, err)
		t.Cleanup(func() { _ = pg.Close() })
		out["postgres"] = pg
	}
	return out
}

// newHost builds a host over st that knows the booking commit policy, as the
// binary does.
func newHost(t *testing.T, st store.Store) *host {
	t.Helper()
	booking := agreement.CommitPolicy()
	return newHostWith(t, st, Policies{booking.Name: booking})
}

func newHostWith(t *testing.T, st store.Store, policies Policies) *host {
	t.Helper()
	iss := newIssuer(t)
	auth, err := NewJWKSAuthenticator(iss.jwks(), "https://auth.test", hostAudience)
	require.NoError(t, err)
	sealer, err := NewEphemeralSealer()
	require.NoError(t, err)
	h := &host{t: t, issuer: iss, auth: auth, directory: &fakeDirectory{}}
	r := &Repository{Store: st, Signer: NewLocalSigner(st, sealer), Now: func() time.Time {
		if h.clock.IsZero() {
			return time.Now()
		}
		return h.clock
	}}
	h.repo = r
	h.app = New(Options{
		Repo: r, Auth: auth, Control: h.directory,
		Issuers: []string{dauthDID}, Admins: []string{dimoDID}, Policies: policies,
		PageSize: 50, Log: zerolog.Nop(),
	})
	return h
}

// roleRecord is a role from org to member, valid from 2026.
func roleRecord(org, member string, covers delegation.Covers, abilities ...string) delegation.Record {
	return delegation.Record{
		Type: delegation.TypeRole, From: org, To: member, Covers: covers, Abilities: abilities,
		Validity:   delegation.Window{From: tp(time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC))},
		Redelegate: delegation.Redelegate{Mode: delegation.RedelegateNone}, CreatedAt: time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC),
	}
}

// grantRole has the org write member a role and returns its URI.
func (h *host) grantRole(org string, rec delegation.Record) string {
	h.t.Helper()
	status, body := h.do(http.MethodPost, "/orgs/"+org+"/"+delegation.CollectionRole, org, rec)
	require.Equal(h.t, http.StatusCreated, status, body)
	return body["uri"].(string)
}

// do sends a request as the given DID (or unauthenticated when as is "").
func (h *host) do(method, path, as string, body any) (int, map[string]any) {
	h.t.Helper()
	var reader io.Reader
	if body != nil {
		var data []byte
		switch b := body.(type) {
		case string:
			data = []byte(b)
		case []byte:
			data = b
		case delegation.Record:
			data = policy(h.t, &b)
		case *delegation.Record:
			data = policy(h.t, b)
		default:
			var err error
			data, err = json.Marshal(b)
			require.NoError(h.t, err)
		}
		reader = bytes.NewReader(data)
	}
	req := httptest.NewRequest(method, path, reader)
	req.Header.Set("Content-Type", "application/json")
	if as != "" {
		require.NoError(h.t, h.issuer.present(req, h.issuer.identity(h.t, as)))
	}
	resp, err := h.app.Test(req, -1)
	require.NoError(h.t, err)
	defer func() { _ = resp.Body.Close() }()
	raw, err := io.ReadAll(resp.Body)
	require.NoError(h.t, err)
	var out map[string]any
	_ = json.Unmarshal(raw, &out)
	return resp.StatusCode, out
}

// policy renders a record as the ODRL policy a client sends. The host fills in
// the uid from where the policy is written.
func policy(t *testing.T, rec *delegation.Record) []byte {
	t.Helper()
	data, err := odrl.Marshal(rec, "")
	require.NoError(t, err)
	return data
}

var orgSeq int

func newOrgDID() string {
	orgSeq++
	return fmt.Sprintf("did:dimo:org%d%d", time.Now().UnixNano(), orgSeq)
}

func ts(t time.Time) string { return t.UTC().Format(time.RFC3339) }

// delegationRecord is a grant from org to Ford Credit as the ODRL policy that
// goes over the wire. extra replaces top-level keys of the policy.
func delegationRecord(org string, extra map[string]any) map[string]any {
	rec := map[string]any{
		"@context":        []string{odrl.ContextODRL, odrl.ContextDIMO},
		"@type":           odrl.TypeAgreement,
		"profile":         odrl.Profile,
		"assigner":        org,
		"assignee":        "did:dimo:fordcredit",
		"permission":      []map[string]any{permission("at://"+org+"/network.dimo.org.tag/fleet", "dimo:telemetry.read")},
		"dimo:redelegate": map[string]any{"mode": "none"},
		"dcterms:issued":  ts(time.Now()),
	}
	for k, v := range extra {
		rec[k] = v
	}
	return rec
}

// permission is an ODRL permission over target valid, and reading data, from 2026.
func permission(target string, actions ...string) map[string]any {
	from := ts(time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC))
	return map[string]any{
		"target": target,
		"action": actions,
		"constraint": []map[string]any{
			{"leftOperand": odrl.LeftDateTime, "operator": odrl.OpGTEQ, "rightOperand": from},
			{"leftOperand": odrl.LeftDataTime, "operator": odrl.OpGTEQ, "rightOperand": from},
		},
	}
}

func TestRepositoryFlow(t *testing.T) {
	for name, st := range stores(t) {
		t.Run(name, func(t *testing.T) {
			h := newHost(t, st)
			org := newOrgDID()
			const alice, bob = "did:dimo:alice", "did:dimo:bob"

			// Nothing under /orgs works without a token.
			status, body := h.do(http.MethodGet, "/orgs/"+org, "", nil)
			assert.Equal(t, http.StatusUnauthorized, status, body)

			// Only the org can register itself.
			status, body = h.do(http.MethodPost, "/orgs/"+org, alice, nil)
			assert.Equal(t, http.StatusForbidden, status, body)
			status, body = h.do(http.MethodPost, "/orgs/"+org, org, nil)
			require.Equal(t, http.StatusCreated, status, body)
			orgKey := body["key"].(string)
			status, body = h.do(http.MethodPost, "/orgs/"+org, org, nil)
			assert.Equal(t, http.StatusConflict, status, body)

			status, body = h.do(http.MethodGet, "/orgs/"+org, alice, nil)
			require.Equal(t, http.StatusOK, status, body)
			assert.Equal(t, orgKey, body["key"])
			assert.Equal(t, float64(0), body["head"].(map[string]any)["seq"])

			// Writes to an org that is not on this host are refused.
			status, body = h.do(http.MethodPut, "/orgs/did:dimo:nowhere/network.dimo.org.tag/fleet", alice, `{"name":"Fleet"}`)
			assert.Equal(t, http.StatusNotFound, status, body)

			// The org writes a tag as itself; committedBy is empty for that.
			status, body = h.do(http.MethodPut, "/orgs/"+org+"/network.dimo.org.tag/fleet", org, `{"description": "All cars", "name": "Fleet"}`)
			require.Equal(t, http.StatusCreated, status, body)
			assert.Equal(t, "create", body["op"])
			assert.Equal(t, "at://"+org+"/network.dimo.org.tag/fleet", body["uri"])
			assert.Equal(t, float64(1), body["seq"])

			// Nobody else may touch it until they hold a role.
			status, body = h.do(http.MethodPut, "/orgs/"+org+"/network.dimo.org.tag/fleet", alice, `{"name":"Fleet","description":"Every car"}`)
			require.Equal(t, http.StatusForbidden, status, body)
			status, body = h.do(http.MethodGet, "/orgs/"+org+"/network.dimo.org.tag/fleet", bob, nil)
			require.Equal(t, http.StatusForbidden, status, body)

			// Roles from the org to Alice and Bob, keyed by fresh TIDs via POST.
			fleet := delegation.Covers{Tag: "at://" + org + "/network.dimo.org.tag/fleet"}
			roleURI := h.grantRole(org, roleRecord(org, alice, fleet, "delegation:create", "tag:write", "telemetry:read"))
			_, _, roleKey, err := delegation.ParseURI(roleURI)
			require.NoError(t, err)
			require.NoError(t, repo.ValidateTID(roleKey))
			h.grantRole(org, roleRecord(org, bob, fleet, "delegation:create", delegation.AbilityOrgRead))

			// Alice updates the tag. Same key, so an update commit.
			status, body = h.do(http.MethodPut, "/orgs/"+org+"/network.dimo.org.tag/fleet", alice, `{"name":"Fleet","description":"Every car"}`)
			require.Equal(t, http.StatusOK, status, body)
			assert.Equal(t, "update", body["op"])

			status, body = h.do(http.MethodGet, "/orgs/"+org+"/network.dimo.org.tag/fleet", bob, nil)
			require.Equal(t, http.StatusOK, status, body)
			assert.Equal(t, alice, body["committedBy"])
			assert.Equal(t, map[string]any{"name": "Fleet", "description": "Every car"}, body["record"])
			assert.Nil(t, body["tombstone"])

			// A delegation by Alice under a stable key, as a booking service would.
			grant := delegationRecord(org, map[string]any{"dimo:createdBy": alice})
			status, body = h.do(http.MethodPut, "/orgs/"+org+"/network.dimo.delegation/booking:42:renter", alice, grant)
			require.Equal(t, http.StatusCreated, status, body)

			// Memberships, custody and the control opening.
			joined := time.Date(2026, 3, 1, 0, 0, 0, 0, time.UTC)
			membership := map[string]any{"tag": "at://" + org + "/network.dimo.org.tag/fleet", "vehicle": "did:dimo:veh1", "joinedAt": ts(joined)}
			status, body = h.do(http.MethodPost, "/orgs/"+org+"/network.dimo.org.tagMembership", alice, membership)
			require.Equal(t, http.StatusCreated, status, body)

			custody := map[string]any{"vehicle": "did:dimo:veh1", "holder": "did:dimo:renter", "from": ts(joined.Add(time.Hour))}
			status, body = h.do(http.MethodPost, "/orgs/"+org+"/network.dimo.org.custody", alice, custody)
			require.Equal(t, http.StatusCreated, status, body)

			salt, err := control.NewSalt()
			require.NoError(t, err)
			opening := control.Opening{Controller: org, Era: 0, Salt: salt}
			status, body = h.do(http.MethodPut, "/orgs/"+org+"/network.dimo.org.vehicleControl/did:dimo:veh1", org, opening)
			require.Equal(t, http.StatusCreated, status, body)

			// Listing shows live records in key order; the log route is not a collection.
			status, body = h.do(http.MethodGet, "/orgs/"+org+"/network.dimo.org.tag", bob, nil)
			require.Equal(t, http.StatusOK, status, body)
			assert.Len(t, body["records"], 1)

			// Bob tombstones the grant; it is gone from listings but still readable.
			status, body = h.do(http.MethodDelete, "/orgs/"+org+"/network.dimo.delegation/booking:42:renter", bob, nil)
			require.Equal(t, http.StatusOK, status, body)
			assert.Equal(t, "tombstone", body["op"])
			status, body = h.do(http.MethodDelete, "/orgs/"+org+"/network.dimo.delegation/booking:42:renter", bob, nil)
			assert.Equal(t, http.StatusConflict, status, body)
			status, body = h.do(http.MethodDelete, "/orgs/"+org+"/network.dimo.delegation/never", bob, nil)
			assert.Equal(t, http.StatusNotFound, status, body)

			status, body = h.do(http.MethodGet, "/orgs/"+org+"/network.dimo.delegation/booking:42:renter", alice, nil)
			assert.Equal(t, http.StatusGone, status, body)
			assert.Equal(t, alice, body["committedBy"])
			tomb := body["tombstone"].(map[string]any)
			assert.Equal(t, bob, tomb["by"])
			status, body = h.do(http.MethodGet, "/orgs/"+org+"/network.dimo.delegation", alice, nil)
			require.Equal(t, http.StatusOK, status, body)
			assert.Empty(t, body["records"])

			// The next compilation brings the key back: a create, not an update.
			status, body = h.do(http.MethodPut, "/orgs/"+org+"/network.dimo.delegation/booking:42:renter", alice, grant)
			require.Equal(t, http.StatusCreated, status, body)
			assert.Equal(t, "create", body["op"])

			// Read the whole log back and verify it offline against #dimo_org.
			// The log carries the openings, so it takes org:admin or the org.
			status, body = h.do(http.MethodGet, "/orgs/"+org+"/commits", bob, nil)
			require.Equal(t, http.StatusForbidden, status, body)
			status, body = h.do(http.MethodGet, "/orgs/"+org+"/commits", org, nil)
			require.Equal(t, http.StatusOK, status, body)
			raw, err := json.Marshal(body["commits"])
			require.NoError(t, err)
			var log []repo.Committed
			require.NoError(t, json.Unmarshal(raw, &log))
			require.Len(t, log, 10)
			heads, err := repo.VerifyLog(org, log, orgKey)
			require.NoError(t, err)
			assert.Equal(t, repo.Head{Seq: 4, Live: true}, heads["network.dimo.org.tag/fleet"])
			assert.Equal(t, repo.Head{Seq: 10, Live: true}, heads["network.dimo.delegation/booking:42:renter"])
			assert.Equal(t, "", log[0].CommittedBy)
			assert.Equal(t, "", log[1].CommittedBy)
			assert.Equal(t, alice, log[3].CommittedBy)
			assert.Equal(t, bob, log[8].CommittedBy)
			assert.Empty(t, log[8].Record)

			// Paging the log.
			status, body = h.do(http.MethodGet, "/orgs/"+org+"/commits?after=8&limit=1", org, nil)
			require.Equal(t, http.StatusOK, status, body)
			assert.Len(t, body["commits"], 1)

			// The head advanced with every commit.
			status, body = h.do(http.MethodGet, "/orgs/"+org, alice, nil)
			require.Equal(t, http.StatusOK, status, body)
			assert.Equal(t, float64(10), body["head"].(map[string]any)["seq"])
			assert.Equal(t, log[9].CID, body["head"].(map[string]any)["cid"])
		})
	}
}

func TestStructuralChecks(t *testing.T) {
	h := newHost(t, store.NewMemoryStore())
	org := newOrgDID()
	const alice = "did:dimo:alice"
	status, body := h.do(http.MethodPost, "/orgs/"+org, org, nil)
	require.Equal(t, http.StatusCreated, status, body)

	base := "/orgs/" + org + "/"
	cases := []struct {
		name, path string
		as         string
		body       any
		want       string
	}{
		{"bad rkey", base + "network.dimo.org.tag/no/slash", alice, `{"name":"x"}`, ""},
		{"reserved rkey", base + "network.dimo.org.tag/..", alice, `{"name":"x"}`, "reserved"},
		{"rkey with space", base + "network.dimo.org.tag/a%20b", alice, `{"name":"x"}`, "not allowed"},
		{"unknown collection", base + "network.dimo.other/x", alice, `{"a":1}`, "unknown collection"},
		{"not an object", base + "network.dimo.org.tag/x", alice, `[1]`, "JSON object"},
		{"not JSON", base + "network.dimo.org.tag/x", alice, `{`, "JSON object"},
		{"unknown field", base + "network.dimo.org.tag/x", alice, `{"name":"x","colour":"red"}`, "unknown field"},
		{"tag without name", base + "network.dimo.org.tag/x", alice, `{"description":"x"}`, "name must not be empty"},
		{"delegation type mismatch", base + "network.dimo.org.role/x", alice, delegationRecord(org, nil), "an ODRL Agreement does not belong in network.dimo.org.role"},
		{"delegation from another org", base + "network.dimo.delegation/x", alice, delegationRecord(org, map[string]any{"assigner": "did:dimo:other"}), "repository"},
		{"delegation invalid", base + "network.dimo.delegation/x", alice, delegationRecord(org, map[string]any{"permission": []map[string]any{permission("at://" + org + "/network.dimo.org.tag/fleet")}}), "abilities must not be empty"},
		{"createdBy contradicts member", base + "network.dimo.delegation/x", alice, delegationRecord(org, map[string]any{"dimo:createdBy": "did:dimo:bob"}), "createdBy claims did:dimo:bob but the write is by did:dimo:alice"},
		{"createdBy contradicts org", base + "network.dimo.delegation/x", org, delegationRecord(org, map[string]any{"dimo:createdBy": alice}), "the write is by the org itself"},
		{"delegation in the record shape", base + "network.dimo.delegation/x", alice,
			map[string]any{"$type": delegation.TypeDelegation, "from": org, "to": "did:dimo:fordcredit"}, "not an ODRL policy"},
		{"delegation offered, not agreed", base + "network.dimo.delegation/x", alice, delegationRecord(org, map[string]any{"@type": odrl.TypeOffer}), "grants nothing"},
		{"delegation with an unknown term", base + "network.dimo.delegation/x", alice, delegationRecord(org, map[string]any{"dimo:maxSpeed": 120}), "unknown field"},
		{"delegation claiming to live elsewhere", base + "network.dimo.delegation/x", alice,
			delegationRecord(org, map[string]any{"uid": "at://" + org + "/network.dimo.delegation/y"}), "uid is"},
		{"membership in another org's tag", base + "network.dimo.org.tagMembership/x", alice,
			map[string]any{"tag": "at://did:dimo:other/network.dimo.org.tag/fleet", "vehicle": "did:dimo:v", "joinedAt": ts(time.Now())}, "belongs to did:dimo:other"},
		{"membership leaves before joining", base + "network.dimo.org.tagMembership/x", alice,
			map[string]any{"tag": "at://" + org + "/network.dimo.org.tag/fleet", "vehicle": "did:dimo:v", "joinedAt": ts(time.Now()), "leftAt": ts(time.Now().Add(-time.Hour))}, "leftAt must be after"},
		{"custody without holder", base + "network.dimo.org.custody/x", alice, map[string]any{"vehicle": "did:dimo:v", "from": ts(time.Now())}, "holder must be a DID"},
		{"opening for another controller", base + "network.dimo.org.vehicleControl/did:dimo:v", org,
			control.Opening{Controller: "did:dimo:other", Salt: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"}, "names controller"},
		{"opening keyed by something else", base + "network.dimo.org.vehicleControl/veh1", org,
			control.Opening{Controller: org, Salt: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"}, "must be the vehicle DID"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			status, body := h.do(http.MethodPut, tc.path, tc.as, tc.body)
			if tc.want == "" {
				// A slash in the key does not even route to the record handler.
				assert.NotEqual(t, http.StatusCreated, status, body)
				return
			}
			require.Equal(t, http.StatusBadRequest, status, body)
			assert.Contains(t, body["error"], tc.want)
		})
	}

	// createdBy that agrees with the witnessed author is fine, and so is an
	// org writing under its own name.
	h.grantRole(org, roleRecord(org, alice, delegation.Covers{Tag: "at://" + org + "/network.dimo.org.tag/fleet"}, "delegation:create", "telemetry:read"))
	status, body = h.do(http.MethodPut, base+"network.dimo.delegation/ok1", alice, delegationRecord(org, map[string]any{"dimo:createdBy": alice}))
	assert.Equal(t, http.StatusCreated, status, body)
	status, body = h.do(http.MethodPut, base+"network.dimo.delegation/ok2", org, delegationRecord(org, map[string]any{"dimo:createdBy": org}))
	assert.Equal(t, http.StatusCreated, status, body)

	// What was committed is the ODRL policy, identified by where it lives.
	status, body = h.do(http.MethodGet, base+"network.dimo.delegation/ok1", alice, nil)
	require.Equal(t, http.StatusOK, status, body)
	stored := body["record"].(map[string]any)
	assert.Equal(t, odrl.TypeAgreement, stored["@type"])
	assert.Equal(t, "at://"+org+"/network.dimo.delegation/ok1", stored["uid"])
	assert.Equal(t, "did:dimo:fordcredit", stored["assignee"])

	// Nothing invalid reached the log.
	status, body = h.do(http.MethodGet, "/orgs/"+org+"/commits", org, nil)
	require.Equal(t, http.StatusOK, status, body)
	assert.Len(t, body["commits"], 3)
}

func TestRegisterWithSuppliedKey(t *testing.T) {
	h := newHost(t, store.NewMemoryStore())
	org := newOrgDID()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	der, err := x509.MarshalPKCS8PrivateKey(key)
	require.NoError(t, err)
	want, err := dimocrypto.EncodeDIDKey(&key.PublicKey)
	require.NoError(t, err)

	status, body := h.do(http.MethodPost, "/orgs/"+org, org, map[string]string{"privateKey": base64.StdEncoding.EncodeToString(der)})
	require.Equal(t, http.StatusCreated, status, body)
	assert.Equal(t, want, body["key"])

	status, body = h.do(http.MethodPut, "/orgs/"+org+"/network.dimo.org.tag/fleet", org, `{"name":"Fleet"}`)
	require.Equal(t, http.StatusCreated, status, body)
	status, body = h.do(http.MethodGet, "/orgs/"+org+"/commits", org, nil)
	require.Equal(t, http.StatusOK, status, body)
	raw, _ := json.Marshal(body["commits"])
	var log []repo.Committed
	require.NoError(t, json.Unmarshal(raw, &log))
	_, err = repo.VerifyLog(org, log, want)
	require.NoError(t, err)

	status, body = h.do(http.MethodPost, "/orgs/"+newOrgDID(), "did:dimo:x", map[string]string{"privateKey": "nope"})
	assert.Equal(t, http.StatusForbidden, status, body)
	other := newOrgDID()
	status, body = h.do(http.MethodPost, "/orgs/"+other, other, map[string]string{"privateKey": "nope"})
	assert.Equal(t, http.StatusBadRequest, status, body)
}

// Org keys are sealed in the store; a signer built fresh over the same store
// and master key signs with the same key, and one with another master key
// cannot open them.
func TestSealedKeysSurviveRestart(t *testing.T) {
	st := store.NewMemoryStore()
	master := make([]byte, MasterKeyLen)
	_, err := rand.Read(master)
	require.NoError(t, err)
	sealer, err := NewSealer(master)
	require.NoError(t, err)
	ctx := t.Context()

	signer := NewLocalSigner(st, sealer)
	org := newOrgDID()
	didKey, err := signer.Register(ctx, org, nil)
	require.NoError(t, err)

	again := NewLocalSigner(st, sealer)
	got, err := again.PublicKey(ctx, org)
	require.NoError(t, err)
	assert.Equal(t, didKey, got)
	sig, err := again.Sign(ctx, org, []byte("hello"))
	require.NoError(t, err)
	require.NoError(t, dimocrypto.VerifyWithDIDKey(didKey, []byte("hello"), sig))

	wrong, err := NewEphemeralSealer()
	require.NoError(t, err)
	_, err = NewLocalSigner(st, wrong).PublicKey(ctx, org)
	assert.ErrorContains(t, err, "unseal")

	// The org DID is bound into the seal.
	o, err := st.GetOrg(ctx, org)
	require.NoError(t, err)
	_, err = sealer.Open("did:dimo:other", o.KeyEnc)
	assert.Error(t, err)
}

func TestConcurrentWritesKeepOneChain(t *testing.T) {
	for name, st := range stores(t) {
		t.Run(name, func(t *testing.T) {
			h := newHost(t, st)
			org := newOrgDID()
			status, body := h.do(http.MethodPost, "/orgs/"+org, org, nil)
			require.Equal(t, http.StatusCreated, status, body)
			orgKey := body["key"].(string)
			h.grantRole(org, roleRecord(org, "did:dimo:alice", delegation.Covers{Inherit: true}, "tag:write"))

			const writers, perWriter = 8, 10
			var wg sync.WaitGroup
			for w := range writers {
				wg.Add(1)
				go func() {
					defer wg.Done()
					for i := range perWriter {
						path := fmt.Sprintf("/orgs/%s/network.dimo.org.tag/w%d-%d", org, w, i)
						status, body := h.do(http.MethodPut, path, "did:dimo:alice", `{"name":"x"}`)
						assert.Equal(t, http.StatusCreated, status, body)
					}
				}()
			}
			wg.Wait()

			log, err := h.repo.Log(t.Context(), org, 0, 0)
			require.NoError(t, err)
			require.Len(t, log, writers*perWriter+1)
			heads, err := repo.VerifyLog(org, log, orgKey)
			require.NoError(t, err)
			assert.Len(t, heads, writers*perWriter+1)
		})
	}
}

// hostAudience is the aud the test host requires of identity tokens.
const hostAudience = "https://orghost.test"

func TestJWKSAuthenticator(t *testing.T) {
	iss := newIssuer(t)
	auth, err := NewJWKSAuthenticator(iss.jwks(), "https://auth.test", hostAudience)
	require.NoError(t, err)
	ctx := t.Context()
	now := time.Now().Unix()
	good := iss.claims("did:dimo:alice", "write read")
	const path = "/orgs/did:dimo:org/network.dimo.org.tag"

	// cred presents token for a POST to path with a fresh proof from key.
	cred := func(token string, key *dpop.Key) Credentials {
		proof, err := key.Proof(http.MethodPost, hostAudience+path, token, time.Now())
		require.NoError(t, err)
		return Credentials{Authorization: "DPoP " + token, Proof: proof, Method: http.MethodPost, Path: path}
	}

	id, err := auth.Authenticate(ctx, cred(iss.token(t, good), iss.holder))
	require.NoError(t, err)
	assert.Equal(t, Identity{DID: "did:dimo:alice", Scopes: []string{"read", "write"}}, id)

	with := func(k string, v any) map[string]any {
		out := map[string]any{}
		for kk, vv := range good {
			out[kk] = vv
		}
		if v == nil {
			delete(out, k)
		} else {
			out[k] = v
		}
		return out
	}

	// aud may be an array naming this host among others.
	_, err = auth.Authenticate(ctx, cred(iss.token(t, with("aud", []string{"dq", hostAudience})), iss.holder))
	require.NoError(t, err)

	_, err = NewJWKSAuthenticator(iss.jwks(), "https://auth.test", "")
	require.Error(t, err, "an authenticator without an audience accepts every relying party's tokens")

	other := newIssuer(t)
	stranger, err := dpop.GenerateKey()
	require.NoError(t, err)
	token := iss.token(t, good)
	replayed := cred(token, iss.holder)
	_, err = auth.Authenticate(ctx, replayed)
	require.NoError(t, err)
	tokenCase := func(claims map[string]any) Credentials { return cred(iss.token(t, claims), iss.holder) }
	for name, c := range map[string]Credentials{
		"no header":      {Method: http.MethodPost, Path: path},
		"not DPoP":       {Authorization: "Basic abc", Method: http.MethodPost, Path: path},
		"bearer":         func() Credentials { c := cred(token, iss.holder); c.Authorization = "Bearer " + token; return c }(),
		"garbage":        {Authorization: "DPoP a.b", Method: http.MethodPost, Path: path},
		"expired":        tokenCase(with("exp", now-120)),
		"no exp":         tokenCase(with("exp", 0)),
		"not yet valid":  tokenCase(with("nbf", now+600)),
		"wrong issuer":   tokenCase(with("iss", "https://evil.test")),
		"no audience":    tokenCase(with("aud", nil)),
		"other audience": tokenCase(with("aud", "dimo")),
		"audience list":  tokenCase(with("aud", []string{"dimo", "dq"})),
		"sub not a DID":  tokenCase(with("sub", "0xabc")),
		"no scope":       tokenCase(with("scope", nil)),
		"unknown scope":  tokenCase(with("scope", "read admin")),
		"unbound":        tokenCase(with("cnf", nil)),
		"other key":      cred(other.token(t, good), iss.holder),
		"unknown kid":    cred(iss.tokenWithHeader(t, map[string]any{"alg": "RS256", "kid": "k2"}, good), iss.holder),
		"alg none":       cred(iss.tokenWithHeader(t, map[string]any{"alg": "none", "kid": iss.kid}, good), iss.holder),
		"alg HS256":      cred(iss.tokenWithHeader(t, map[string]any{"alg": "HS256", "kid": iss.kid}, good), iss.holder),
		"tampered claim": cred(tamperClaims(t, token, with("sub", "did:dimo:mallory")), iss.holder),
		// The token is fine; the proof is what fails.
		"no proof":        func() Credentials { c := cred(token, iss.holder); c.Proof = ""; return c }(),
		"copied token":    cred(token, stranger),
		"replayed proof":  replayed,
		"proof for a GET": func() Credentials { c := cred(token, iss.holder); c.Method = http.MethodGet; return c }(),
		"proof for elsewhere": func() Credentials {
			c := cred(token, iss.holder)
			c.Path = "/orgs/did:dimo:org/pending/1/approve"
			return c
		}(),
		"proof for another token": func() Credentials {
			c := cred(iss.token(t, with("jti", "other")), iss.holder)
			c.Authorization = "DPoP " + token
			return c
		}(),
	} {
		t.Run(name, func(t *testing.T) {
			_, err := auth.Authenticate(ctx, c)
			assert.ErrorIs(t, err, ErrUnauthenticated)
		})
	}

	// Leeway: a token a few seconds past exp still passes.
	_, err = auth.Authenticate(ctx, tokenCase(with("exp", now-5)))
	assert.NoError(t, err)
}

// TestReplayCacheFull: a full DPoP replay cache is this host's capacity, not
// the caller's credentials, so a sound request is answered 503 with
// Retry-After and no WWW-Authenticate challenge, bad credentials are still 401,
// and the request passes once there is room.
func TestReplayCacheFull(t *testing.T) {
	h := newHost(t, store.NewMemoryStore())
	org := newOrgDID()
	h.auth.proofs.MaxReplayEntries = 1
	// The register request's proof fills the cache.
	status, body := h.do(http.MethodPost, "/orgs/"+org, org, nil)
	require.Equal(t, http.StatusCreated, status, body)

	path := "/orgs/" + org
	token := h.issuer.identity(t, org)
	proof, err := h.issuer.holder.Proof(http.MethodGet, hostAudience+path, token, time.Now())
	require.NoError(t, err)
	_, err = h.auth.Authenticate(t.Context(), Credentials{Authorization: "DPoP " + token, Proof: proof, Method: http.MethodGet, Path: path})
	require.ErrorIs(t, err, ErrUnavailable)
	assert.NotErrorIs(t, err, ErrUnauthenticated)

	req := httptest.NewRequest(http.MethodGet, path, nil)
	require.NoError(t, h.issuer.present(req, h.issuer.identity(t, org)))
	resp, err := h.app.Test(req, -1)
	require.NoError(t, err)
	defer func() { _ = resp.Body.Close() }()
	assert.Equal(t, http.StatusServiceUnavailable, resp.StatusCode)
	assert.Equal(t, "1", resp.Header.Get(fiber.HeaderRetryAfter))
	assert.Empty(t, resp.Header.Get(fiber.HeaderWWWAuthenticate), "not an authentication failure")
	var out map[string]any
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&out))
	assert.Equal(t, "temporarily_unavailable", out["code"])

	// Bad credentials are still 401: the token is checked before the proof.
	status, body = h.do(http.MethodGet, path, "", nil)
	assert.Equal(t, http.StatusUnauthorized, status, body)
	assert.Equal(t, "invalid_token", body["code"])

	// With room again the same request passes.
	h.auth.proofs.MaxReplayEntries = 2
	status, body = h.do(http.MethodGet, path, org, nil)
	assert.Equal(t, http.StatusOK, status, body)
}

// TestScopes: each route takes only tokens carrying its scope, and refuses
// the rest with 403 insufficient_scope before looking at anything else.
func TestScopes(t *testing.T) {
	h := newHost(t, store.NewMemoryStore())
	org := newOrgDID()
	status, body := h.do(http.MethodPost, "/orgs/"+org, org, nil)
	require.Equal(t, http.StatusCreated, status, body)

	send := func(method, path, scope string, body any) (int, map[string]any) {
		t.Helper()
		var reader io.Reader
		if body != nil {
			data, err := json.Marshal(body)
			require.NoError(t, err)
			reader = bytes.NewReader(data)
		}
		req := httptest.NewRequest(method, path, reader)
		req.Header.Set("Content-Type", "application/json")
		require.NoError(t, h.issuer.present(req, h.issuer.scoped(t, org, scope)))
		resp, err := h.app.Test(req, -1)
		require.NoError(t, err)
		defer func() { _ = resp.Body.Close() }()
		var out map[string]any
		_ = json.NewDecoder(resp.Body).Decode(&out)
		return resp.StatusCode, out
	}
	tags := "/orgs/" + org + "/network.dimo.org.tag"
	tag := map[string]string{"name": "fleet"}

	// A read token reads, and that is all.
	status, _ = send(http.MethodGet, tags, "read", nil)
	assert.Equal(t, http.StatusOK, status)
	status, _ = send(http.MethodGet, "/me/delegations", "read", nil)
	assert.Equal(t, http.StatusOK, status)
	status, body = send(http.MethodPut, tags+"/fleet", "read", tag)
	assert.Equal(t, http.StatusForbidden, status)
	assert.Equal(t, "insufficient_scope", body["code"])
	assert.Equal(t, "write", body["scope"])

	// A write token writes but does not read, approve or register.
	status, body = send(http.MethodPut, tags+"/fleet", "write", tag)
	assert.Equal(t, http.StatusCreated, status, body)
	status, _ = send(http.MethodGet, tags, "write", nil)
	assert.Equal(t, http.StatusForbidden, status)
	for _, path := range []string{"/orgs/" + org + "/pending/1/approve", "/orgs/" + org + "/revoke-authored-by", "/orgs/" + org} {
		status, body = send(http.MethodPost, path, "read write", map[string]any{})
		assert.Equal(t, http.StatusForbidden, status, path)
		assert.Equal(t, "approve", body["scope"], path)
	}
	status, body = send(http.MethodDelete, tags+"/fleet", "write", nil)
	assert.Equal(t, http.StatusOK, status, body)

	// An approve token gets past the scope check on the routes behind it, and
	// writes nothing else.
	status, body = send(http.MethodPost, "/orgs/"+org+"/pending/nope/approve", "approve", map[string]any{})
	assert.NotEqual(t, "insufficient_scope", body["code"], status)
	status, _ = send(http.MethodPut, tags+"/fleet", "approve", tag)
	assert.Equal(t, http.StatusForbidden, status)
}

func tamperClaims(t *testing.T, token string, claims map[string]any) string {
	t.Helper()
	parts := bytes.Split([]byte(token), []byte("."))
	require.Len(t, parts, 3)
	c, _ := json.Marshal(claims)
	parts[1] = []byte(base64.RawURLEncoding.EncodeToString(c))
	return string(bytes.Join(parts, []byte(".")))
}
