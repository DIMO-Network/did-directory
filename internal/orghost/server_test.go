package orghost

import (
	"bytes"
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
	"github.com/DIMO-Network/did-directory/pkg/control"
	"github.com/DIMO-Network/did-directory/pkg/delegation"
	"github.com/DIMO-Network/did-directory/pkg/repo"
	"github.com/gofiber/fiber/v2"
	"github.com/rs/zerolog"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// issuer stands in for dauth: an RS256 key published as a JWKS, minting
// identity tokens whose sub is a DID.
type issuer struct {
	key *rsa.PrivateKey
	kid string
}

func newIssuer(t *testing.T) *issuer {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	return &issuer{key: key, kid: "k1"}
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

// identity mints a fresh token for did, valid for an hour.
func (i *issuer) identity(t *testing.T, did string) string {
	now := time.Now().Unix()
	return i.token(t, map[string]any{"iss": "https://auth.test", "sub": did, "iat": now, "nbf": now, "exp": now + 3600})
}

type host struct {
	t      *testing.T
	app    *fiber.App
	issuer *issuer
	repo   *Repository
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

func newHost(t *testing.T, st store.Store) *host {
	t.Helper()
	iss := newIssuer(t)
	auth, err := NewJWKSAuthenticator(iss.jwks(), "https://auth.test")
	require.NoError(t, err)
	sealer, err := NewEphemeralSealer()
	require.NoError(t, err)
	r := &Repository{Store: st, Signer: NewLocalSigner(st, sealer)}
	return &host{t: t, app: New(r, auth, 50, zerolog.Nop()), issuer: iss, repo: r}
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
		req.Header.Set("Authorization", "Bearer "+h.issuer.identity(h.t, as))
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

var orgSeq int

func newOrgDID() string {
	orgSeq++
	return fmt.Sprintf("did:dimo:org%d%d", time.Now().UnixNano(), orgSeq)
}

func ts(t time.Time) string { return t.UTC().Format(time.RFC3339) }

func delegationRecord(org string, extra map[string]any) map[string]any {
	rec := map[string]any{
		"$type":      delegation.TypeDelegation,
		"from":       org,
		"to":         "did:dimo:fordcredit",
		"basis":      []string{},
		"covers":     map[string]any{"tag": "at://" + org + "/network.dimo.org.tag/fleet"},
		"abilities":  []string{"telemetry:read"},
		"dataWindow": map[string]any{"from": ts(time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC))},
		"validity":   map[string]any{"from": ts(time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC))},
		"redelegate": map[string]any{"mode": "none"},
		"createdAt":  ts(time.Now()),
	}
	for k, v := range extra {
		rec[k] = v
	}
	return rec
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
			pub, err := dimocrypto.DecodeDIDKey(orgKey)
			require.NoError(t, err)
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

			// Alice updates it. Same key, so an update commit.
			status, body = h.do(http.MethodPut, "/orgs/"+org+"/network.dimo.org.tag/fleet", alice, `{"name":"Fleet","description":"Every car"}`)
			require.Equal(t, http.StatusOK, status, body)
			assert.Equal(t, "update", body["op"])

			status, body = h.do(http.MethodGet, "/orgs/"+org+"/network.dimo.org.tag/fleet", bob, nil)
			require.Equal(t, http.StatusOK, status, body)
			assert.Equal(t, alice, body["committedBy"])
			assert.Equal(t, map[string]any{"name": "Fleet", "description": "Every car"}, body["record"])
			assert.Nil(t, body["tombstone"])

			// A role from the org to Alice, keyed by a fresh TID via POST.
			role := map[string]any{
				"$type": delegation.TypeRole, "from": org, "to": alice, "basis": []string{},
				"covers":     map[string]any{"tag": "at://" + org + "/network.dimo.org.tag/fleet"},
				"abilities":  []string{"delegation:create", "tag:write", "telemetry:read"},
				"validity":   map[string]any{"from": ts(time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC))},
				"redelegate": map[string]any{"mode": "none"}, "createdAt": ts(time.Now()),
			}
			status, body = h.do(http.MethodPost, "/orgs/"+org+"/network.dimo.org.role", org, role)
			require.Equal(t, http.StatusCreated, status, body)
			_, _, roleKey, err := delegation.ParseURI(body["uri"].(string))
			require.NoError(t, err)
			require.NoError(t, repo.ValidateTID(roleKey))

			// A delegation by Alice under a stable key, as a booking service would.
			grant := delegationRecord(org, map[string]any{"createdBy": alice})
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
			status, body = h.do(http.MethodGet, "/orgs/"+org+"/commits", bob, nil)
			require.Equal(t, http.StatusOK, status, body)
			raw, err := json.Marshal(body["commits"])
			require.NoError(t, err)
			var log []repo.Committed
			require.NoError(t, json.Unmarshal(raw, &log))
			require.Len(t, log, 9)
			heads, err := repo.VerifyLog(org, log, pub)
			require.NoError(t, err)
			assert.Equal(t, repo.Head{Seq: 2, Live: true}, heads["network.dimo.org.tag/fleet"])
			assert.Equal(t, repo.Head{Seq: 9, Live: true}, heads["network.dimo.delegation/booking:42:renter"])
			assert.Equal(t, "", log[0].CommittedBy)
			assert.Equal(t, alice, log[1].CommittedBy)
			assert.Equal(t, bob, log[7].CommittedBy)
			assert.Empty(t, log[7].Record)

			// Paging the log.
			status, body = h.do(http.MethodGet, "/orgs/"+org+"/commits?after=7&limit=1", bob, nil)
			require.Equal(t, http.StatusOK, status, body)
			assert.Len(t, body["commits"], 1)

			// The head advanced with every commit.
			status, body = h.do(http.MethodGet, "/orgs/"+org, alice, nil)
			require.Equal(t, http.StatusOK, status, body)
			assert.Equal(t, float64(9), body["head"].(map[string]any)["seq"])
			assert.Equal(t, log[8].CID, body["head"].(map[string]any)["cid"])
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
		{"delegation type mismatch", base + "network.dimo.org.role/x", alice, delegationRecord(org, nil), "$type is"},
		{"delegation from another org", base + "network.dimo.delegation/x", alice, delegationRecord(org, map[string]any{"from": "did:dimo:other"}), "repository"},
		{"delegation invalid", base + "network.dimo.delegation/x", alice, delegationRecord(org, map[string]any{"abilities": []string{}}), "abilities must not be empty"},
		{"createdBy contradicts member", base + "network.dimo.delegation/x", alice, delegationRecord(org, map[string]any{"createdBy": "did:dimo:bob"}), "createdBy claims did:dimo:bob but the write is by did:dimo:alice"},
		{"createdBy contradicts org", base + "network.dimo.delegation/x", org, delegationRecord(org, map[string]any{"createdBy": alice}), "the write is by the org itself"},
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
	status, body = h.do(http.MethodPut, base+"network.dimo.delegation/ok1", alice, delegationRecord(org, map[string]any{"createdBy": alice}))
	assert.Equal(t, http.StatusCreated, status, body)
	status, body = h.do(http.MethodPut, base+"network.dimo.delegation/ok2", org, delegationRecord(org, map[string]any{"createdBy": org}))
	assert.Equal(t, http.StatusCreated, status, body)

	// Nothing invalid reached the log.
	status, body = h.do(http.MethodGet, "/orgs/"+org+"/commits", alice, nil)
	require.Equal(t, http.StatusOK, status, body)
	assert.Len(t, body["commits"], 2)
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
	_, err = repo.VerifyLog(org, log, &key.PublicKey)
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
			pub, err := dimocrypto.DecodeDIDKey(body["key"].(string))
			require.NoError(t, err)

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
			require.Len(t, log, writers*perWriter)
			heads, err := repo.VerifyLog(org, log, pub)
			require.NoError(t, err)
			assert.Len(t, heads, writers*perWriter)
		})
	}
}

func TestJWKSAuthenticator(t *testing.T) {
	iss := newIssuer(t)
	auth, err := NewJWKSAuthenticator(iss.jwks(), "https://auth.test")
	require.NoError(t, err)
	ctx := t.Context()
	now := time.Now().Unix()
	good := map[string]any{"iss": "https://auth.test", "sub": "did:dimo:alice", "exp": now + 60}

	did, err := auth.Authenticate(ctx, "Bearer "+iss.token(t, good))
	require.NoError(t, err)
	assert.Equal(t, "did:dimo:alice", did)

	with := func(k string, v any) map[string]any {
		out := map[string]any{}
		for kk, vv := range good {
			out[kk] = vv
		}
		out[k] = v
		return out
	}
	other := newIssuer(t)
	for name, header := range map[string]string{
		"no header":      "",
		"not bearer":     "Basic abc",
		"garbage":        "Bearer a.b",
		"expired":        "Bearer " + iss.token(t, with("exp", now-120)),
		"no exp":         "Bearer " + iss.token(t, with("exp", 0)),
		"not yet valid":  "Bearer " + iss.token(t, with("nbf", now+600)),
		"wrong issuer":   "Bearer " + iss.token(t, with("iss", "https://evil.test")),
		"sub not a DID":  "Bearer " + iss.token(t, with("sub", "0xabc")),
		"other key":      "Bearer " + other.token(t, good),
		"unknown kid":    "Bearer " + iss.tokenWithHeader(t, map[string]any{"alg": "RS256", "kid": "k2"}, good),
		"alg none":       "Bearer " + iss.tokenWithHeader(t, map[string]any{"alg": "none", "kid": iss.kid}, good),
		"alg HS256":      "Bearer " + iss.tokenWithHeader(t, map[string]any{"alg": "HS256", "kid": iss.kid}, good),
		"tampered claim": "Bearer " + tamperClaims(t, iss.token(t, good), with("sub", "did:dimo:mallory")),
	} {
		t.Run(name, func(t *testing.T) {
			_, err := auth.Authenticate(ctx, header)
			assert.ErrorIs(t, err, ErrUnauthenticated)
		})
	}

	// Leeway: a token a few seconds past exp still passes.
	_, err = auth.Authenticate(ctx, "Bearer "+iss.token(t, with("exp", now-5)))
	assert.NoError(t, err)
}

func tamperClaims(t *testing.T, token string, claims map[string]any) string {
	t.Helper()
	parts := bytes.Split([]byte(token), []byte("."))
	require.Len(t, parts, 3)
	c, _ := json.Marshal(claims)
	parts[1] = []byte(base64.RawURLEncoding.EncodeToString(c))
	return string(bytes.Join(parts, []byte(".")))
}
