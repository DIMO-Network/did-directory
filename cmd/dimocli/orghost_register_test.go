package main

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/DIMO-Network/did-directory/pkg/client"
	"github.com/DIMO-Network/did-directory/pkg/didkey"
	"github.com/DIMO-Network/did-directory/pkg/dpop"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// audienceDauth is dauth's sign-in for any DID whose challenge pub signs: the
// challenge names the audience and scope asked for, and the token carries
// them, bound to the challenge's DPoP key.
type audienceDauth struct {
	url    string
	mu     sync.Mutex
	scopes []string
}

func newAudienceDauth(t *testing.T, pub *didkey.PublicKey) *audienceDauth {
	t.Helper()
	d := &audienceDauth{}
	verifier := dpop.NewVerifier()
	var did, jkt, text, scope string
	var aud []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		d.mu.Lock()
		defer d.mu.Unlock()
		switch r.URL.Path {
		case "/signin/challenge":
			var req struct {
				DID, Scope, JKT string
				Audience        []string
			}
			_ = json.NewDecoder(r.Body).Decode(&req)
			did, jkt, scope, aud = req.DID, req.JKT, req.Scope, req.Audience
			text = fmt.Sprintf("dauth.test wants you to sign in as\n%s\n\nFor: %s\nScope: %s\nKey: %s\n\nNonce: n1\nIssued At: 2026-11-22T00:00:00Z\nExpiration Time: 2026-11-22T00:05:00Z",
				req.DID, strings.Join(req.Audience, ", "), req.Scope, req.JKT)
			_ = json.NewEncoder(w).Encode(map[string]any{"challenge": text, "nonce": "n1"})
		case "/signin/token":
			var body struct{ Nonce, Signature string }
			_ = json.NewDecoder(r.Body).Decode(&body)
			got, err := verifier.Verify(r.Header.Get(dpop.HeaderName), http.MethodPost, d.url+"/signin/token", "")
			if err != nil || got != jkt || pub.Verify([]byte(text), body.Signature) != nil {
				http.Error(w, `{"error":"invalid_grant"}`, http.StatusUnauthorized)
				return
			}
			d.scopes = append(d.scopes, scope)
			claims, _ := json.Marshal(map[string]any{"sub": did, "aud": aud, "scope": scope, "cnf": map[string]string{"jkt": jkt}})
			tok := "e30." + base64.RawURLEncoding.EncodeToString(claims) + ".sig"
			_ = json.NewEncoder(w).Encode(map[string]any{"token": tok, "token_type": "DPoP", "expires_in": 600})
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(srv.Close)
	d.url = srv.URL
	return d
}

// fakeOrgHost registers orgs as the org host does: the token's sub must be
// the org, its scope must hold approve (read for GET), and every request must
// be DPoP-proved by the token's key, each proof once. unavailable answers that
// many POSTs 503 with Retry-After first.
type fakeOrgHost struct {
	url         string
	key         string
	status      int
	unavailable int
	mu          sync.Mutex
	registers   []string
	posts, gets int
	registered  map[string]bool
}

func newFakeOrgHost(t *testing.T) *fakeOrgHost {
	t.Helper()
	_, hostKey, err := newKey()
	require.NoError(t, err)
	h := &fakeOrgHost{key: hostKey, status: http.StatusCreated, registered: map[string]bool{}}
	verifier := dpop.NewVerifier()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h.mu.Lock()
		defer h.mu.Unlock()
		org, ok := strings.CutPrefix(r.URL.Path, "/orgs/")
		if !ok {
			http.NotFound(w, r)
			return
		}
		tok, _ := strings.CutPrefix(r.Header.Get("Authorization"), "DPoP ")
		claims, err := jwtClaims(tok)
		require.NoError(t, err)
		var c struct {
			Sub, Scope string
			Cnf        struct{ Jkt string }
		}
		require.NoError(t, json.Unmarshal(claims, &c))
		scopes := strings.Fields(c.Scope)
		jkt, err := verifier.Verify(r.Header.Get(dpop.HeaderName), r.Method, h.url+r.URL.Path, tok)
		if err != nil || jkt != c.Cnf.Jkt || c.Sub != org {
			http.Error(w, `{"error":"invalid_token"}`, http.StatusUnauthorized)
			return
		}
		switch r.Method {
		case http.MethodGet:
			h.gets++
			if !slices.Contains(scopes, "read") || !h.registered[org] {
				http.Error(w, `{"error":"not found"}`, http.StatusNotFound)
				return
			}
			_ = json.NewEncoder(w).Encode(map[string]any{"did": org, "key": h.key, "head": map[string]any{"seq": 0}})
		case http.MethodPost:
			h.posts++
			if !slices.Contains(scopes, "approve") {
				http.Error(w, `{"error":"insufficient_scope"}`, http.StatusForbidden)
				return
			}
			if h.unavailable > 0 {
				h.unavailable--
				w.Header().Set("Retry-After", "2")
				http.Error(w, `{"error":"the register did not finish, retry shortly","code":"temporarily_unavailable"}`, http.StatusServiceUnavailable)
				return
			}
			if h.registered[org] {
				http.Error(w, `{"error":"org is already registered on this host"}`, http.StatusConflict)
				return
			}
			h.registers = append(h.registers, org)
			w.WriteHeader(h.status)
			if h.status == http.StatusCreated {
				h.registered[org] = true
				_ = json.NewEncoder(w).Encode(map[string]string{"did": org, "key": h.key})
				return
			}
			_, _ = w.Write([]byte(`{"error":"the org's DID does not name this host as #dimo_org_host"}`))
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(srv.Close)
	h.url = srv.URL
	return h
}

// R7-F8: create --org-host makes the DID first, with the host entry and no
// #dimo_org, registers it on the host as the org, and then publishes the key
// the host returns: under ORG_SIGNER=kms the host makes its own key, so a
// locally generated #dimo_org would be one nobody serving the org holds.
func TestCreate_OrgHostRegistersThenPublishesTheHostKey(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	sg, err := newFileSignerK1()
	require.NoError(t, err)
	pub, err := didkey.Decode(sg.DIDKey())
	require.NoError(t, err)
	dauth := newAudienceDauth(t, pub)
	host := newFakeOrgHost(t)
	c, ops := directoryStub(t)

	var out bytes.Buffer
	derived, err := executeCreate(context.Background(), c, createOptions{Org: true, OrgHost: host.url + "/", Dauth: dauth.url}, sg, &out)
	require.NoError(t, err, out.String())

	require.Len(t, *ops, 2, "the genesis, then the update publishing the host's key")
	genesis, update := (*ops)[0], (*ops)[1]
	assert.Equal(t, host.url, genesis.Services[OrgHostServiceID].Endpoint, "published without the trailing slash")
	assert.NotContains(t, genesis.VerificationMethods, OrgKeyID, "no key is published before the host makes one")
	verifyOp(t, sg.DIDKey(), genesis)

	assert.Equal(t, []string{derived}, host.registers)
	require.Len(t, dauth.scopes, 1, "one sign-in")
	assert.Contains(t, strings.Fields(dauth.scopes[0]), "approve", "register takes an approve token")
	assert.Equal(t, host.key, update.VerificationMethods[OrgKeyID])
	assert.Equal(t, sg.DIDKey(), update.VerificationMethods["signing"])
	assert.Equal(t, genesis.Services, update.Services)
	require.NotNil(t, update.Prev)
	assert.Equal(t, "bafyfake", *update.Prev, "the update follows the genesis")
	verifyOp(t, sg.DIDKey(), update)
	assert.Contains(t, out.String(), host.key)

	_, err = os.Stat(filepath.Join(home, ".dimo", "keys", strings.TrimPrefix(derived, "did:dimo:")+".org.json"))
	assert.True(t, os.IsNotExist(err), "no #dimo_org private key is made or kept")
}

// A register the host refuses leaves the DID created and says how to finish.
func TestCreate_OrgHostRegisterRefusedSaysHowToFinish(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	sg, err := newFileSignerK1()
	require.NoError(t, err)
	pub, err := didkey.Decode(sg.DIDKey())
	require.NoError(t, err)
	dauth := newAudienceDauth(t, pub)
	host := newFakeOrgHost(t)
	host.status = http.StatusForbidden
	c, ops := directoryStub(t)

	_, err = executeCreate(context.Background(), c, createOptions{OrgHost: host.url, Dauth: dauth.url}, sg, &bytes.Buffer{})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "does not name this host")
	assert.Contains(t, err.Error(), "dimocli register --did")
	assert.Len(t, *ops, 1, "the genesis only")
}

// --org-key still publishes a key the host already holds, with no register.
func TestCreate_OrgHostWithOrgKeyDoesNotRegister(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	sg, err := newFileSignerK1()
	require.NoError(t, err)
	_, given, err := newKey()
	require.NoError(t, err)
	c, ops := directoryStub(t)
	_, err = executeCreate(context.Background(), c, createOptions{OrgHost: "http://127.0.0.1:1", OrgKey: given, Dauth: "http://127.0.0.1:1"}, sg, &bytes.Buffer{})
	require.NoError(t, err)
	require.Len(t, *ops, 1)
	assert.Equal(t, given, (*ops)[0].VerificationMethods[OrgKeyID])
}

// noWait stands in for the Retry-After sleep and records what was asked.
func noWait(t *testing.T) *[]time.Duration {
	t.Helper()
	var waits []time.Duration
	old := retryWait
	retryWait = func(_ context.Context, d time.Duration) error {
		waits = append(waits, d)
		return nil
	}
	t.Cleanup(func() { retryWait = old })
	return &waits
}

// Fix round 1, item 4: a 503 from the host (a KMS register to retry) is
// retried once, after its Retry-After, with a fresh proof.
func TestRegisterOnHost_RetriesOnceOn503(t *testing.T) {
	sg, err := newFileSignerK1()
	require.NoError(t, err)
	pub, err := didkey.Decode(sg.DIDKey())
	require.NoError(t, err)
	dauth := newAudienceDauth(t, pub)
	const org = "did:dimo:retry"

	waits := noWait(t)
	host := newFakeOrgHost(t)
	host.unavailable = 1
	key, err := registerOnHost(context.Background(), dauth.url, host.url, org, sg)
	require.NoError(t, err)
	assert.Equal(t, host.key, key)
	assert.Equal(t, 2, host.posts)
	assert.Equal(t, []time.Duration{2 * time.Second}, *waits)

	// Only once.
	host = newFakeOrgHost(t)
	host.unavailable = 2
	_, err = registerOnHost(context.Background(), dauth.url, host.url, "did:dimo:retry2", sg)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "503")
	assert.Equal(t, 2, host.posts)
}

// Fix round 1, item 4: an org already on the host (a run whose publish failed)
// answers 409, and the CLI reads the key the host holds instead.
func TestRegisterOnHost_ConflictReadsTheKey(t *testing.T) {
	sg, err := newFileSignerK1()
	require.NoError(t, err)
	pub, err := didkey.Decode(sg.DIDKey())
	require.NoError(t, err)
	dauth := newAudienceDauth(t, pub)
	host := newFakeOrgHost(t)
	const org = "did:dimo:again"
	host.registered[org] = true

	key, err := registerOnHost(context.Background(), dauth.url, host.url, org, sg)
	require.NoError(t, err)
	assert.Equal(t, host.key, key)
	assert.Equal(t, 1, host.posts)
	assert.Equal(t, 1, host.gets)
}

// recordingDirectory accepts submissions and serves each DID's audit log back,
// so a command that reads the head after a create sees it. failPost, when
// set, is the one submission (1-based) it refuses.
type recordingDirectory struct {
	mu       sync.Mutex
	logs     map[string][]map[string]any
	posts    int
	failPost int
	ops      []map[string]any
}

func newRecordingDirectory(t *testing.T) (*recordingDirectory, *httptest.Server) {
	t.Helper()
	d := &recordingDirectory{logs: map[string][]map[string]any{}}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		d.mu.Lock()
		defer d.mu.Unlock()
		path := strings.TrimPrefix(r.URL.Path, "/")
		switch {
		case r.Method == http.MethodPost:
			d.posts++
			if d.posts == d.failPost {
				http.Error(w, `{"error":"unavailable"}`, http.StatusServiceUnavailable)
				return
			}
			var op map[string]any
			require.NoError(t, json.NewDecoder(r.Body).Decode(&op))
			cid := fmt.Sprintf("bafy%d", len(d.ops))
			d.ops = append(d.ops, op)
			d.logs[path] = append(d.logs[path], map[string]any{"cid": cid, "operation": op})
			_, _ = w.Write([]byte(`{"did":"` + path + `","cid":"` + cid + `"}`))
		case r.Method == http.MethodGet && strings.HasSuffix(path, "/log/audit"):
			_ = json.NewEncoder(w).Encode(d.logs[strings.TrimSuffix(path, "/log/audit")])
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(srv.Close)
	return d, srv
}

// Fix round 1, item 4: dimocli register finishes a create --org-host run that
// failed after the genesis: when the host refused, and when the host
// registered but publishing the key failed. It is safe to run again.
func TestRegisterCmd_FinishesAFailedCreate(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	noWait(t)
	sg, err := newFileSignerK1()
	require.NoError(t, err)
	pub, err := didkey.Decode(sg.DIDKey())
	require.NoError(t, err)
	dauth := newAudienceDauth(t, pub)

	t.Run("the host refused", func(t *testing.T) {
		host := newFakeOrgHost(t)
		host.status = http.StatusForbidden
		dir, srv := newRecordingDirectory(t)
		c := client.New(srv.URL)
		org, err := executeCreate(context.Background(), c, createOptions{OrgHost: host.url, Dauth: dauth.url}, sg, &bytes.Buffer{})
		require.Error(t, err)
		require.NotEmpty(t, org)
		assert.Contains(t, err.Error(), "dimocli register --did "+org)

		host.status = http.StatusCreated
		var out bytes.Buffer
		require.NoError(t, executeRegister(context.Background(), c, &turnkeyFlags{}, org, dauth.url, &out))
		require.Len(t, dir.ops, 2)
		vms := dir.ops[1]["verificationMethods"].(map[string]any)
		assert.Equal(t, host.key, vms[OrgKeyID])

		// Again: nothing left to do.
		require.NoError(t, executeRegister(context.Background(), c, &turnkeyFlags{}, org, dauth.url, &out))
		assert.Len(t, dir.ops, 2, "no second update")
		assert.Contains(t, out.String(), "already publishes")
	})

	t.Run("publishing the key failed", func(t *testing.T) {
		host := newFakeOrgHost(t)
		dir, srv := newRecordingDirectory(t)
		c := client.New(srv.URL)
		// The genesis lands; the update that publishes the host key does not.
		dir.failPost = 2
		org, err := executeCreate(context.Background(), c, createOptions{OrgHost: host.url, Dauth: dauth.url}, sg, &bytes.Buffer{})
		require.Error(t, err)
		assert.Contains(t, err.Error(), "is registered on")
		assert.Contains(t, err.Error(), "dimocli register --did "+org)
		require.Len(t, dir.ops, 1)

		require.NoError(t, executeRegister(context.Background(), c, &turnkeyFlags{}, org, dauth.url, &bytes.Buffer{}))
		assert.Equal(t, 2, host.posts, "the second register is a 409")
		assert.Equal(t, 1, host.gets, "and the key is read back")
		require.Len(t, dir.ops, 2)
		assert.Equal(t, host.key, dir.ops[1]["verificationMethods"].(map[string]any)[OrgKeyID])
	})
}
