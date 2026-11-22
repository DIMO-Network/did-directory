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
	"strings"
	"sync"
	"testing"

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
// the org, its scope approve, and the request DPoP-proved by the token's key.
type fakeOrgHost struct {
	url       string
	key       string
	status    int
	mu        sync.Mutex
	registers []string
}

func newFakeOrgHost(t *testing.T) *fakeOrgHost {
	t.Helper()
	_, hostKey, err := newKey()
	require.NoError(t, err)
	h := &fakeOrgHost{key: hostKey, status: http.StatusCreated}
	verifier := dpop.NewVerifier()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h.mu.Lock()
		defer h.mu.Unlock()
		org, ok := strings.CutPrefix(r.URL.Path, "/orgs/")
		if r.Method != http.MethodPost || !ok {
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
		jkt, err := verifier.Verify(r.Header.Get(dpop.HeaderName), http.MethodPost, h.url+r.URL.Path, tok)
		if err != nil || jkt != c.Cnf.Jkt || c.Sub != org || c.Scope != "approve" {
			http.Error(w, `{"error":"invalid_token"}`, http.StatusUnauthorized)
			return
		}
		h.registers = append(h.registers, org)
		w.WriteHeader(h.status)
		if h.status == http.StatusCreated {
			_ = json.NewEncoder(w).Encode(map[string]string{"did": org, "key": h.key})
			return
		}
		_, _ = w.Write([]byte(`{"error":"the org's DID does not name this host as #dimo_org_host"}`))
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
	assert.Equal(t, []string{"approve"}, dauth.scopes, "register takes an approve token")
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
	assert.Contains(t, err.Error(), "dimocli update")
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
