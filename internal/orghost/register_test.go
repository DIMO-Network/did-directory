package orghost

import (
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strconv"
	"testing"
	"time"

	"github.com/DIMO-Network/did-directory/internal/did"
	"github.com/DIMO-Network/did-directory/internal/orghost/store"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const wantNotThisHost = "the org's DID does not name this host as #dimo_org_host"

// kmsHost is a host whose new orgs register under a fake KMS.
func kmsHost(t *testing.T, opts ...func(*Options)) (*host, *fakeKMS) {
	t.Helper()
	st := store.NewMemoryStore()
	h := newHostWith(t, st, nil, opts...)
	api := newFakeKMS(t)
	h.repo.Signer = NewKMSSigner(st, api, "alias/dimo-org/")
	return h, api
}

func TestRegister_HostMismatchIs403AndNoKMSCall(t *testing.T) {
	h, api := kmsHost(t)
	for _, endpoint := range []string{
		"https://other-host.test",
		hostAudience + "/", // compared exactly
		"http://orghost.test",
		"",
	} {
		org := newOrgDID()
		h.directory.publishHost(org, endpoint)
		status, body := h.do(http.MethodPost, "/orgs/"+org, org, nil)
		assert.Equal(t, http.StatusForbidden, status, endpoint)
		assert.Equal(t, wantNotThisHost, body["error"], endpoint)
	}
	assert.Empty(t, api.created, "no KMS key is made for an org that names another host")
}

func TestRegister_MissingServiceIs403(t *testing.T) {
	h := newHost(t, store.NewMemoryStore())

	// A document with other services but no #dimo_org_host.
	org := newOrgDID()
	h.directory.publishDoc(org, did.ServiceEntry{ID: "#atproto_pds", Type: "AtprotoPersonalDataServer", ServiceEndpoint: hostAudience})
	status, body := h.do(http.MethodPost, "/orgs/"+org, org, nil)
	assert.Equal(t, http.StatusForbidden, status, body)
	assert.Equal(t, wantNotThisHost, body["error"])

	// No services at all.
	org = newOrgDID()
	h.directory.publishDoc(org)
	status, body = h.do(http.MethodPost, "/orgs/"+org, org, nil)
	assert.Equal(t, http.StatusForbidden, status, body)
	assert.Equal(t, wantNotThisHost, body["error"])

	// A DID the directory does not know.
	org = newOrgDID()
	status, body = h.do(http.MethodPost, "/orgs/"+org, org, nil)
	assert.Equal(t, http.StatusForbidden, status, body)
	assert.Equal(t, wantNotThisHost, body["error"])

	_, err := h.repo.Store.GetOrg(t.Context(), org)
	assert.True(t, store.IsNotFound(err), "nothing was registered")
}

func TestRegister_OwnDIDNamesThisHost(t *testing.T) {
	// The full DID URL form of the service id is accepted too, and a
	// configured public URL with a trailing slash matches the bare one.
	h, api := kmsHost(t, func(o *Options) { o.PublicURL = hostAudience + "/" })
	org := newOrgDID()
	h.directory.publishDoc(org, did.ServiceEntry{ID: org + "#" + OrgHostServiceID, Type: "DimoOrgHost", ServiceEndpoint: hostAudience})
	status, body := h.do(http.MethodPost, "/orgs/"+org, org, nil)
	require.Equal(t, http.StatusCreated, status, body)
	assert.Len(t, api.created, 1)
}

func TestRegister_DirectoryDownIs503AndNoKMSCall(t *testing.T) {
	h, api := kmsHost(t)
	org := newOrgDID()
	h.publish(org)
	h.directory.resolveErr = errors.New("connection refused")
	status, body := h.do(http.MethodPost, "/orgs/"+org, org, nil)
	assert.Equal(t, http.StatusServiceUnavailable, status, body)
	assert.Empty(t, api.created)
}

// registerResp registers org as itself and returns the raw response.
func (h *host) registerResp(org string) *http.Response {
	h.t.Helper()
	req := httptest.NewRequest(http.MethodPost, "/orgs/"+org, nil)
	require.NoError(h.t, h.issuer.present(req, h.issuer.identity(h.t, org)))
	resp, err := h.app.Test(req, -1)
	require.NoError(h.t, err)
	h.t.Cleanup(func() { _ = resp.Body.Close() })
	return resp
}

func TestRegister_EleventhInAMinuteIs429(t *testing.T) {
	h, api := kmsHost(t, func(o *Options) { o.RegisterPerMinute = 10 })
	start := time.Date(2026, 11, 22, 12, 0, 0, 0, time.UTC)
	for i := range 10 {
		h.clock = start.Add(time.Duration(i) * time.Second)
		org := newOrgDID()
		h.publish(org)
		resp := h.registerResp(org)
		require.Equal(t, http.StatusCreated, resp.StatusCode, i)
	}

	h.clock = start.Add(30 * time.Second)
	org := newOrgDID()
	h.publish(org)
	resp := h.registerResp(org)
	raw, _ := io.ReadAll(resp.Body)
	assert.Equal(t, http.StatusTooManyRequests, resp.StatusCode, string(raw))
	retry, err := strconv.Atoi(resp.Header.Get("Retry-After"))
	require.NoError(t, err, "Retry-After is whole seconds")
	assert.Equal(t, 30, retry, "the first register leaves the window 30s from now")
	assert.Len(t, api.created, 10, "the 11th never reaches KMS")
	before := h.directory.resolves

	// A minute after the first, one slot is free again.
	h.clock = start.Add(time.Minute)
	resp = h.registerResp(org)
	assert.Equal(t, http.StatusCreated, resp.StatusCode)
	assert.Equal(t, before+1, h.directory.resolves)
	resp = h.registerResp(newOrgDID())
	assert.Equal(t, http.StatusTooManyRequests, resp.StatusCode, "the second register is still in the window")
}

func TestRegister_RateLimitZeroDisables(t *testing.T) {
	h, _ := kmsHost(t, func(o *Options) { o.RegisterPerMinute = 0 })
	h.clock = time.Date(2026, 11, 22, 12, 0, 0, 0, time.UTC)
	for i := range 25 {
		org := newOrgDID()
		h.publish(org)
		require.Equal(t, http.StatusCreated, h.registerResp(org).StatusCode, i)
	}
}
