package orghost

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strconv"
	"testing"
	"time"

	"github.com/DIMO-Network/did-directory/internal/did"
	"github.com/DIMO-Network/did-directory/internal/orghost/store"
	"github.com/aws/aws-sdk-go-v2/service/kms"
	"github.com/rs/zerolog"
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
		"http://orghost.test",
		"https://orghost.test:8443",
		"https://orghost.test/elsewhere",
		"https://ops@orghost.test",
		"https://orghost.test?x=1",
		"https://orghost.test#frag",
		"orghost.test",
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
	next := newOrgDID()
	h.publish(next)
	resp = h.registerResp(next)
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

// R4-F1: a register that will not make a key spends no budget. A DID that
// names no host (403) and an org replaying its register (409) used to drain
// the host-wide bucket, so one signed-in DID could block every new org.
func TestRegister_RefusedRegistersSpendNoBudget(t *testing.T) {
	h, api := kmsHost(t, func(o *Options) { o.RegisterPerMinute = 10 })
	h.clock = time.Date(2026, 11, 22, 12, 0, 0, 0, time.UTC)
	attacker := "did:dimo:attacker" // never publishes #dimo_org_host
	for i := range 20 {
		status, body := h.do(http.MethodPost, "/orgs/"+attacker, attacker, nil)
		require.Equal(t, http.StatusForbidden, status, "%d %v", i, body)
	}
	org := newOrgDID()
	h.publish(org)
	require.Equal(t, http.StatusCreated, h.registerResp(org).StatusCode, "refused registers left the budget whole")

	for range 20 {
		require.Equal(t, http.StatusConflict, h.registerResp(org).StatusCode)
	}
	other := newOrgDID()
	h.publish(other)
	assert.Equal(t, http.StatusCreated, h.registerResp(other).StatusCode, "409 replays spend nothing either")
	assert.Len(t, api.created, 2)
}

// V2's probe for R4-F1: a DID floods registers every 500 ms for five minutes
// while a real org retries every 7 s. The org's first retry succeeds.
func TestRegister_LegitRetrySucceedsWhileOneDIDFloods(t *testing.T) {
	h, api := kmsHost(t, func(o *Options) {
		o.RegisterPerMinute = 10
		o.RegisterPerCallerPerMinute = 3
	})
	start := time.Date(2026, 11, 22, 12, 0, 0, 0, time.UTC)
	attacker := "did:dimo:attacker" // names no host
	// A second attacker whose DID names this host: its first register makes a
	// key and every later one is a 409.
	squatter := newOrgDID()
	h.publish(squatter)
	org := newOrgDID()
	h.publish(org)
	codes := map[int]int{}
	for ms := 0; ms < 5*60*1000; ms += 250 {
		h.clock = start.Add(time.Duration(ms) * time.Millisecond)
		if ms%500 == 0 {
			h.do(http.MethodPost, "/orgs/"+attacker, attacker, nil)
			h.do(http.MethodPost, "/orgs/"+squatter, squatter, nil)
		}
		if ms >= 20_000 && ms%7000 == 250 && codes[http.StatusCreated] == 0 {
			codes[h.registerResp(org).StatusCode]++
		}
	}
	assert.Equal(t, map[int]int{http.StatusCreated: 1}, codes, "the org's first register succeeds")
	assert.Len(t, api.created, 2, "one key for the squatter, one for the org")
}

// failingKMS fails every CreateKey for one org, as a KMS error would; a DID
// whose register keeps failing after it was charged must not drain the
// host-wide budget alone.
type failingKMS struct {
	*fakeKMS
	org string
}

func (f *failingKMS) CreateKey(ctx context.Context, in *kms.CreateKeyInput, o ...func(*kms.Options)) (*kms.CreateKeyOutput, error) {
	for _, tag := range in.Tags {
		if tag.TagValue != nil && *tag.TagValue == f.org {
			return nil, errors.New("kms: internal failure")
		}
	}
	return f.fakeKMS.CreateKey(ctx, in, o...)
}

func TestRegister_PerCallerLimit(t *testing.T) {
	st := store.NewMemoryStore()
	h := newHostWith(t, st, nil, func(o *Options) {
		o.RegisterPerMinute = 10
		o.RegisterPerCallerPerMinute = 3
	})
	looper := newOrgDID()
	h.publish(looper)
	h.repo.Signer = NewKMSSigner(st, &failingKMS{fakeKMS: newFakeKMS(t), org: looper}, "alias/dimo-org/")
	start := time.Date(2026, 11, 22, 12, 0, 0, 0, time.UTC)
	h.clock = start

	for i := range 3 {
		assert.Equal(t, http.StatusInternalServerError, h.registerResp(looper).StatusCode, i)
	}
	resp := h.registerResp(looper)
	raw, _ := io.ReadAll(resp.Body)
	assert.Equal(t, http.StatusTooManyRequests, resp.StatusCode, string(raw))
	assert.Contains(t, string(raw), "too many registers by this caller")
	assert.Equal(t, "60", resp.Header.Get("Retry-After"))

	// The other seven slots of the minute are still there for everyone else.
	for i := range 7 {
		org := newOrgDID()
		h.publish(org)
		require.Equal(t, http.StatusCreated, h.registerResp(org).StatusCode, i)
	}
	org := newOrgDID()
	h.publish(org)
	assert.Equal(t, http.StatusTooManyRequests, h.registerResp(org).StatusCode, "the host-wide minute is spent")

	// A minute on, the looper has slots again.
	h.clock = start.Add(time.Minute + time.Second)
	assert.Equal(t, http.StatusInternalServerError, h.registerResp(looper).StatusCode)
}

// The daily cap counts the orgs this host made in the last 24 hours, in the
// store, so it holds across replicas sharing a database; past it, registers
// are refused with 429 and the host logs at error level, since that is the
// alarm. (The store tests cover the Postgres count.)
func TestRegister_DailyCap(t *testing.T) {
	var logs bytes.Buffer
	h := newHostWith(t, store.NewMemoryStore(), nil, func(o *Options) {
		o.Log = zerolog.New(&logs)
		o.RegisterMaxPerDay = 3
	})
	now := time.Now().UTC()
	h.clock = now
	for i := range 3 {
		org := newOrgDID()
		h.publish(org)
		require.Equal(t, http.StatusCreated, h.registerResp(org).StatusCode, i)
	}
	org := newOrgDID()
	h.publish(org)
	resp := h.registerResp(org)
	raw, _ := io.ReadAll(resp.Body)
	assert.Equal(t, http.StatusTooManyRequests, resp.StatusCode, string(raw))
	assert.NotEmpty(t, resp.Header.Get("Retry-After"))
	assert.Contains(t, logs.String(), `"level":"error"`)
	assert.Contains(t, logs.String(), "daily cap")
	_, err := h.repo.Store.GetOrg(t.Context(), org)
	assert.True(t, store.IsNotFound(err), "nothing was registered")

	// A day on, the window is empty again.
	h.clock = now.Add(25 * time.Hour)
	assert.Equal(t, http.StatusCreated, h.registerResp(org).StatusCode)
}

// R4-F6: the DID's #dimo_org_host is compared to this host's URL after the same
// normalisation: scheme and host case, the default port and a trailing slash
// make no difference.
func TestRegister_EndpointComparedNormalised(t *testing.T) {
	for _, endpoint := range []string{
		"HTTPS://OrgHost.Test",
		"https://orghost.test:443",
		"https://orghost.test/",
	} {
		h, api := kmsHost(t)
		org := newOrgDID()
		h.directory.publishHost(org, endpoint)
		status, body := h.do(http.MethodPost, "/orgs/"+org, org, nil)
		assert.Equal(t, http.StatusCreated, status, "%s: %v", endpoint, body)
		assert.Len(t, api.created, 1, endpoint)
	}
}
