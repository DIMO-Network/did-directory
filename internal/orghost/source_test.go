package orghost

import (
	"net/http"
	"testing"

	"github.com/DIMO-Network/did-directory/internal/orghost/store"
	"github.com/DIMO-Network/did-directory/pkg/delegation"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// A source sends data about many cars under its own identity, so din asks with
// anyGrant and the host finds the grant (docs/2026-10-24-sources.md).

const relay = "did:dimo:flespi"

// writeGrant has org let `to` write telemetry about car,
// and returns the grant's URI.
func (h *host) writeGrant(org, to, car string) string {
	h.t.Helper()
	rec := delegation.Record{
		Type: delegation.TypeDelegation, From: org, To: to,
		Covers: delegation.Covers{Vehicle: car}, Abilities: []string{"telemetry:write"},
		Validity:   delegation.Window{From: tp(day(1))},
		Redelegate: delegation.Redelegate{Mode: delegation.RedelegateNone}, CreatedAt: day(1),
	}
	status, body := h.do(http.MethodPut, "/orgs/"+org+"/"+delegation.CollectionDelegation+"/source", org, rec)
	require.Equal(h.t, http.StatusCreated, status, body)
	return body["uri"].(string)
}

func (h *host) authorizeAny(caller, vehicle string, abilities ...string) (int, map[string]any) {
	h.t.Helper()
	return h.do(http.MethodPost, "/authorize", dauthDID, AuthorizeRequest{AnyGrant: true, Caller: caller, Vehicle: vehicle, Abilities: abilities})
}

func TestAuthorizeAnyGrant_SourceWrites(t *testing.T) {
	h := newHost(t, store.NewMemoryStore())
	org := newOrgDID()
	car := carOf(org)
	h.fleet(org)
	uri := h.writeGrant(org, relay, car)
	h.clock = day(5)

	status, body := h.authorizeAny(relay, car, "telemetry:write")
	require.Equal(t, http.StatusOK, status, body)
	assert.Equal(t, []any{"telemetry:write"}, body["live"])
	assert.Equal(t, uri, body["chain"].([]any)[0], "the chain says which grant answered")

	status, body = h.authorizeAny(relay, car, "telemetry:read")
	assert.Equal(t, http.StatusForbidden, status, body)
	assert.Equal(t, CodeNotCovered, body["code"], "writing about a car is not reading it")

	other := newOrgDID()
	h.fleet(other)
	h.clock = day(5)
	status, body = h.authorizeAny(relay, carOf(other), "telemetry:write")
	assert.Equal(t, http.StatusForbidden, status, body)
	assert.Equal(t, CodeNotCovered, body["code"], "a car nobody granted")

	// The controller needs no grant to write about its own car.
	status, body = h.authorizeAny(org, car, "telemetry:write")
	assert.Equal(t, http.StatusOK, status, body)

	status, body = h.do(http.MethodDelete, "/orgs/"+org+"/"+delegation.CollectionDelegation+"/source", org, nil)
	require.Equal(t, http.StatusOK, status, body)
	status, body = h.authorizeAny(relay, car, "telemetry:write")
	assert.Equal(t, http.StatusForbidden, status, body)
	assert.Equal(t, CodeNotCovered, body["code"], "a revoked grant is one of many, so the answer is about the car")
}

// A relay run as an org: the grant is to the org, and the server that signs
// in is a member whose role lets it write.
func TestAuthorizeAnyGrant_SourceOrgMember(t *testing.T) {
	h := newHost(t, store.NewMemoryStore())
	org := newOrgDID()
	car := carOf(org)
	h.fleet(org)

	relayOrg := newOrgDID()
	server := relayOrg + "-ingest"
	status, body := h.do(http.MethodPost, "/orgs/"+relayOrg, relayOrg, nil)
	require.Equal(t, http.StatusCreated, status, body)
	h.writeGrant(org, relayOrg, car)
	h.clock = day(5)

	status, body = h.authorizeAny(server, car, "telemetry:write")
	assert.Equal(t, http.StatusForbidden, status, body, "not a member yet")

	h.grantRole(relayOrg, roleRecord(relayOrg, server, delegation.Covers{Inherit: true}, "telemetry:write"))
	status, body = h.authorizeAny(server, car, "telemetry:write")
	assert.Equal(t, http.StatusOK, status, body)
}

func TestAuthorizeAnyGrant_TakesNoURI(t *testing.T) {
	h := newHost(t, store.NewMemoryStore())
	status, body := h.do(http.MethodPost, "/authorize", dauthDID, AuthorizeRequest{
		AnyGrant: true, URI: "at://did:dimo:x/" + delegation.CollectionDelegation + "/y",
		Caller: relay, Vehicle: "did:dimo:car", Abilities: []string{"telemetry:write"},
	})
	assert.Equal(t, http.StatusBadRequest, status, body)
}
