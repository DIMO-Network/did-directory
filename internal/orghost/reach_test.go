package orghost

import (
	"context"
	"net/http"
	"testing"
	"time"

	"github.com/DIMO-Network/did-directory/internal/orghost/store"
	"github.com/DIMO-Network/did-directory/pkg/delegation"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// R4-F7: GET /orgs/:org gives the head (how many commits, and when the
// repository last changed) only to the org and its members. Anyone signed in
// gets the key, which the DID document publishes anyway.
func TestGetOrg_HeadOnlyForMembers(t *testing.T) {
	h := newHost(t, store.NewMemoryStore())
	org := newOrgDID()
	h.publish(org)
	status, body := h.do(http.MethodPost, "/orgs/"+org, org, nil)
	require.Equal(t, http.StatusCreated, status, body)
	key := body["key"]
	h.grantRole(org, roleRecord(org, "did:dimo:alice", delegation.Covers{Inherit: true}, "telemetry:read"))

	status, body = h.do(http.MethodGet, "/orgs/"+org, "did:dimo:stranger", nil)
	require.Equal(t, http.StatusOK, status, body)
	assert.Equal(t, key, body["key"])
	assert.Equal(t, org, body["did"])
	assert.NotContains(t, body, "head", "a non-member learns nothing about the log")

	for _, as := range []string{org, "did:dimo:alice"} {
		status, body = h.do(http.MethodGet, "/orgs/"+org, as, nil)
		require.Equal(t, http.StatusOK, status, body)
		assert.Equal(t, key, body["key"])
		require.Contains(t, body, "head", as)
		assert.Equal(t, float64(1), body["head"].(map[string]any)["seq"], as)
	}

	status, body = h.do(http.MethodGet, "/orgs/did:dimo:nowhere", "did:dimo:stranger", nil)
	assert.Equal(t, http.StatusNotFound, status, body)
}

// countingStore counts DeletePending calls, so a test can tell a pending write
// was never claimed.
type countingStore struct {
	store.Store
	deletes int
}

func (c *countingStore) DeletePending(ctx context.Context, org, id string) error {
	c.deletes++
	return c.Store.DeletePending(ctx, org, id)
}

// pendingRole parks a role over car written by the org, which needs a second
// approval because it hands out a live ability, and returns its pending id.
func pendingRole(t *testing.T, h *host, org, car string) string {
	t.Helper()
	role := delegation.Record{
		Type: delegation.TypeRole, From: org, To: "did:dimo:backend",
		Covers: delegation.Covers{Vehicle: car}, Abilities: []string{"command:lock"},
		Redelegate: delegation.Redelegate{Mode: delegation.RedelegateNone}, CreatedAt: time.Now().UTC().Truncate(time.Second),
	}
	status, body := h.do(http.MethodPost, "/orgs/"+org+"/"+delegation.CollectionRole, org, role)
	require.Equal(t, http.StatusAccepted, status, body)
	return body["pending"].(string)
}

// R4-F8, reviewer 4's P4: approve resolves who the caller is before it claims
// the pending write. A pending id outside the caller's reach is not found, as
// one that does not exist is: it is never deleted, and the answer names
// nothing the write covers.
func TestApprove_OutsideReachIs404AndClaimsNothing(t *testing.T) {
	h := newHost(t, store.NewMemoryStore())
	org := newOrgDID()
	h.publish(org)
	status, body := h.do(http.MethodPost, "/orgs/"+org, org, nil)
	require.Equal(t, http.StatusCreated, status, body)
	// A member whose role reads nothing and approves nothing.
	h.grantRole(org, roleRecord(org, "did:dimo:dave", delegation.Covers{Inherit: true}, "telemetry:read"))
	const car = "did:dimo:secretcar"
	id := pendingRole(t, h, org, car)
	counted := &countingStore{Store: h.repo.Store}
	h.repo.Store = counted

	for _, as := range []string{"did:dimo:stranger", "did:dimo:dave"} {
		status, body = h.do(http.MethodPost, "/orgs/"+org+"/pending/"+id+"/approve", as, nil)
		assert.Equal(t, http.StatusNotFound, status, "%s: %v", as, body)
		assert.NotContains(t, body["error"], car, as)
	}
	status, body = h.do(http.MethodPost, "/orgs/"+org+"/pending/nope/approve", "did:dimo:stranger", nil)
	assert.Equal(t, http.StatusNotFound, status, body, "the same answer as an id that does not exist")
	assert.Zero(t, counted.deletes, "the pending write was never claimed")
	_, err := counted.GetPending(t.Context(), org, id)
	assert.NoError(t, err)
}

// A member who may see the pending write but holds no authority to approve it
// is refused before the write is claimed, so a real approver never finds it
// missing.
func TestApprove_ReaderWithoutAuthorityClaimsNothing(t *testing.T) {
	h := newHost(t, store.NewMemoryStore())
	org := newOrgDID()
	h.publish(org)
	status, body := h.do(http.MethodPost, "/orgs/"+org, org, nil)
	require.Equal(t, http.StatusCreated, status, body)
	h.grantRole(org, roleRecord(org, "did:dimo:erin", delegation.Covers{Inherit: true}, delegation.AbilityOrgRead))
	h.grantRole(org, roleRecord(org, "did:dimo:carol", delegation.Covers{Inherit: true}, delegation.AbilityOrgAdmin, delegation.AbilityOrgMembers))
	id := pendingRole(t, h, org, "did:dimo:car1")
	counted := &countingStore{Store: h.repo.Store}
	h.repo.Store = counted

	status, body = h.do(http.MethodPost, "/orgs/"+org+"/pending/"+id+"/approve", "did:dimo:erin", nil)
	assert.Equal(t, http.StatusForbidden, status, body)
	assert.Zero(t, counted.deletes)

	status, body = h.do(http.MethodPost, "/orgs/"+org+"/pending/"+id+"/approve", "did:dimo:carol", nil)
	require.Equal(t, http.StatusCreated, status, body)
	assert.Equal(t, 1, counted.deletes)
}
