package orghost

import (
	"encoding/json"
	"net/http"
	"testing"
	"time"

	"github.com/DIMO-Network/did-directory/pkg/control"
	"github.com/DIMO-Network/did-directory/pkg/delegation"
	"github.com/DIMO-Network/did-directory/pkg/proof"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Authority is judged at the moment it was exercised, and a record's history
// is in its log. These are the cases where reading only a record's current
// version gave the wrong answer.

// TestRoleVersionAtCommitTime: a grant's author is judged by the role as it
// stood when the grant was committed. Re-saving the role unchanged used to
// void every grant written under it; narrowing it voided them too, although
// the author held the authority when they wrote them.
func TestRoleVersionAtCommitTime(t *testing.T) {
	for name, st := range stores(t) {
		t.Run(name, func(t *testing.T) {
			a := newAvis(t, st)
			car1 := a.cars[0]
			fl := delegation.Covers{Tag: a.tag["fl-fleet"]}
			status, body := a.do(http.MethodPut, a.path(delegation.CollectionTagMembership, "c1"), a.org, a.join("fl-fleet", car1, day(1)))
			require.Equal(t, http.StatusCreated, status, body)

			erin := "did:dimo:erin" + a.org[len("did:dimo:"):]
			a.clock = day(2)
			roleURI := a.grantRole(a.org, roleRecord(a.org, erin, fl, "delegation:create", "telemetry:read", "events:read"))
			_, _, roleKey, err := delegation.ParseURI(roleURI)
			require.NoError(t, err)

			a.clock = day(3)
			status, body = a.do(http.MethodPut, a.path(delegation.CollectionDelegation, "erin-insurer"), erin,
				a.grant(insurer, fl, "telemetry:read"))
			require.Equal(t, http.StatusCreated, status, body)
			grantURI := a.uri(delegation.CollectionDelegation, "erin-insurer")

			status, body = a.authorize(day(4), grantURI, insurer, car1, "telemetry:read")
			require.Equal(t, http.StatusOK, status, body)

			// The org re-saves the role unchanged.
			a.clock = day(5)
			status, body = a.do(http.MethodPut, a.path(delegation.CollectionRole, roleKey), a.org,
				roleRecord(a.org, erin, fl, "delegation:create", "telemetry:read", "events:read"))
			require.Equal(t, http.StatusOK, status, body)
			status, body = a.authorize(day(6), grantURI, insurer, car1, "telemetry:read")
			require.Equal(t, http.StatusOK, status, "an unchanged role does not void what was written under it"+": %v", body)

			// The org narrows the role: what Erin wrote before stands, and she can
			// no longer write it.
			a.clock = day(7)
			status, body = a.do(http.MethodPut, a.path(delegation.CollectionRole, roleKey), a.org,
				roleRecord(a.org, erin, fl, "delegation:create", "events:read"))
			require.Equal(t, http.StatusOK, status, body)
			status, body = a.authorize(day(8), grantURI, insurer, car1, "telemetry:read")
			require.Equal(t, http.StatusOK, status, "authority is judged when it was exercised"+": %v", body)
			status, body = a.do(http.MethodPut, a.path(delegation.CollectionDelegation, "erin-again"), erin,
				a.grant(insurer, fl, "telemetry:read"))
			assert.Equal(t, http.StatusForbidden, status, body)

			// A proof of the grant carries the role's versions and verifies offline.
			a.clock = day(8)
			status, p, body := a.proof(grantURI, car1, insurer)
			require.Equal(t, http.StatusOK, status, body)
			_, err = proof.Verify(t.Context(), p, proof.Anchors{})
			require.NoError(t, err)
		})
	}
}

// TestMembershipEditByTheUnauthorized: a tag edit counts toward a delegation
// only when its author could have granted that delegation's abilities (§9.2).
// When a later edit does not count, the interval the last entitled author
// stated stands; judging the whole record by its last editor used to drop the
// car from the delegation altogether.
func TestMembershipEditByTheUnauthorized(t *testing.T) {
	for name, st := range stores(t) {
		t.Run(name, func(t *testing.T) {
			a := newAvis(t, st)
			car1 := a.cars[0]
			fl := delegation.Covers{Tag: a.tag["fl-fleet"]}

			// The insurer's grant carries events:read, which Dave (tag:write and
			// telemetry:read) could not have granted.
			status, body := a.do(http.MethodPut, a.path(delegation.CollectionDelegation, "insurer"), alice,
				a.grant(insurer, fl, "telemetry:read", "events:read"))
			require.Equal(t, http.StatusCreated, status, body)
			insurerURI := a.uri(delegation.CollectionDelegation, "insurer")

			a.clock = day(2)
			status, body = a.do(http.MethodPut, a.path(delegation.CollectionTagMembership, "c1"), alice, a.join("fl-fleet", car1, day(2)))
			require.Equal(t, http.StatusCreated, status, body)

			status, body = a.authorize(day(10), insurerURI, insurer, car1, "events:read")
			require.Equal(t, http.StatusOK, status, body)
			assert.Equal(t, delegation.Span(tp(day(2)), nil), window(t, body, "events:read"))

			// Dave moves the join date back a day with an edit the host would refuse
			// (it names the delegation he cannot widen), written here as the store
			// holds it to show that the evaluator does not rely on the host.
			edit := a.join("fl-fleet", car1, day(1))
			a.clock = day(3)
			status, body = a.do(http.MethodPut, a.path(delegation.CollectionTagMembership, "c1"), dave, edit)
			require.Equal(t, http.StatusForbidden, status, body)
			appendAs(t, a.host, a.org, delegation.CollectionTagMembership, "c1", edit, dave)

			status, body = a.authorize(day(10), insurerURI, insurer, car1, "events:read")
			require.Equal(t, http.StatusOK, status, "Alice's interval stands"+": %v", body)
			assert.Equal(t, delegation.Span(tp(day(2)), nil), window(t, body, "events:read"), "Dave's edit does not count")

			// Alice, who may, closes the interval; that counts.
			closed := a.join("fl-fleet", car1, day(2))
			closed.LeftAt = tp(day(5))
			a.clock = day(6)
			status, body = a.do(http.MethodPut, a.path(delegation.CollectionTagMembership, "c1"), alice, closed)
			require.Equal(t, http.StatusOK, status, body)
			status, body = a.authorize(day(10), insurerURI, insurer, car1, "events:read")
			require.Equal(t, http.StatusOK, status, body)
			assert.Equal(t, delegation.Span(tp(day(2)), tp(day(5))), window(t, body, "events:read"))
		})
	}
}

// TestEarlierEraOpening: a controller's opening of an era proves that era for
// good. When the same controller opens a new era (after a revokeSince, or on
// buying a car back), the vehicleControl record moves on, and reading only
// its current version used to take the earlier era's history away.
func TestEarlierEraOpening(t *testing.T) {
	for name, st := range stores(t) {
		t.Run(name, func(t *testing.T) {
			a := newAvis(t, st)
			car1 := a.cars[0]
			rec := a.grant(insurer, delegation.Covers{Vehicle: car1}, "telemetry:read")
			rec.DataWindow = delegation.Window{From: tp(day(1))}
			status, body := a.do(http.MethodPut, a.path(delegation.CollectionDelegation, "insurer-car1"), a.org, rec)
			require.Equal(t, http.StatusCreated, status, body)
			grantURI := a.uri(delegation.CollectionDelegation, "insurer-car1")

			// Era 0 as the harness set it up, then era 1 for the same controller
			// from day 5, with a freshly salted commitment and its opening.
			state := a.directory.states[car1]
			era0 := state.Eras[0]
			era0.End = tp(day(5))
			salt, err := control.NewSalt()
			require.NoError(t, err)
			opening := control.Opening{Controller: a.org, Era: 1, Salt: salt}
			commitment, err := control.Commit(opening)
			require.NoError(t, err)
			a.directory.set(car1, &control.State{DID: car1, Eras: []control.Era{era0, {Number: 1, Start: tp(day(5)), Commitment: commitment}}})
			a.clock = day(5)
			status, body = a.do(http.MethodPut, a.path(delegation.CollectionVehicleControl, car1), a.org, opening)
			require.Equal(t, http.StatusOK, status, body)

			status, body = a.authorize(day(8).Add(time.Minute), grantURI, insurer, car1, "telemetry:read")
			require.Equal(t, http.StatusOK, status, body)
			assert.Equal(t, delegation.Span(tp(day(1)), nil), window(t, body, "telemetry:read"),
				"era 0 keeps counting: its opening is in the record's history")

			status, p, body := a.proof(grantURI, car1, insurer)
			require.Equal(t, http.StatusOK, status, body)
			_, err = proof.Verify(t.Context(), p, proof.Anchors{})
			require.NoError(t, err)
		})
	}
}

// appendAs commits body at collection/rkey as by, past the host's write
// checks: what a buggy or older host could have left in a log, which the
// evaluator has to judge on its own.
func appendAs(t *testing.T, h *host, org, collection, rkey string, body any, by string) {
	t.Helper()
	data, err := json.Marshal(body)
	require.NoError(t, err)
	rec, err := h.repo.Prepare(org, collection, rkey, data, by)
	require.NoError(t, err)
	_, err = h.repo.Put(t.Context(), org, collection, rkey, rec, by, nil)
	require.NoError(t, err)
}
