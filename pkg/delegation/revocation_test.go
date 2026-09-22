package delegation

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Writes are org acts (§6.3), and a member's tombstone is one of them: it
// revokes the record when the member held, at the time, the ability that
// manages records of that kind over its scope. The abilities the record hands
// out are not needed to take it away.
func TestRevocation_MemberTombstoneCountsForTheOrg(t *testing.T) {
	r, e, u := avisFleet(t)
	s := r.records[u]
	r.role(avis, alice, Covers{Tag: flTag}, []string{"delegation:create"}, day(1))

	_, err := e.Coverage(ctx, u, car, day(10))
	require.NoError(t, err)

	s.Tombstone = &Tombstone{At: day(5), By: alice}
	_, err = e.Coverage(ctx, u, car, day(10))
	assert.ErrorIs(t, err, ErrRevoked, "alice holds delegation:create over the tag")
	_, err = e.Coverage(ctx, u, car, day(4))
	assert.NoError(t, err, "before the tombstone")

	s.Tombstone = &Tombstone{At: day(5), By: bob}
	_, err = e.Coverage(ctx, u, car, day(10))
	assert.NoError(t, err, "bob holds nothing in avis, so his tombstone is ignored")

	// A role that ended before the tombstone does not count.
	role := &r.roles[avis+"|"+alice][0]
	role.Tombstone = &Tombstone{At: day(4), By: avis}
	s.Tombstone = &Tombstone{At: day(5), By: alice}
	_, err = e.Coverage(ctx, u, car, day(10))
	assert.NoError(t, err, "alice's role was gone by the time she wrote the tombstone")
}

// A lien is revocable only by its recipient, and a member of the recipient
// org who may manage its grants revokes it for them.
func TestRevocation_RecipientOrgMemberReleasesALien(t *testing.T) {
	r, e, u := avisFleet(t)
	s := r.records[u]
	s.Record.RevocableBy = RevocableByTo
	r.role(fordCredit, fcAnalyst, Covers{Inherit: true}, []string{"delegation:create"}, day(1))

	s.Tombstone = &Tombstone{At: day(5), By: alice}
	r.role(avis, alice, Covers{Inherit: true}, []string{"delegation:create"}, day(1))
	_, err := e.Coverage(ctx, u, car, day(10))
	assert.NoError(t, err, "the issuer's staff cannot release a lien")

	s.Tombstone = &Tombstone{At: day(5), By: fcAnalyst}
	_, err = e.Coverage(ctx, u, car, day(10))
	assert.ErrorIs(t, err, ErrRevoked)
}

// A role a member wrote is checked like a delegation a member wrote: the
// author must have held org:members and everything the role hands out, and a
// role to oneself needs a second approval.
func TestRoles_MemberWrittenRoleNeedsAuthority(t *testing.T) {
	r, e, u := avisFleet(t)
	r.role(avis, alice, Covers{Inherit: true}, []string{"org:members", "delegation:create", "telemetry:read"}, day(1))

	// Alice writes Bob a role with less than she holds: a role.
	bobRole := r.role(avis, bob, Covers{Tag: flTag}, []string{"delegation:create", "telemetry:read"}, day(2))
	bobRole.CommittedBy = alice
	held, err := e.HeldRoles(ctx, avis, bob, day(3))
	require.NoError(t, err)
	assert.Len(t, held, 1)

	// A role handing out more than Alice holds is not a role.
	bobRole.Record.Abilities = []string{"delegation:create", "command:unlock"}
	held, err = e.HeldRoles(ctx, avis, bob, day(3))
	require.NoError(t, err)
	assert.Empty(t, held, "alice never held command:unlock")

	// Alice writes herself a role, within what she holds: ignored until
	// somebody else with the same authority approves.
	self := r.role(avis, alice, Covers{Tag: flTag}, []string{"org:members", "delegation:create"}, day(2))
	self.CommittedBy = alice
	held, err = e.HeldRoles(ctx, avis, alice, day(3))
	require.NoError(t, err)
	assert.Len(t, held, 1, "the self-written role does not count")
	self.ApprovedBy = []string{bob}
	held, err = e.HeldRoles(ctx, avis, alice, day(3))
	require.NoError(t, err)
	assert.Len(t, held, 1, "bob did not hold org:members when he approved")
	r.role(avis, bob, Covers{Inherit: true}, []string{"org:members", "delegation:create"}, day(1))
	held, err = e.HeldRoles(ctx, avis, alice, day(3))
	require.NoError(t, err)
	assert.Len(t, held, 2, "approved by bob, who held the same authority")

	// A role wider than its author's authority is not a role, approved or not.
	wide := r.role(avis, alice, Covers{Inherit: true}, []string{"org:members", "delegation:create", "events:read"}, day(2))
	wide.CommittedBy, wide.ApprovedBy = alice, []string{bob}
	held, err = e.HeldRoles(ctx, avis, alice, day(3))
	require.NoError(t, err)
	assert.Len(t, held, 2, "alice never held events:read")

	// And what the org itself wrote is trusted as the org's act.
	_, err = e.Coverage(ctx, u, car, day(10))
	assert.NoError(t, err)
}

// RolesCovering is the host's write-time check and hasRole is the evaluator's;
// they are the same function, so a write the host accepts is one evaluation
// honours.
func TestRolesCovering(t *testing.T) {
	r, e, _ := avisFleet(t)
	r.role(avis, alice, Covers{Tag: flTag}, []string{"delegation:create", "telemetry:read"}, day(1))

	roles, err := e.RolesCovering(ctx, avis, alice, Covers{Tag: flTag}, []string{"delegation:create", "telemetry:read"}, day(2))
	require.NoError(t, err)
	assert.Len(t, roles, 1)
	roles, err = e.RolesCovering(ctx, avis, alice, Covers{Vehicle: car}, []string{"delegation:create"}, day(4))
	require.NoError(t, err)
	assert.Len(t, roles, 1, "a tag-scoped role covers a car in the tag")
	roles, err = e.RolesCovering(ctx, avis, alice, Covers{Vehicle: car}, []string{"delegation:create"}, day(2))
	require.NoError(t, err)
	assert.Empty(t, roles, "the car joined on day 3")
	roles, err = e.RolesCovering(ctx, avis, alice, Covers{Tag: flTag}, []string{"delegation:create", "command:unlock"}, day(2))
	require.NoError(t, err)
	assert.Empty(t, roles, "command:unlock is not held")
	roles, err = e.RolesCovering(ctx, avis, alice, Covers{Inherit: true}, []string{"delegation:create"}, day(2))
	require.NoError(t, err)
	assert.Empty(t, roles, "a tag role does not cover everything")
	roles, err = e.RolesCovering(ctx, avis, alice, Covers{Tag: flTag}, []string{"delegation:create"}, day(0))
	require.NoError(t, err)
	assert.Empty(t, roles, "before the role was committed")
}

func TestManageAbility(t *testing.T) {
	d := delegation(avis, fordCredit, Covers{Tag: flTag}, "telemetry:read")
	assert.Equal(t, AbilityDelegationCreate, ManageAbility(&d))
	assert.Equal(t, []string{AbilityDelegationCreate, "telemetry:read"}, AuthoringNeed(&d))
	assert.Equal(t, []string{AbilityTagWrite, "telemetry:read"}, MembershipNeed(&d))
	role := Record{Type: TypeRole, From: avis, To: alice, Abilities: []string{"tag:write"}}
	assert.Equal(t, AbilityOrgMembers, ManageAbility(&role))
	assert.Equal(t, []string{avis, fordCredit}, Revokers(&Record{From: avis, To: fordCredit, RevocableBy: RevocableByEither}))
	assert.Equal(t, []string{avis}, Revokers(&Record{From: avis, To: fordCredit}))
}
