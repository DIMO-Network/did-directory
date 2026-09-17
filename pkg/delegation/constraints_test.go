package delegation

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const (
	booking = "did:dimo:booking-svc" // unattended: compiles bookings into grants
	thief   = "did:dimo:thief"
)

// bookingLimits is the shape of a rental: one car, for the length of a booking,
// with the commands custody needs and nothing else.
func bookingLimits() *RoleConstraints {
	return &RoleConstraints{
		MaxVehicles:    1,
		MaxValidity:    30 * 24 * time.Hour,
		Abilities:      []string{"command:unlock", "command:lock", "telemetry:read"},
		AllowExclusive: true,
	}
}

// bookingFleet: Avis controls two cars, both in the fleet tag, and the booking
// service holds delegation:create org-wide, because it must be able to issue a
// custody grant over whichever car the renter is standing next to.
func bookingFleet(t *testing.T) (*memResolver, *Evaluator, *Stored) {
	t.Helper()
	r := newResolver()
	r.parties[booking] = Party{Kind: KindOrg, Operator: true}
	r.control(t, car, avis)
	r.control(t, otherCar, avis)
	r.join(flTag, car, avis, day(1), nil)
	r.join(flTag, otherCar, avis, day(1), nil)
	role := r.role(avis, booking, Covers{Inherit: true},
		[]string{"delegation:create", "command:unlock", "command:lock", "telemetry:read", "location:precise"}, day(1))
	return r, &Evaluator{Resolver: r}, role
}

// issue writes a record the booking service authored.
func issue(r *memResolver, rkey string, rec Record) (string, *Stored) {
	rec.CreatedBy = booking
	u := uri(avis, rkey)
	return u, r.put(u, rec, day(2))
}

// The hole: a role bounds which abilities its holder may hand out, but not the
// shape. A booking service needs command:* over the whole fleet to unlock a car
// at pickup, so a compromised one writes a fleet-wide, permanent,
// command-bearing grant using exactly the authority it legitimately holds.
func TestRoleConstraints_CompromisedBookingServiceTakesTheFleet(t *testing.T) {
	r, e, role := bookingFleet(t)
	grab := delegation(avis, thief, Covers{Tag: flTag}, "command:unlock", "telemetry:read")
	u, _ := issue(r, "grab", grab)

	cov, err := e.Coverage(ctx, u, car, day(10))
	require.NoError(t, err, "an unconstrained role permits any shape, which is the hole")
	assert.Equal(t, []string{"command:unlock"}, cov.Live)

	role.Record.Constraints = bookingLimits()
	_, err = e.Coverage(ctx, u, car, day(10))
	assert.ErrorIs(t, err, ErrExceedsRole)
	assert.ErrorContains(t, err, "covers 2 vehicles, limit 1")
}

// Writing straight to the store bypasses CheckCommit, so the same shape must
// also fail to evaluate. It does, above. Here it fails at the writer too.
func TestRoleConstraints_CommitRefusesTheSameShape(t *testing.T) {
	_, _, role := bookingFleet(t)
	role.Record.Constraints = bookingLimits()
	grab := delegation(avis, thief, Covers{Tag: flTag}, "command:unlock", "telemetry:read")
	grab.CreatedBy = booking

	cc := CommitContext{From: Party{Kind: KindOrg, Operator: true}, CoveredVehicles: 2, Role: &role.Record, Approved: true}
	assert.ErrorIs(t, CheckCommit(&grab, cc), ErrExceedsRole)

	cc.Role = nil
	assert.NoError(t, CheckCommit(&grab, cc), "an author with no constrained role is bounded only by its abilities")

	unlimited := role.Record
	unlimited.Constraints = nil
	cc.Role = &unlimited
	assert.NoError(t, CheckCommit(&grab, cc), "and neither does a role that set no constraints")
}

// Not naming the fleet is not the same as not covering it: covers.inherit is
// counted through the basis, or a constrained role would only have to say
// "whatever my parent covers" to take the fleet anyway.
func TestRoleConstraints_InheritedCoverageIsStillCounted(t *testing.T) {
	r, e, _ := bookingFleet(t)
	fleet := delegation(avis, fordPro, Covers{Tag: flTag}, "command:unlock", "telemetry:read")
	fleet.Redelegate = Redelegate{Mode: RedelegateAttenuated, MaxDepth: 2}
	fu := uri(avis, "fordpro-fleet")
	r.put(fu, fleet, day(1))

	role := r.role(fordPro, booking, Covers{Inherit: true},
		[]string{"delegation:create", "command:unlock", "telemetry:read"}, day(1))
	role.Record.Constraints = &RoleConstraints{MaxVehicles: 1}

	grab := delegation(fordPro, thief, Covers{Inherit: true}, "command:unlock")
	grab.Basis = []string{fu}
	grab.CreatedBy = booking
	gu := uri(fordPro, "grab")
	s := r.put(gu, grab, day(2))

	_, err := e.Coverage(ctx, gu, car, day(10))
	assert.ErrorIs(t, err, ErrExceedsRole)
	assert.ErrorContains(t, err, "covers 2 vehicles, limit 1")

	// Naming the one car it booked is within the role.
	s.Record.Covers = Covers{Vehicle: car}
	cov, err := e.Coverage(ctx, gu, car, day(10))
	require.NoError(t, err)
	assert.Equal(t, []string{"command:unlock"}, cov.Live)
}

// What the booking service is actually for: one car, one booking window,
// exclusive commands so the operator cannot immobilise a car someone is driving.
func TestRoleConstraints_CustodyGrantIsAllowed(t *testing.T) {
	r, e, role := bookingFleet(t)
	role.Record.Constraints = bookingLimits()

	custody := delegation(avis, renter, Covers{Vehicle: car}, "command:unlock", "telemetry:read")
	custody.Exclusive = []string{"command:unlock"}
	custody.Validity = Window{From: tp(day(3)), To: tp(day(6))}
	u, _ := issue(r, "custody", custody)

	cov, err := e.Coverage(ctx, u, car, day(4))
	require.NoError(t, err)
	assert.Equal(t, []string{"command:unlock"}, cov.Live)

	cc := CommitContext{From: Party{Kind: KindOrg, Operator: true}, CoveredVehicles: 1, Role: &role.Record, Approved: true}
	assert.NoError(t, CheckCommit(&custody, cc))
}

// A permanent grant is the shape being guarded against, so an unbounded validity
// is refused wherever a maximum duration is set.
func TestRoleConstraints_ValidityMustBeBounded(t *testing.T) {
	r, e, role := bookingFleet(t)
	role.Record.Constraints = bookingLimits()

	forever := delegation(avis, thief, Covers{Vehicle: car}, "command:unlock")
	forever.Validity = Window{From: tp(day(3))}
	u, s := issue(r, "forever", forever)

	_, err := e.Coverage(ctx, u, car, day(4))
	assert.ErrorIs(t, err, ErrExceedsRole)
	assert.ErrorContains(t, err, "bounded at both ends")

	s.Record.Validity = Window{From: tp(day(3)), To: tp(day(90))}
	_, err = e.Coverage(ctx, u, car, day(4))
	assert.ErrorIs(t, err, ErrExceedsRole)
	assert.ErrorContains(t, err, "exceeds limit")
}

// The role may read a car's location itself without being able to hand that out.
func TestRoleConstraints_AbilityOutsideTheIssueSet(t *testing.T) {
	r, e, role := bookingFleet(t)
	role.Record.Constraints = bookingLimits()

	track := delegation(avis, thief, Covers{Vehicle: car}, "location:precise")
	track.Validity = Window{From: tp(day(3)), To: tp(day(6))}
	u, _ := issue(r, "track", track)

	_, err := e.Coverage(ctx, u, car, day(4))
	assert.ErrorIs(t, err, ErrExceedsRole)
	assert.ErrorContains(t, err, "may not issue location:precise")
}

// Redelegation and exclusivity are off unless the role says otherwise, so a
// grant this role issues cannot seed a chain the org never saw, nor lock the
// operator out of its own car.
func TestRoleConstraints_RedelegationAndExclusivityAreOptIn(t *testing.T) {
	r, e, role := bookingFleet(t)
	role.Record.Constraints = &RoleConstraints{MaxVehicles: 1}

	pass := delegation(avis, thief, Covers{Vehicle: car}, "command:unlock")
	pass.Redelegate = Redelegate{Mode: RedelegateAttenuated, MaxDepth: 1}
	u, s := issue(r, "passon", pass)
	_, err := e.Coverage(ctx, u, car, day(4))
	assert.ErrorIs(t, err, ErrExceedsRole)
	assert.ErrorContains(t, err, "redelegable")

	s.Record.Redelegate = Redelegate{}
	s.Record.Exclusive = []string{"command:unlock"}
	_, err = e.Coverage(ctx, u, car, day(4))
	assert.ErrorIs(t, err, ErrExceedsRole)
	assert.ErrorContains(t, err, "exclusive or recovery")

	s.Record.Exclusive = nil
	s.Record.Recovery = true
	_, err = e.Coverage(ctx, u, car, day(4))
	assert.ErrorIs(t, err, ErrExceedsRole, "recovery overrides someone else's hold, so it is the same privilege")

	s.Record.Recovery = false
	role.Record.Constraints = &RoleConstraints{MaxVehicles: 1, AllowExclusive: true, AllowRedelegation: true}
	s.Record.Exclusive = []string{"command:unlock"}
	_, err = e.Coverage(ctx, u, car, day(4))
	assert.NoError(t, err)
}

// Constraints bind the role that authorizes the write, not the member. Someone
// who also holds an unconstrained role writes under that one.
func TestRoleConstraints_AnotherRoleWithoutLimitsStillAuthorizes(t *testing.T) {
	r, e, role := bookingFleet(t)
	role.Record.Constraints = bookingLimits()
	grab := delegation(avis, thief, Covers{Tag: flTag}, "command:unlock", "telemetry:read")
	u, _ := issue(r, "grab", grab)

	_, err := e.Coverage(ctx, u, car, day(10))
	require.ErrorIs(t, err, ErrExceedsRole)

	r.role(avis, booking, Covers{Inherit: true},
		[]string{"delegation:create", "command:unlock", "telemetry:read"}, day(1))
	_, err = e.Coverage(ctx, u, car, day(10))
	assert.NoError(t, err, "an admin role with no issue limits is still an admin role")
}

// Nothing changes for a role that sets no constraints, and a role cannot promise
// what it does not hold.
func TestRoleConstraints_Validation(t *testing.T) {
	role := Record{Type: TypeRole, From: avis, To: booking, Covers: Covers{Inherit: true},
		Abilities: []string{"delegation:create", "command:unlock"}}
	assert.NoError(t, role.Validate())

	role.Constraints = &RoleConstraints{MaxVehicles: 1, Abilities: []string{"command:unlock"}}
	assert.NoError(t, role.Validate())

	role.Constraints = &RoleConstraints{Abilities: []string{"location:precise"}}
	assert.ErrorContains(t, role.Validate(), "which the role does not hold")

	role.Constraints = &RoleConstraints{MaxVehicles: -1}
	assert.ErrorContains(t, role.Validate(), "maxVehicles")

	role.Constraints = &RoleConstraints{MaxValidity: -time.Hour}
	assert.ErrorContains(t, role.Validate(), "maxValidity")

	grant := validRecord()
	grant.Constraints = &RoleConstraints{MaxVehicles: 1}
	assert.ErrorContains(t, grant.Validate(), "only roles carry issue constraints")
}
