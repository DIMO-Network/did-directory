package delegation

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// fcTag is a tag in Ford Credit's own repository, used to scope its staff.
var fcTag = "at://" + fordCredit + "/" + CollectionTag + "/analysts"

// Authority comes from what the repository witnessed, never from inside the
// signed record. A record that simply omits createdBy must not thereby escape
// the role that authorized it.
func TestAuthority_CommittedByIsNotSelfAsserted(t *testing.T) {
	r, e, role := bookingFleet(t)
	role.Record.Constraints = bookingLimits()

	grab := delegation(avis, thief, Covers{Tag: flTag}, "command:unlock", "telemetry:read")
	u := uri(avis, "grab")
	s := r.put(u, grab, day(2))
	s.CommittedBy = booking // what the host authenticated
	require.Empty(t, s.Record.CreatedBy, "the record says nothing about who wrote it")

	_, err := e.Coverage(ctx, u, car, day(10))
	assert.ErrorIs(t, err, ErrExceedsRole, "omitting createdBy must not escape the role")
	assert.ErrorContains(t, err, "covers 2 vehicles, limit 1")

	// The audit copy agreeing with the witness changes nothing.
	s.Record.CreatedBy = booking
	_, err = e.Coverage(ctx, u, car, day(10))
	assert.ErrorIs(t, err, ErrExceedsRole)

	// And an audit copy that contradicts the witness is a lie, not a widening.
	s.Record.CreatedBy = avis
	_, err = e.Coverage(ctx, u, car, day(10))
	assert.ErrorContains(t, err, "createdBy")
}

// A claim of authorship the repository never witnessed is refused rather than
// trusted: the claim lives inside the record, so believing it would hand
// authorship back to whoever wrote the record.
func TestAuthority_ClaimWithoutAWitnessIsRefused(t *testing.T) {
	r, e, u := avisFleet(t)
	r.records[u].Record.CreatedBy = alice
	r.role(avis, alice, Covers{Inherit: true},
		[]string{"delegation:create", "telemetry:read", "location:precise", "command:unlock"}, day(1))

	_, err := e.Coverage(ctx, u, car, day(10))
	assert.ErrorContains(t, err, "witnessed no author")

	r.records[u].CommittedBy = alice
	_, err = e.Coverage(ctx, u, car, day(10))
	assert.NoError(t, err)
}

// Self-dealing keys off the witnessed author too: a member who writes themselves
// a grant and leaves createdBy blank is still writing themselves a grant.
func TestAuthority_SelfDealingUsesTheWitness(t *testing.T) {
	r := newResolver()
	r.control(t, car, avis)
	r.role(avis, alice, Covers{Inherit: true}, []string{"delegation:create", "command:unlock"}, day(1))
	r.role(avis, bob, Covers{Inherit: true}, []string{"delegation:create", "command:unlock"}, day(1))

	rec := delegation(avis, alice, Covers{Vehicle: car}, "command:unlock")
	u := uri(avis, "self")
	s := r.put(u, rec, day(2))
	s.CommittedBy = alice

	e := &Evaluator{Resolver: r}
	_, err := e.Coverage(ctx, u, car, day(3))
	assert.ErrorIs(t, err, ErrSelfDealing)

	s.ApprovedBy = []string{bob}
	_, err = e.Coverage(ctx, u, car, day(3))
	assert.NoError(t, err)

	// And the writer is told before it is ever committed.
	assert.Contains(t,
		ApprovalReasons(&rec, CommitContext{CommittedBy: alice, CoveredVehicles: 1}),
		"author is the recipient")
}

// Recovery is exclusivity's override, so a basis that never permitted an
// exclusive claim cannot be redelegated into one that beats somebody else's.
func TestNarrows_RecoveryNeedsTheSamePermissionAsExclusivity(t *testing.T) {
	r := newResolver()
	r.parties[renter] = Party{Kind: KindPerson}
	r.control(t, car, avis)

	// A third party is driving the car.
	custody := delegation(avis, renter, Covers{Vehicle: car}, "command:unlock")
	custody.Exclusive = []string{"command:unlock"}
	custody.Validity = Window{From: tp(day(2)), To: tp(day(5))}
	r.put(uri(avis, "custody"), custody, day(1))

	// A plain redelegable grant: no exclusivity permission anywhere in it.
	parent := delegation(avis, platform, Covers{Vehicle: car}, "command:unlock")
	parent.Redelegate = Redelegate{Mode: RedelegateAttenuated, MaxDepth: 2}
	pu := uri(avis, "toplatform")
	r.put(pu, parent, day(1))

	child := delegation(platform, insurer, Covers{Inherit: true}, "command:unlock")
	child.Recovery = true
	child.Basis = []string{pu}
	cu := uri(platform, "self-declared-recovery")
	r.put(cu, child, day(1))

	e := &Evaluator{Resolver: r}
	_, err := e.Coverage(ctx, cu, car, day(3))
	assert.ErrorIs(t, err, ErrNotNarrowing, "recovery overrides a custody hold, so the basis must permit it")

	// The sibling without the flag was already refused, for the right reason.
	sibling := child
	sibling.Recovery = false
	su := uri(platform, "sibling")
	r.put(su, sibling, day(1))
	_, err = e.Coverage(ctx, su, car, day(3))
	assert.ErrorIs(t, err, ErrExclusiveHold)

	// Permitting exclusivity permits its override, and the use is flagged.
	r.records[pu].Record.Redelegate.Exclusive = true
	cov, err := e.Coverage(ctx, cu, car, day(3))
	require.NoError(t, err)
	assert.Equal(t, []string{"command:unlock"}, cov.Live)
	assert.True(t, cov.RecoveryUsed)
}

// Permission to claim exclusivity is the controller's to hand out. A partner
// holding a plain redelegable grant cannot switch it on for its own children,
// or its grandchild's hold would suspend the controller's commands (§12.2).
func TestNarrows_ExclusiveRedelegationNeedsTheBasis(t *testing.T) {
	r := newResolver()
	r.control(t, car, avis)

	// Avis's own crew holds the commands directly.
	crew := delegation(avis, alice, Covers{Vehicle: car}, "command:lock")
	cru := uri(avis, "crew")
	r.put(cru, crew, day(1))

	// Ford Pro may redelegate twice, but was never permitted exclusivity.
	fp := delegation(avis, fordPro, Covers{Vehicle: car}, "command:lock")
	fp.Redelegate = Redelegate{Mode: RedelegateAttenuated, MaxDepth: 2}
	fpu := uri(avis, "fordpro")
	r.put(fpu, fp, day(1))

	// Ford Pro turns exclusivity on for the integrator ...
	in := delegation(fordPro, integrator, Covers{Inherit: true}, "command:lock")
	in.Basis = []string{fpu}
	in.Redelegate = Redelegate{Mode: RedelegateAttenuated, MaxDepth: 1, Exclusive: true}
	inu := uri(fordPro, "integrator")
	r.put(inu, in, day(1))

	// ... and the integrator claims the commands exclusively.
	hold := delegation(integrator, marketing, Covers{Inherit: true}, "command:lock")
	hold.Basis = []string{inu}
	hold.Exclusive = []string{"command:lock"}
	hu := uri(integrator, "hold")
	r.put(hu, hold, day(2))

	e := &Evaluator{Resolver: r}
	_, err := e.Coverage(ctx, inu, car, day(3))
	assert.ErrorIs(t, err, ErrNotNarrowing)
	_, err = e.Coverage(ctx, hu, car, day(3))
	assert.ErrorIs(t, err, ErrNotNarrowing)
	cov, err := e.Authorize(ctx, cru, alice, "", car, []string{"command:lock"}, day(3))
	require.NoError(t, err, "a hold whose chain does not narrow suspends nobody")
	assert.Equal(t, []string{"command:lock"}, cov.Live)

	// Once Avis permits it, the chain holds and the hold is in force.
	r.records[fpu].Record.Redelegate.Exclusive = true
	_, err = e.Coverage(ctx, hu, car, day(3))
	require.NoError(t, err)
	_, err = e.Authorize(ctx, cru, alice, "", car, []string{"command:lock"}, day(3))
	assert.ErrorIs(t, err, ErrExclusiveHold)
}

// An allowlist bounds who, not how many, so it cannot silently turn an
// attenuated basis's two remaining hops into an unbounded chain.
func TestNarrows_AllowlistChildSpendsTheAttenuatedBudget(t *testing.T) {
	r := newResolver()
	r.control(t, car, avis)
	parent := delegation(avis, fordPro, Covers{Vehicle: car}, "telemetry:read")
	parent.Redelegate = Redelegate{Mode: RedelegateAttenuated, MaxDepth: 2}
	pu := uri(avis, "p")
	r.put(pu, parent, day(1))

	child := delegation(fordPro, integrator, Covers{Inherit: true}, "telemetry:read")
	child.Redelegate = Redelegate{Mode: RedelegateAllowlist, Grantees: []string{marketing}}
	child.Basis = []string{pu}
	cu := uri(fordPro, "c")
	s := r.put(cu, child, day(2))

	e := &Evaluator{Resolver: r}
	_, err := e.Coverage(ctx, cu, car, day(3))
	assert.ErrorIs(t, err, ErrNotNarrowing, "an unbounded allowlist cannot spend a bounded budget")

	// Naming the remaining depth is within the basis.
	s.Record.Redelegate.MaxDepth = 1
	_, err = e.Coverage(ctx, cu, car, day(3))
	assert.NoError(t, err)

	// Claiming more than was paid for is not.
	s.Record.Redelegate.MaxDepth = 2
	_, err = e.Coverage(ctx, cu, car, day(3))
	assert.ErrorIs(t, err, ErrNotNarrowing)
}

// A tag-scoped staff role must be able to exercise a delegation addressed to
// their org, exactly as an org-wide one can. hasRole already agrees.
func TestUseRole_TagScopedStaffCanExerciseTheGrant(t *testing.T) {
	r, e, u := avisFleet(t)
	r.join(fcTag, car, fordCredit, day(1), nil)
	r.role(fordCredit, fcAnalyst, Covers{Tag: fcTag}, []string{"location:precise"}, day(1))

	cov, err := e.Authorize(ctx, u, fcAnalyst, "", car, []string{"location:precise"}, day(10))
	require.NoError(t, err)
	assert.Equal(t, Span(tp(day(3)), nil), cov.Historical["location:precise"])

	// A car outside the role's tag is still out of scope.
	r.control(t, otherCar, avis)
	r.join(flTag, otherCar, avis, day(3), nil)
	_, err = e.Authorize(ctx, u, fcAnalyst, "", otherCar, []string{"location:precise"}, day(10))
	assert.ErrorIs(t, err, ErrUnauthorized)
}

// A policy a caller built by hand is the policy in force. Replacing it wholesale
// because it carries no name both loosens and tightens it, silently.
func TestPolicy_CallerBuiltPolicyIsKept(t *testing.T) {
	p := Policy{VehicleApprovalThreshold: 10, MaxChainDepth: 2, AllowIrrevocableFromNonOperator: true}
	got := p.orDefault()
	assert.Equal(t, 10, got.VehicleApprovalThreshold)
	assert.Equal(t, 2, got.MaxChainDepth)
	assert.True(t, got.AllowIrrevocableFromNonOperator)

	// The genuinely zero policy is still the default profile.
	assert.Equal(t, DefaultPolicy(), Policy{}.orDefault())

	// And unset fields fall back field by field, not all or nothing.
	partial := Policy{Name: "eu-consumer"}.orDefault()
	assert.Equal(t, DefaultApprovalThreshold, partial.VehicleApprovalThreshold)
	assert.Equal(t, MaxChainDepth, partial.MaxChainDepth)
	assert.Equal(t, "eu-consumer", partial.Name)
}

// The evaluator's own chain depth follows the policy the caller built, too.
func TestPolicy_CallerBuiltDepthIsEnforced(t *testing.T) {
	r := newResolver()
	r.control(t, car, avis)
	parent := delegation(avis, fordPro, Covers{Vehicle: car}, "telemetry:read")
	parent.Redelegate = Redelegate{Mode: RedelegateAttenuated, MaxDepth: 2}
	pu := uri(avis, "p")
	r.put(pu, parent, day(1))

	child := delegation(fordPro, integrator, Covers{Inherit: true}, "telemetry:read")
	child.Redelegate = Redelegate{Mode: RedelegateAttenuated, MaxDepth: 1}
	child.Basis = []string{pu}
	cu := uri(fordPro, "c")
	r.put(cu, child, day(2))

	grand := delegation(integrator, marketing, Covers{Inherit: true}, "telemetry:read")
	grand.Basis = []string{cu}
	gu := uri(integrator, "g")
	r.put(gu, grand, day(3))

	shallow := &Evaluator{Resolver: r, Policy: Policy{VehicleApprovalThreshold: 10, MaxChainDepth: 2}}
	_, err := shallow.Coverage(ctx, gu, car, day(4))
	assert.ErrorIs(t, err, ErrChainTooDeep)
}

// Authorize is the path an issuer actually calls, so it must carry the same
// audit facts Coverage reports: the one operation that overrides a renter's
// custody is exactly the one worth logging.
func TestAuthorize_ReportsRecoveryAndSuspension(t *testing.T) {
	r := newResolver()
	r.parties[renter] = Party{Kind: KindPerson}
	r.control(t, car, avis)

	custody := delegation(avis, renter, Covers{Vehicle: car}, "command:unlock")
	custody.Exclusive = []string{"command:unlock"}
	custody.Validity = Window{From: tp(day(2)), To: tp(day(5))}
	r.put(uri(avis, "custody"), custody, day(1))

	recovery := delegation(avis, insurer, Covers{Vehicle: car}, "command:unlock")
	recovery.Recovery = true
	ru := uri(avis, "recovery")
	r.put(ru, recovery, day(1))

	ops := delegation(avis, fordPro, Covers{Vehicle: car}, "command:unlock", "telemetry:read")
	ou := uri(avis, "ops")
	r.put(ou, ops, day(1))

	e := &Evaluator{Resolver: r}
	cov, err := e.Authorize(ctx, ru, insurer, "", car, []string{"command:unlock"}, day(3))
	require.NoError(t, err)
	assert.Equal(t, []string{"command:unlock"}, cov.Live)
	assert.True(t, cov.RecoveryUsed, "the issuer logs every use of recovery")

	// A partly suspended grant still reports what is suspended alongside what is
	// left, rather than silently returning only the half that worked.
	part, err := e.Authorize(ctx, ou, fordPro, "", car, []string{"command:unlock", "telemetry:read"}, day(3))
	require.NoError(t, err)
	assert.NotEmpty(t, part.Historical["telemetry:read"])
	assert.Empty(t, part.Live)
	assert.Equal(t, []string{"command:unlock"}, part.Suspended)
}

// Two live holds over the same ability is an issuing mistake, and the newer one
// is the one in force. Suspending both locks both parties out of a car one of
// them is driving, which is the outcome §12.5 exists to prevent.
func TestExclusive_OverlappingHoldsDoNotLockBothOut(t *testing.T) {
	r := newResolver()
	r.parties[renter] = Party{Kind: KindPerson}
	r.control(t, car, avis)

	// The previous renter's booking, whose device never synced a return.
	stale := delegation(avis, renter, Covers{Vehicle: car}, "command:unlock")
	stale.Exclusive = []string{"command:unlock"}
	stale.Validity = Window{From: tp(day(2)), To: tp(day(8))}
	su := uri(avis, "stale")
	r.put(su, stale, day(1))

	// The next renter, standing next to the car.
	next := delegation(avis, bob, Covers{Vehicle: car}, "command:unlock")
	next.Exclusive = []string{"command:unlock"}
	next.Validity = Window{From: tp(day(5)), To: tp(day(9))}
	nu := uri(avis, "next")
	r.put(nu, next, day(4))

	e := &Evaluator{Resolver: r}
	cov, err := e.Coverage(ctx, nu, car, day(6))
	require.NoError(t, err, "the newer hold opens the door")
	assert.Equal(t, []string{"command:unlock"}, cov.Live)

	_, err = e.Coverage(ctx, su, car, day(6))
	assert.ErrorIs(t, err, ErrExclusiveHold, "and supersedes the stale one")

	// The operator is blocked by both, which is what exclusivity is for.
	ops := delegation(avis, fordPro, Covers{Vehicle: car}, "command:unlock")
	ou := uri(avis, "ops")
	r.put(ou, ops, day(1))
	_, err = e.Coverage(ctx, ou, car, day(6))
	assert.ErrorIs(t, err, ErrExclusiveHold)
}

// afterTransfer: drop means keep only the era in force. With no era in force
// there is nothing to keep, and quietly keeping everything is the opposite of
// what the record asked for.
func TestTransfer_DropWithNoEraInForce(t *testing.T) {
	r := newResolver()
	r.control(t, car, avis)
	parent := delegation(avis, fordPro, Covers{Vehicle: car}, "telemetry:read")
	parent.Redelegate = Redelegate{Mode: RedelegateAttenuated, MaxDepth: 1}
	pu := uri(avis, "p")
	r.put(pu, parent, day(1))

	child := delegation(fordPro, integrator, Covers{Inherit: true}, "telemetry:read")
	child.Basis = []string{pu}
	child.AfterTransfer = Drop
	cu := uri(fordPro, "c")
	r.put(cu, child, day(2))

	e := &Evaluator{Resolver: r}
	cov, err := e.Coverage(ctx, cu, car, day(5))
	require.NoError(t, err, "while the era is in force, drop keeps it")
	assert.Equal(t, All(), cov.Historical["telemetry:read"])

	// The car leaves DIMO: the era ends and no new one opens.
	r.states[car].Eras[0].End = tp(day(10))
	_, err = e.Coverage(ctx, cu, car, day(20))
	assert.ErrorIs(t, err, ErrNotCovered)
}

// The narrowest role the design offers still hands out an unbounded reach
// backwards unless the data window is bounded too: one compromised booking
// service, one car at a time, and every trip every prior renter took.
func TestRoleConstraints_DataWindowReachIsBounded(t *testing.T) {
	r, e, role := bookingFleet(t)
	limits := bookingLimits()
	limits.MaxDataReach = 24 * time.Hour
	role.Record.Constraints = limits

	rummage := delegation(avis, thief, Covers{Vehicle: car}, "telemetry:read")
	rummage.Validity = Window{From: tp(day(3)), To: tp(day(4))}
	u := uri(avis, "rummage")
	s := r.put(u, rummage, day(2))
	s.CommittedBy = booking

	_, err := e.Coverage(ctx, u, car, day(3))
	assert.ErrorIs(t, err, ErrExceedsRole)
	assert.ErrorContains(t, err, "dataWindow must have a start")

	// Reaching back a week before the booking is not one custody grant.
	s.Record.DataWindow = Window{From: tp(day(-4)), To: tp(day(4))}
	_, err = e.Coverage(ctx, u, car, day(3))
	assert.ErrorIs(t, err, ErrExceedsRole)
	assert.ErrorContains(t, err, "before validity")

	// The booking it is for, plus the day of slack the role allows, is.
	s.Record.DataWindow = Window{From: tp(day(2)), To: tp(day(4))}
	cov, err := e.Coverage(ctx, u, car, day(3))
	require.NoError(t, err)
	assert.Equal(t, Span(tp(day(2)), tp(day(4))), cov.Historical["telemetry:read"])
}
