package delegation

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const (
	host     = "did:dimo:host"     // person who rents out their own car
	platform = "did:dimo:platform" // peer-to-peer marketplace
	renter   = "did:dimo:renter"
)

// A sole proprietor with cars on a platform is an operator even though the DID
// is a person. Entity type must not decide policy.
func TestOperatorStatus_NotEntityType(t *testing.T) {
	r := newResolver()
	r.parties[host] = Party{Kind: KindPerson, Operator: true}
	r.parties[renter] = Party{Kind: KindPerson}
	r.control(t, car, host)

	lien := delegation(host, fordCredit, Covers{Vehicle: car}, "location:precise")
	lien.RevocableBy = RevocableByTo
	u := uri(host, "lien")
	r.put(u, lien, day(1))

	e := &Evaluator{Resolver: r}
	_, err := e.Coverage(ctx, u, car, day(2))
	assert.NoError(t, err, "an attested operator may issue an irrevocable lien")
	assert.NoError(t, CheckCommit(&lien, CommitContext{From: r.parties[host], Approved: true}))

	// The same shape from a consumer is still refused.
	r.parties[host] = Party{Kind: KindPerson}
	_, err = e.Coverage(ctx, u, car, day(2))
	assert.ErrorIs(t, err, ErrLienNotAllowed)

	// Unless the governing policy allows it.
	permissive := &Evaluator{Resolver: r, Policy: Policy{Name: "permissive", AllowIrrevocableFromNonOperator: true}}
	_, err = permissive.Coverage(ctx, u, car, day(2))
	assert.NoError(t, err)
}

// An operating person can hold staff, so roles must not require an org DID.
func TestOperatorCanHoldStaff(t *testing.T) {
	r := newResolver()
	r.parties[host] = Party{Kind: KindPerson, Operator: true}
	r.control(t, car, host)
	r.role(host, bob, Covers{Vehicle: car}, []string{"telemetry:read"}, day(1))

	rec := delegation(host, platform, Covers{Vehicle: car}, "telemetry:read")
	u := uri(host, "toplatform")
	r.put(u, rec, day(1))

	cov, err := (&Evaluator{Resolver: r}).Authorize(ctx, u, platform, "", car, []string{"telemetry:read"}, day(2))
	require.NoError(t, err)
	assert.NotEmpty(t, cov.Historical)

	role := Record{Type: TypeRole, From: host, To: bob, Covers: Covers{Vehicle: car}, Abilities: []string{"telemetry:read"}}
	assert.NoError(t, CheckCommit(&role, CommitContext{From: r.parties[host]}))
}

// Staff are customers too: an employee must not write themselves a grant.
func TestSelfDealing(t *testing.T) {
	r := newResolver()
	r.control(t, car, avis)
	r.role(avis, alice, Covers{Inherit: true}, []string{"delegation:create", "command:unlock"}, day(1))
	r.role(avis, bob, Covers{Inherit: true}, []string{"delegation:create", "command:unlock"}, day(1))

	rec := delegation(avis, alice, Covers{Vehicle: car}, "command:unlock")
	rec.CreatedBy = alice
	u := uri(avis, "self")
	s := r.put(u, rec, day(2))
	s.CommittedBy = alice

	e := &Evaluator{Resolver: r}
	_, err := e.Coverage(ctx, u, car, day(3))
	assert.ErrorIs(t, err, ErrSelfDealing)

	// Approval by the author, or by the recipient, is not approval.
	s.ApprovedBy = []string{alice}
	_, err = e.Coverage(ctx, u, car, day(3))
	assert.ErrorIs(t, err, ErrSelfDealing)

	// A second person who held the same authority at commit time is.
	s.ApprovedBy = []string{bob}
	cov, err := e.Coverage(ctx, u, car, day(3))
	require.NoError(t, err)
	assert.Equal(t, []string{"command:unlock"}, cov.Live)

	// An approver without the authority does not count.
	s.ApprovedBy = []string{fcAnalyst}
	_, err = e.Coverage(ctx, u, car, day(3))
	assert.ErrorIs(t, err, ErrSelfDealing)

	// And the commit-time check flags it before it is ever written.
	assert.ErrorIs(t, CheckCommit(&rec, CommitContext{From: r.parties[avis], CommittedBy: alice, CoveredVehicles: 1}), ErrApprovalRequired)
}

// Custody suspends the operator's commands over that car, with a logged
// recovery path. Historical access is untouched.
func TestCustodySuspendsOperatorCommands(t *testing.T) {
	r := newResolver()
	r.parties[renter] = Party{Kind: KindPerson}
	r.control(t, car, avis)

	custody := delegation(avis, renter, Covers{Vehicle: car}, "command:unlock", "command:lock", "telemetry:read")
	custody.Exclusive = []string{"command:unlock", "command:lock"}
	custody.Validity = Window{From: tp(day(2)), To: tp(day(5))}
	custody.DataWindow = Window{From: tp(day(2)), To: tp(day(5))}
	cu := uri(avis, "custody")
	r.put(cu, custody, day(1))

	ops := delegation(avis, fordPro, Covers{Vehicle: car}, "command:unlock", "telemetry:read")
	ou := uri(avis, "ops")
	r.put(ou, ops, day(1))

	recovery := delegation(avis, insurer, Covers{Vehicle: car}, "command:unlock")
	recovery.Recovery = true
	ru := uri(avis, "recovery")
	r.put(ru, recovery, day(1))

	e := &Evaluator{Resolver: r}

	during, err := e.Coverage(ctx, cu, car, day(3))
	require.NoError(t, err)
	assert.ElementsMatch(t, []string{"command:unlock", "command:lock"}, during.Live, "the renter holds the commands")

	blocked, err := e.Coverage(ctx, ou, car, day(3))
	require.NoError(t, err)
	assert.Empty(t, blocked.Live, "the operator cannot command a car someone else is driving")
	assert.Equal(t, []string{"command:unlock"}, blocked.Suspended)
	assert.NotEmpty(t, blocked.Historical["telemetry:read"], "reading data is unaffected")

	rec, err := e.Coverage(ctx, ru, car, day(3))
	require.NoError(t, err)
	assert.Equal(t, []string{"command:unlock"}, rec.Live, "recovery still works")
	assert.True(t, rec.RecoveryUsed, "and is flagged so the issuer logs it")

	after, err := e.Coverage(ctx, ou, car, day(6))
	require.NoError(t, err)
	assert.Equal(t, []string{"command:unlock"}, after.Live, "the hold ends with custody")
	assert.Empty(t, after.Suspended)
}

// Exclusivity narrows like everything else: a sub-delegate cannot invent a hold
// its basis never had, and can pass on one it did.
func TestExclusivityNarrows(t *testing.T) {
	r := newResolver()
	r.control(t, car, avis)

	parent := delegation(avis, platform, Covers{Vehicle: car}, "command:unlock")
	parent.Redelegate = Redelegate{Mode: RedelegateAttenuated, MaxDepth: 1}
	pu := uri(avis, "toplatform")
	r.put(pu, parent, day(1))

	child := delegation(platform, renter, Covers{Inherit: true}, "command:unlock")
	child.Exclusive = []string{"command:unlock"}
	child.Basis = []string{pu}
	cu := uri(platform, "tocustomer")
	r.put(cu, child, day(1))

	e := &Evaluator{Resolver: r}
	_, err := e.Coverage(ctx, cu, car, day(2))
	assert.ErrorIs(t, err, ErrNotNarrowing, "the basis never permitted an exclusive claim")

	r.records[pu].Record.Redelegate.Exclusive = true
	cov, err := e.Coverage(ctx, cu, car, day(2))
	require.NoError(t, err)
	assert.Equal(t, []string{"command:unlock"}, cov.Live)
}

// One person, two hats, at the same instant: Alice works for Avis and rents from
// Avis this weekend. Each capacity is evaluated on its own chain.
func TestSamePersonBothCapacities(t *testing.T) {
	r := newResolver()
	r.control(t, car, avis)
	r.join(flTag, car, avis, day(1), nil)

	// Employee capacity: a fleet grant Alice uses through her role.
	fleet := delegation(avis, fordPro, Covers{Tag: flTag}, "telemetry:read")
	fu := uri(avis, "fleet")
	r.put(fu, fleet, day(1))
	r.role(fordPro, alice, Covers{Inherit: true}, []string{"telemetry:read"}, day(1))

	// Renter capacity: her own custody grant this weekend.
	custody := delegation(avis, alice, Covers{Vehicle: car}, "command:unlock")
	custody.Exclusive = []string{"command:unlock"}
	custody.Validity = Window{From: tp(day(2)), To: tp(day(4))}
	cu := uri(avis, "alice-weekend")
	r.put(cu, custody, day(1))

	e := &Evaluator{Resolver: r}

	asEmployee, err := e.Authorize(ctx, fu, alice, "", car, []string{"telemetry:read"}, day(3))
	require.NoError(t, err)
	assert.Equal(t, []string{fu}, asEmployee.Chain)
	assert.Empty(t, asEmployee.Live)

	asRenter, err := e.Authorize(ctx, cu, alice, "", car, []string{"command:unlock"}, day(3))
	require.NoError(t, err)
	assert.Equal(t, []string{cu}, asRenter.Chain)
	assert.Equal(t, []string{"command:unlock"}, asRenter.Live)

	// Her employee capacity gives her no commands, custody or not.
	_, err = e.Authorize(ctx, fu, alice, "", car, []string{"command:unlock"}, day(3))
	assert.ErrorIs(t, err, ErrUnauthorized)
}

// Peer-to-peer: consumer host, org platform in the middle, consumer renter.
func TestPeerToPeerChain(t *testing.T) {
	r := newResolver()
	r.parties[host] = Party{Kind: KindPerson}
	r.parties[platform] = Party{Kind: KindOrg, Operator: true}
	r.parties[renter] = Party{Kind: KindPerson}
	r.control(t, car, host)

	listing := delegation(host, platform, Covers{Vehicle: car}, "command:unlock", "telemetry:read")
	listing.Redelegate = Redelegate{Mode: RedelegateAllowlist, Grantees: []string{renter}, Exclusive: true}
	lu := uri(host, "listing")
	r.put(lu, listing, day(1))

	booking := delegation(platform, renter, Covers{Inherit: true}, "command:unlock", "telemetry:read")
	booking.Basis = []string{lu}
	booking.Exclusive = []string{"command:unlock"}
	booking.Validity = Window{From: tp(day(2)), To: tp(day(4))}
	booking.DataWindow = Window{From: tp(day(2)), To: tp(day(4))}
	bu := uri(platform, "booking")
	r.put(bu, booking, day(1))

	e := &Evaluator{Resolver: r}
	cov, err := e.Coverage(ctx, bu, car, day(3))
	require.NoError(t, err)
	assert.Equal(t, []string{"command:unlock"}, cov.Live)
	assert.Equal(t, []string{bu, lu}, cov.Chain)

	// The host keeps reading their own car but cannot unlock it mid-booking.
	hostSide := delegation(host, insurer, Covers{Vehicle: car}, "command:unlock", "telemetry:read")
	hu := uri(host, "insurer")
	r.put(hu, hostSide, day(1))
	hc, err := e.Coverage(ctx, hu, car, day(3))
	require.NoError(t, err)
	assert.Empty(t, hc.Live)
	assert.Equal(t, []string{"command:unlock"}, hc.Suspended)

	// After the booking, control is whole again.
	after, err := e.Coverage(ctx, hu, car, day(5))
	require.NoError(t, err)
	assert.Equal(t, []string{"command:unlock"}, after.Live)

	// The booking's custody grant dies at return, so a second grant carries the
	// renter's own history: same data window, longer validity. This is what the
	// agreement compiles to, and it is separately revocable.
	_, err = e.Coverage(ctx, bu, car, day(5))
	assert.ErrorIs(t, err, ErrNotValid, "custody itself does not outlive the return")

	history := delegation(platform, renter, Covers{Inherit: true}, "telemetry:read")
	history.Basis = []string{lu}
	history.DataWindow = Window{From: tp(day(2)), To: tp(day(4))}
	hu2 := uri(platform, "booking-history")
	r.put(hu2, history, day(1))

	kept, err := e.Coverage(ctx, hu2, car, day(5))
	require.NoError(t, err)
	assert.Equal(t, Span(tp(day(2)), tp(day(4))), kept.Historical["telemetry:read"],
		"the renter keeps the window they drove")
	assert.Empty(t, kept.Live)
}

func TestExclusiveValidation(t *testing.T) {
	r := validRecord()
	r.Exclusive = []string{"command:unlock"}
	assert.ErrorContains(t, r.Validate(), "not granted by this record")

	r.Abilities = []string{"telemetry:read"}
	r.Exclusive = []string{"telemetry:read"}
	assert.ErrorContains(t, r.Validate(), "only live abilities")

	r.Abilities = []string{"telemetry:read"}
	r.Exclusive = nil
	r.Recovery = true
	assert.ErrorContains(t, r.Validate(), "recovery requires")

	ok := validRecord()
	ok.Abilities = []string{"command:unlock"}
	ok.Exclusive = []string{"command:unlock"}
	ok.Recovery = true
	assert.NoError(t, ok.Validate())
	_ = time.Now
}

// A grant whose every ability is suspended must not look like a grant that was
// never made: the operator is told somebody is driving their car.
func TestSuspendedIsNotUncovered(t *testing.T) {
	r := newResolver()
	r.parties[renter] = Party{Kind: KindPerson}
	r.control(t, car, avis)

	custody := delegation(avis, renter, Covers{Vehicle: car}, "command:unlock")
	custody.Exclusive = []string{"command:unlock"}
	custody.Validity = Window{From: tp(day(2)), To: tp(day(5))}
	r.put(uri(avis, "custody"), custody, day(1))

	// Commands only: nothing is left once they are suspended.
	ops := delegation(avis, fordPro, Covers{Vehicle: car}, "command:unlock")
	ou := uri(avis, "ops-commands-only")
	r.put(ou, ops, day(1))

	e := &Evaluator{Resolver: r}
	_, err := e.Coverage(ctx, ou, car, day(3))
	assert.ErrorIs(t, err, ErrExclusiveHold)
	assert.ErrorContains(t, err, "command:unlock")
	assert.NotErrorIs(t, err, ErrNotCovered)

	_, err = e.Authorize(ctx, ou, fordPro, "", car, []string{"command:unlock"}, day(3))
	assert.ErrorIs(t, err, ErrExclusiveHold)

	// An ability nobody holds exclusively still reads as not covered.
	_, err = e.Authorize(ctx, ou, fordPro, "", car, []string{"telemetry:read"}, day(3))
	assert.ErrorIs(t, err, ErrNotCovered)

	// And once custody ends the operator is simply authorized again.
	cov, err := e.Authorize(ctx, ou, fordPro, "", car, []string{"command:unlock"}, day(6))
	require.NoError(t, err)
	assert.Equal(t, []string{"command:unlock"}, cov.Live)
}
