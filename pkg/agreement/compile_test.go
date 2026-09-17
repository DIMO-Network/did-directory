package agreement

import (
	"testing"
	"time"

	"github.com/DIMO-Network/did-directory/pkg/delegation"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// compile runs the compiler against the worked example catalog and asserts that
// everything it produces would be accepted by an org host. A grant this package
// emits that CheckCommit rejects is a bug here, not at the commit.
func compile(t *testing.T, a *Agreement, now time.Time) map[string]delegation.Record {
	t.Helper()
	grants, err := Compile(a, RentalCatalog(), now)
	require.NoError(t, err)

	byKey := map[string]delegation.Record{}
	for i := range grants {
		g := &grants[i]
		assert.NoError(t, delegation.CheckCommit(&g.Record, delegation.CommitContext{
			From:            delegation.Party{Kind: delegation.KindOrg, Operator: true},
			CoveredVehicles: 1,
			Policy:          CommitPolicy(),
		}), g.Key)
		byKey[g.Key] = g.Record
	}
	assert.Len(t, byKey, len(grants), "keys must be unique")
	return byKey
}

func keys(m map[string]delegation.Record) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	return out
}

// A paid booking compiles to custody plus history: two records, because custody
// dies at return and the window the renter drove does not.
func TestPaidBookingCompilesCustodyAndHistory(t *testing.T) {
	a := booking()
	got := compile(t, &a, day(10))
	assert.ElementsMatch(t, []string{"bk-1/custody", "bk-1/history"}, keys(got))

	custody := got["bk-1/custody"]
	assert.Equal(t, delegation.TypeDelegation, custody.Type)
	assert.Equal(t, avis, custody.From)
	assert.Equal(t, renter, custody.To)
	assert.Equal(t, delegation.Covers{Vehicle: car}, custody.Covers)
	assert.Equal(t, []string{"command:unlock", "command:lock", "command:charge"}, custody.Abilities)
	// The operator cannot lock a car somebody else is driving.
	assert.Equal(t, custody.Abilities, custody.Exclusive)
	// Live grants activate on the booking window, never on a pickup record.
	assert.Equal(t, day(10), *custody.Validity.From)
	assert.Equal(t, day(15), *custody.Validity.To)
	assert.Equal(t, delegation.Drop, custody.AfterTransfer)
	assert.Equal(t, "sha256:9f2c", custody.Terms)
	assert.Equal(t, backend, custody.CreatedBy)
	assert.Equal(t, day(10), custody.CreatedAt)

	history := got["bk-1/history"]
	assert.Equal(t, []string{"telemetry:read"}, history.Abilities)
	assert.Empty(t, history.Exclusive)
	assert.Equal(t, day(15).Add(30*24*time.Hour), *history.Validity.To)
	assert.Equal(t, delegation.RetainHistory, history.AfterTransfer)
	// Before any custody event syncs, the data window is the booking window: the
	// renter must be able to read the drive they are on.
	assert.Equal(t, day(10), *history.DataWindow.From)
	assert.Equal(t, day(15), *history.DataWindow.To)
}

// The purchase is what creates the access. Until the payment duty is discharged
// there is nothing to mint, and elapsed time never discharges it.
func TestUnpaidBookingCompilesNothing(t *testing.T) {
	a := booking()
	a.Duties[0].FulfilledAt = nil
	a.State = StateBooked
	assert.Empty(t, compile(t, &a, day(10)))
	assert.Empty(t, compile(t, &a, day(14)))

	a.Duties[0].FulfilledAt = tp(day(9))
	assert.Len(t, compile(t, &a, day(10)), 2)
}

// A cancelled booking compiles to nothing at all, history included: the customer
// never drove the car.
func TestCancelledBookingCompilesNothing(t *testing.T) {
	a := booking()
	a.State = StateCancelled
	a.Timestamps.CancelledAt = tp(day(9))
	assert.Empty(t, compile(t, &a, day(10)))
	assert.Empty(t, compile(t, &a, day(30)))
}

// A renter books a class and gets a specific car, often minutes before pickup.
// A grant has to name the car it opens, so nothing compiles until the desk
// assigns one — and everything compiles the moment it does.
func TestVehicleAssignedAtPickup(t *testing.T) {
	a := booking()
	a.Target = Target{Class: "suv-intermediate"}
	assert.Empty(t, compile(t, &a, day(10)))

	a.Target.Vehicle = car
	a.Target.AssignedAt = tp(day(10))
	got := compile(t, &a, day(10))
	assert.Len(t, got, 2)
	assert.Equal(t, car, got["bk-1/custody"].Covers.Vehicle)
}

// Custody dies at return; history keeps exactly the window the renter drove and
// stays separately revocable. This is the reason they are two records.
func TestEarlyReturn(t *testing.T) {
	a := booking()
	a.Custody = []Custody{{Start: day(10), End: tp(day(12))}}
	a.State = StateReturned

	got := compile(t, &a, day(12).Add(time.Hour))
	assert.ElementsMatch(t, []string{"bk-1/history"}, keys(got))

	history := got["bk-1/history"]
	// Custody narrowed the data window after the fact: the renter keeps day 10
	// to day 12, not the booking's day 10 to day 15.
	assert.Equal(t, day(10), *history.DataWindow.From)
	assert.Equal(t, day(12), *history.DataWindow.To)
	// Retention runs from the real return, not the scheduled one.
	assert.Equal(t, day(12).Add(30*24*time.Hour), *history.Validity.To)
}

// When the retention term runs out the history grant stops being produced. The
// caller treats a record it no longer sees as revoked.
func TestRetentionExpiry(t *testing.T) {
	a := booking()
	a.Custody = []Custody{{Start: day(10), End: tp(day(15))}}
	a.State = StateClosed
	a.Timestamps.ClosedAt = tp(day(15))

	assert.Len(t, compile(t, &a, day(20)), 1)
	assert.Len(t, compile(t, &a, day(44)), 1)
	assert.Empty(t, compile(t, &a, day(46)))

	// No retention duty means open-ended: still there a year later.
	a.Duties = a.Duties[:2]
	assert.Len(t, compile(t, &a, day(400)), 1)
}

// A purchased waiver adds the insurer's grant. An unpurchased one does not, and
// no line item means no insurer even though the catalog declares the offer.
func TestWaiverAddsInsurerGrant(t *testing.T) {
	a := booking()
	assert.NotContains(t, keys(compile(t, &a, day(10))), "bk-1/insurer")

	a.Services = append(a.Services, Service{
		Code:        "waiver",
		Beneficiary: insurer,
		Term:        delegation.Window{From: tp(day(1)), To: tp(day(400))},
	})
	got := compile(t, &a, day(10))
	assert.ElementsMatch(t, []string{"bk-1/custody", "bk-1/history", "bk-1/insurer"}, keys(got))

	ins := got["bk-1/insurer"]
	assert.Equal(t, insurer, ins.To)
	assert.Equal(t, []string{"events:read"}, ins.Abilities)
	// Validity is the policy term; what it may read is only the customer's drive.
	assert.Equal(t, day(400), *ins.Validity.To)
	assert.Equal(t, day(15), *ins.DataWindow.To)

	// The insurer's grant survives the return, like the renter's history.
	a.Custody = []Custody{{Start: day(10), End: tp(day(12))}}
	a.State = StateReturned
	got = compile(t, &a, day(13))
	assert.ElementsMatch(t, []string{"bk-1/history", "bk-1/insurer"}, keys(got))
	assert.Equal(t, day(12), *got["bk-1/insurer"].DataWindow.To)
}

// Roadside exists only while something is wrong.
func TestRoadsideOnlyWhileIncidentIsOpen(t *testing.T) {
	a := booking()
	a.Services = append(a.Services, Service{Code: "roadside"})

	// Purchased, but nothing has happened.
	assert.NotContains(t, keys(compile(t, &a, day(11))), "bk-1/roadside/i1")

	a.Incidents = []Incident{{ID: "i1", Responder: roadside, OpenedAt: day(11), ClosedAt: tp(day(12))}}
	assert.NotContains(t, keys(compile(t, &a, day(10))), "bk-1/roadside/i1", "not yet opened")

	got := compile(t, &a, day(11).Add(time.Hour))
	require.Contains(t, got, "bk-1/roadside/i1")
	rs := got["bk-1/roadside/i1"]
	assert.Equal(t, roadside, rs.To)
	assert.Equal(t, []string{"location:precise"}, rs.Abilities)
	assert.Equal(t, day(11), *rs.Validity.From)
	assert.Equal(t, day(12), *rs.Validity.To)
	assert.Equal(t, rs.Validity, rs.DataWindow)

	assert.NotContains(t, keys(compile(t, &a, day(13))), "bk-1/roadside/i1", "closed")

	// Two incidents open at once get one grant each, keyed by incident.
	a.Incidents = []Incident{
		{ID: "i1", Responder: roadside, OpenedAt: day(11)},
		{ID: "i2", Responder: "did:dimo:tow", OpenedAt: day(11)},
	}
	got = compile(t, &a, day(12))
	assert.Contains(t, got, "bk-1/roadside/i1")
	assert.Contains(t, got, "bk-1/roadside/i2")
}

// The provider already holds every ability as controller of record, and a
// delegation record cannot name the same principal twice. An in-house roadside
// desk therefore compiles to nothing rather than to an invalid record.
func TestSelfGrantIsNotWritten(t *testing.T) {
	a := booking()
	a.Services = append(a.Services, Service{Code: "roadside"})
	a.Incidents = []Incident{{ID: "i1", Responder: avis, OpenedAt: day(11)}}
	assert.ElementsMatch(t, []string{"bk-1/custody", "bk-1/history"}, keys(compile(t, &a, day(12))))
}

// Peer to peer is the same chain: the host's listing delegation is the basis and
// it carries onto every compiled grant.
func TestBasisIsCarriedOntoEveryGrant(t *testing.T) {
	a := booking()
	a.Basis = []string{"at://did:dimo:host/network.dimo.delegation/listing-9"}
	for key, rec := range compile(t, &a, day(10)) {
		assert.Equal(t, a.Basis, rec.Basis, key)
	}
}

// Compilation is a pure function of the agreement and the time, so the same
// inputs give the same records in the same order.
func TestCompileIsDeterministic(t *testing.T) {
	a := booking()
	a.Services = append(a.Services, Service{Code: "roadside"})
	a.Incidents = []Incident{{ID: "i1", Responder: roadside, OpenedAt: day(11)}}

	first, err := Compile(&a, RentalCatalog(), day(12))
	require.NoError(t, err)
	second, err := Compile(&a, RentalCatalog(), day(12))
	require.NoError(t, err)
	assert.Equal(t, first, second)
	assert.Equal(t, []string{"custody", "history", "roadside"},
		[]string{first[0].Offer, first[1].Offer, first[2].Offer})
}

func TestCompileErrors(t *testing.T) {
	t.Run("invalid agreement", func(t *testing.T) {
		a := booking()
		a.Type = "x"
		_, err := Compile(&a, RentalCatalog(), day(10))
		assert.Error(t, err)
	})

	t.Run("unknown service", func(t *testing.T) {
		a := booking()
		a.Services = []Service{{Code: "limousine"}}
		_, err := Compile(&a, RentalCatalog(), day(10))
		assert.ErrorIs(t, err, ErrUnknownService)
	})

	t.Run("missing beneficiary", func(t *testing.T) {
		a := booking()
		a.Services = []Service{{Code: "waiver", Term: span(1, 400)}}
		_, err := Compile(&a, RentalCatalog(), day(10))
		assert.ErrorIs(t, err, ErrNoBeneficiary)
	})

	t.Run("missing term", func(t *testing.T) {
		a := booking()
		a.Services = []Service{{Code: "waiver", Beneficiary: insurer}}
		_, err := Compile(&a, RentalCatalog(), day(10))
		assert.ErrorIs(t, err, ErrNoTerm)
	})

	t.Run("unbounded booking", func(t *testing.T) {
		a := booking()
		a.Window.To = nil
		a.Duties = a.Duties[:1]
		_, err := Compile(&a, RentalCatalog(), day(10))
		assert.ErrorIs(t, err, ErrUnboundedBooking)
	})

	t.Run("invalid offer", func(t *testing.T) {
		a := booking()
		_, err := Compile(&a, Catalog{"rental": {{Name: "x", To: ToCustomer}}}, day(10))
		assert.Error(t, err)
	})

	t.Run("duplicate grant", func(t *testing.T) {
		cat := RentalCatalog()
		cat["upgrade"] = []Offer{{
			Name: "custody", To: ToCustomer, Abilities: []string{"stream:live"},
			Validity: ScopeBooking, DataWindow: ScopeUnbounded,
		}}
		a := booking()
		a.Services = append(a.Services, Service{Code: "upgrade"})
		_, err := Compile(&a, cat, day(10))
		assert.ErrorIs(t, err, ErrDuplicateGrant)
	})

	t.Run("record the delegation package would reject", func(t *testing.T) {
		cat := Catalog{"rental": {{
			Name: "inherit-without-basis", To: ToCustomer, Abilities: []string{"telemetry:read"},
			Validity: ScopeBooking, DataWindow: ScopeUnbounded,
			Redelegate: delegation.Redelegate{Mode: delegation.RedelegateAttenuated},
		}}}
		a := booking()
		_, err := Compile(&a, cat, day(10))
		assert.Error(t, err)
	})
}

// An unbounded data window is legitimate for a grant that reads no data, and the
// compiler must not mistake it for an empty one.
func TestUnboundedDataWindow(t *testing.T) {
	cat := Catalog{"rental": {{
		Name: "stream", To: ToCustomer, Abilities: []string{"stream:live"},
		Validity: ScopeBooking, DataWindow: ScopeUnbounded,
	}}}
	a := booking()
	grants, err := Compile(&a, cat, day(10))
	require.NoError(t, err)
	require.Len(t, grants, 1)
	assert.Nil(t, grants[0].Record.DataWindow.From)
	assert.Nil(t, grants[0].Record.DataWindow.To)
}

// The booking profile is what makes machine-written custody possible: the
// default policy puts two admins behind every live ability, which no operator
// writing thousands of bookings a day can produce per booking.
func TestCommitPolicy(t *testing.T) {
	a := booking()
	grants, err := Compile(&a, RentalCatalog(), day(10))
	require.NoError(t, err)

	from := delegation.Party{Kind: delegation.KindOrg, Operator: true}
	custody := grants[0].Record
	assert.ErrorIs(t,
		delegation.CheckCommit(&custody, delegation.CommitContext{From: from, CoveredVehicles: 1}),
		delegation.ErrApprovalRequired)
	assert.NoError(t,
		delegation.CheckCommit(&custody, delegation.CommitContext{From: from, CoveredVehicles: 1, Policy: CommitPolicy()}))

	p := CommitPolicy()
	assert.Equal(t, delegation.DefaultApprovalThreshold, p.VehicleApprovalThreshold)
	assert.Equal(t, delegation.MaxChainDepth, p.MaxChainDepth)
}
