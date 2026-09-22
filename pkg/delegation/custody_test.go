package delegation

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// rentalHistory is the history half of a booking (§12.1): the renter keeps the
// data from their rental long after the car goes back, so its validity outlives
// the booking while its data window is the booking, narrowed to custody.
func rentalHistory(t *testing.T) (*memResolver, *Evaluator, string) {
	t.Helper()
	r := newResolver()
	r.parties[renter] = Party{Kind: KindPerson}
	r.control(t, car, avis)

	rec := delegation(avis, renter, Covers{Vehicle: car}, "telemetry:read")
	rec.DataWindow = Window{From: tp(day(2)), To: tp(day(9))}
	rec.Validity = Window{From: tp(day(2))}
	rec.NarrowToCustody = true
	u := uri(avis, "booking-history")
	r.put(u, rec, day(1))
	return r, &Evaluator{Resolver: r}, u
}

// Someone who brings the car back on day 4 keeps the days they drove, not the
// week they booked.
func TestCustody_EarlyReturnEndsTheDataWindow(t *testing.T) {
	r, e, u := rentalHistory(t)
	r.hold(car, renter, day(2), tp(day(4)))

	cov, err := e.Coverage(ctx, u, car, day(20))
	require.NoError(t, err)
	assert.Equal(t, Span(tp(day(2)), tp(day(4))), cov.Historical["telemetry:read"])
}

// A booking nobody turned up for grants nothing, and another person's custody of
// the same car is not yours.
func TestCustody_NoPickupNoData(t *testing.T) {
	r, e, u := rentalHistory(t)
	_, err := e.Coverage(ctx, u, car, day(20))
	assert.ErrorIs(t, err, ErrNotCovered)

	r.hold(car, bob, day(2), tp(day(4)))
	_, err = e.Coverage(ctx, u, car, day(20))
	assert.ErrorIs(t, err, ErrNotCovered)
}

// The car is still out, so the window runs through now and keeps up with the
// data still being produced. Closing the period at return is what narrows it.
func TestCustody_OpenPeriodRunsToNow(t *testing.T) {
	r, e, u := rentalHistory(t)
	r.hold(car, renter, day(3), nil)

	cov, err := e.Coverage(ctx, u, car, day(5))
	require.NoError(t, err)
	w := cov.Historical["telemetry:read"]
	assert.Equal(t, Span(tp(day(3)), tp(day(9))), w)
	assert.True(t, w.Contains(day(5)), "data from today, while the car is still out")
	assert.False(t, w.Contains(day(2)), "not the day before pickup, booked or not")
}

// One agreement, a car taken and brought back twice: two windows, and the days
// in between belong to nobody.
func TestCustody_TwoPeriodsUnderOneAgreement(t *testing.T) {
	r, e, u := rentalHistory(t)
	r.hold(car, renter, day(2), tp(day(3)))
	r.hold(car, renter, day(6), tp(day(7)))

	cov, err := e.Coverage(ctx, u, car, day(20))
	require.NoError(t, err)
	assert.Equal(t, Span(tp(day(2)), tp(day(3))).Union(Span(tp(day(6)), tp(day(7)))), cov.Historical["telemetry:read"])
	assert.False(t, cov.Historical["telemetry:read"].Contains(day(4)), "the days it sat on the lot are not the renter's")
}

// The circularity §12.3 rules out: the renter takes custody by unlocking the
// car, so the unlock cannot wait on a custody record. Live abilities answer to
// the booking window and to exclusivity, never to custody.
func TestCustody_LiveAbilitiesAreNotNarrowed(t *testing.T) {
	r := newResolver()
	r.control(t, car, avis)

	custody := delegation(avis, renter, Covers{Vehicle: car}, "command:unlock", "telemetry:read")
	custody.Validity = Window{From: tp(day(2)), To: tp(day(9))}
	custody.DataWindow = Window{From: tp(day(2)), To: tp(day(9))}
	custody.NarrowToCustody = true
	u := uri(avis, "custody")
	r.put(u, custody, day(1))

	e := &Evaluator{Resolver: r}
	atPickup, err := e.Coverage(ctx, u, car, day(2))
	require.NoError(t, err)
	assert.Equal(t, []string{"command:unlock"}, atPickup.Live, "the door opens before any custody record exists")
	assert.Empty(t, atPickup.Historical["telemetry:read"])

	r.hold(car, renter, day(2), nil)
	driving, err := e.Coverage(ctx, u, car, day(3))
	require.NoError(t, err)
	assert.Equal(t, Span(tp(day(2)), tp(day(9))), driving.Historical["telemetry:read"], "the record syncs and the data follows")
}

// Everything else is untouched: a grant that does not opt in reads its whole
// data window whatever the custody log says.
func TestCustody_NotOptedInIsUnaffected(t *testing.T) {
	r, e, u := rentalHistory(t)
	r.hold(car, renter, day(2), tp(day(4)))
	r.records[u].Record.NarrowToCustody = false

	cov, err := e.Coverage(ctx, u, car, day(20))
	require.NoError(t, err)
	assert.Equal(t, Span(tp(day(2)), tp(day(9))), cov.Historical["telemetry:read"])
}
