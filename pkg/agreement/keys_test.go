package agreement

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Keys is every key the booking could ever compile to, whatever its state, so
// a booking service can find what an earlier compilation wrote without asking
// the host to list by prefix.
func TestKeys(t *testing.T) {
	a := booking()
	a.Services = append(a.Services,
		Service{Code: "waiver", Beneficiary: insurer, Term: span(1, 400)},
		Service{Code: "roadside"},
	)
	a.Incidents = []Incident{
		{ID: "inc-1", Responder: roadside, OpenedAt: day(11), ClosedAt: tp(day(11).Add(time.Hour))},
		{ID: "inc-2", Responder: roadside, OpenedAt: day(12)},
	}

	keys, err := Keys(&a, RentalCatalog())
	require.NoError(t, err)
	assert.Equal(t, []string{
		"bk-1:rental:custody", "bk-1:rental:history",
		"bk-1:waiver:insurer",
		"bk-1:roadside:roadside:inc-1", "bk-1:roadside:roadside:inc-2",
	}, keys, "closed incidents included: their grants are the ones to find and revoke")

	// Everything Compile produces, in any state, is in the set.
	for _, now := range []time.Time{day(9), day(11), day(13), day(60)} {
		for _, g := range mustCompile(t, &a, now) {
			assert.Contains(t, keys, g.Key)
		}
	}

	// An unpaid booking compiles to nothing and still has keys, because a
	// cancellation before pickup is exactly when they matter.
	unpaid := booking()
	unpaid.Duties[0].FulfilledAt = nil
	got, err := Compile(&unpaid, RentalCatalog(), day(11))
	require.NoError(t, err)
	assert.Empty(t, got)
	keys, err = Keys(&unpaid, RentalCatalog())
	require.NoError(t, err)
	assert.Equal(t, []string{"bk-1:rental:custody", "bk-1:rental:history"}, keys)

	// The same refusals as Compile, even when Compile would not get as far.
	bad := booking()
	bad.ID = "bk/1"
	bad.Duties[0].FulfilledAt = nil
	_, err = Keys(&bad, RentalCatalog())
	assert.ErrorIs(t, err, ErrBadKey)
	unknown := booking()
	unknown.Services = []Service{{Code: "valet"}}
	_, err = Keys(&unknown, RentalCatalog())
	assert.ErrorIs(t, err, ErrUnknownService)
	dup := booking()
	dup.Services = append(dup.Services, Service{Code: "rental"})
	_, err = Keys(&dup, RentalCatalog())
	assert.ErrorIs(t, err, ErrDuplicateGrant)
}
