package agreement

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/DIMO-Network/did-directory/pkg/control"
	"github.com/DIMO-Network/did-directory/pkg/delegation"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// fleet is a minimal delegation.Resolver: one car, one controller, and whatever
// records the test commits. It exists so these tests can check that compiled
// records evaluate the way §12 says, not merely that they are well formed.
type fleet struct {
	records map[string]*delegation.Stored
	roles   map[string][]delegation.Stored
	state   *control.State
	opening *control.Opening
	vehicle string
	custody []delegation.CustodyPeriod
}

// hold records that a holder physically had the car, the way a booking service
// or the car's own device would once a pickup or return syncs.
func (f *fleet) hold(holder string, from time.Time, until *time.Time) {
	f.custody = append(f.custody, delegation.CustodyPeriod{
		Vehicle: f.vehicle, Holder: holder, From: from, Until: until,
	})
}

func newFleet(t *testing.T, vehicle, controller string) *fleet {
	t.Helper()
	salt, err := control.NewSalt()
	require.NoError(t, err)
	opening := &control.Opening{Controller: controller, Era: 0, Salt: salt}
	commitment, err := control.Commit(*opening)
	require.NoError(t, err)
	return &fleet{
		records: map[string]*delegation.Stored{},
		roles:   map[string][]delegation.Stored{},
		state:   &control.State{DID: vehicle, Eras: []control.Era{{Number: 0, Commitment: commitment}}},
		opening: opening,
		vehicle: vehicle,
	}
}

func (f *fleet) commit(key string, rec delegation.Record, at time.Time) string {
	uri := "at://" + rec.From + "/" + delegation.TypeDelegation + "/" + key
	f.records[uri] = &delegation.Stored{URI: uri, Record: rec, CommittedAt: at}
	return uri
}

func (f *fleet) Record(_ context.Context, uri string) (*delegation.Stored, error) {
	s, ok := f.records[uri]
	if !ok {
		return nil, fmt.Errorf("record %s not found", uri)
	}
	return s, nil
}

func (f *fleet) Memberships(context.Context, string, string) ([]delegation.Membership, error) {
	return nil, nil
}

// role gives member a constrained role over every car in the fleet. §12 has the
// booking service holding exactly this, and the evaluator insists on it: a
// record whose createdBy is not its issuer is only valid if the author held
// delegation:create plus every ability in the record when it was committed.
func (f *fleet) role(org, member string, abilities []string, at time.Time) {
	key := org + "|" + member
	f.roles[key] = append(f.roles[key], delegation.Stored{
		URI: "at://" + org + "/" + delegation.TypeRole + "/" + member,
		Record: delegation.Record{
			Type: delegation.TypeRole, From: org, To: member,
			Covers: delegation.Covers{Inherit: true}, Abilities: abilities,
		},
		CommittedAt: at,
	})
}

// TagSize and Custody complete the Resolver interface. This fleet holds one car
// and records custody as the booking's own custody events.
func (f *fleet) TagSize(context.Context, string, time.Time) (int, error) { return 1, nil }

func (f *fleet) Custody(_ context.Context, vehicle, holder string) ([]delegation.CustodyPeriod, error) {
	var out []delegation.CustodyPeriod
	for _, c := range f.custody {
		if c.Vehicle == vehicle && c.Holder == holder {
			out = append(out, c)
		}
	}
	return out, nil
}

func (f *fleet) Roles(_ context.Context, org, member string) ([]delegation.Stored, error) {
	return f.roles[org+"|"+member], nil
}

func (f *fleet) ControlState(_ context.Context, vehicle string) (*control.State, error) {
	if vehicle != f.vehicle {
		return &control.State{DID: vehicle}, nil
	}
	return f.state, nil
}

func (f *fleet) Opening(_ context.Context, vehicle string, era uint64, controller string) (*control.Opening, error) {
	if vehicle != f.vehicle || era != f.opening.Era || controller != f.opening.Controller {
		return nil, nil
	}
	return f.opening, nil
}

func (f *fleet) Party(_ context.Context, did string) (delegation.Party, error) {
	if did == avis {
		return delegation.Party{Kind: delegation.KindOrg, Operator: true}, nil
	}
	return delegation.Party{Kind: delegation.KindPerson, ConsumerProtected: true}, nil
}

// Exclusives mirrors what an org host's coverage index does: the live records
// over this vehicle that claim an exclusive hold.
func (f *fleet) Exclusives(_ context.Context, vehicle string, at time.Time) ([]delegation.ExclusiveHold, error) {
	var holds []delegation.ExclusiveHold
	for _, s := range f.records {
		rec := &s.Record
		if len(rec.Exclusive) == 0 || rec.Covers.Vehicle != vehicle || !rec.Validity.Set().Contains(at) {
			continue
		}
		holds = append(holds, delegation.ExclusiveHold{URI: s.URI, Holder: rec.To, Abilities: rec.Exclusive})
	}
	return holds, nil
}

// The compiled records are not just well formed: they evaluate the way §12
// describes. Custody suspends the operator's own commands for the booking
// window and not a minute longer, and the history grant outlives custody with
// the data window the renter actually drove.
func TestCompiledGrantsEvaluate(t *testing.T) {
	const valet = "did:dimo:valet"
	ctx := context.Background()

	f := newFleet(t, car, avis)
	f.role(avis, backend, RentalCatalog().Abilities(), day(1))
	ev := &delegation.Evaluator{Resolver: f, Policy: CommitPolicy()}

	// An org host commits what the booking compiles to, and recommits as the
	// booking moves. The keys are stable, so the second pass upserts the history
	// grant with the narrowed window rather than adding a second one; custody is
	// simply no longer produced, and the host tombstones it.
	driving := booking()
	for _, g := range mustCompile(t, &driving, day(11)) {
		f.commit(g.Key, g.Record, day(9))
	}

	a := booking()
	a.Custody = []Custody{{Start: day(10), End: tp(day(12))}}
	// The same pickup and return, as the fleet's own custody records: the history
	// grant narrows to these, so the window is the drive rather than the booking.
	f.hold(renter, day(10), tp(day(12)))
	a.State = StateReturned
	returnedGrants := mustCompile(t, &a, day(13))
	require.Len(t, returnedGrants, 1)
	for _, g := range returnedGrants {
		f.commit(g.Key, g.Record, day(9))
	}

	// Avis grants its valet crew the same commands, with no exclusive claim. The
	// crew also reads telemetry, which is what keeps the coverage non-empty while
	// the commands are suspended: delegation.Evaluator collapses a record whose
	// every ability is suspended into ErrNotCovered, so a commands-only record
	// cannot report that it was suspended rather than never granted.
	valetURI := f.commit("valet", delegation.Record{
		Type: delegation.TypeDelegation, From: avis, To: valet,
		Covers:    delegation.Covers{Vehicle: car},
		Abilities: []string{"command:unlock", "command:lock", "telemetry:read"},
		Validity:  span(1, 400),
	}, day(1))

	custodyURI := "at://" + avis + "/" + delegation.TypeDelegation + "/bk-1/rental/custody"
	historyURI := "at://" + avis + "/" + delegation.TypeDelegation + "/bk-1/rental/history"

	t.Run("renter can unlock during the booking", func(t *testing.T) {
		cov, err := ev.Authorize(ctx, custodyURI, renter, "", car, []string{"command:unlock"}, day(11))
		require.NoError(t, err)
		assert.Equal(t, []string{"command:unlock"}, cov.Live)
		assert.Empty(t, cov.Suspended)
	})

	t.Run("the operator's commands are suspended while somebody is driving", func(t *testing.T) {
		_, err := ev.Authorize(ctx, valetURI, valet, "", car, []string{"command:unlock"}, day(11))
		assert.ErrorIs(t, err, delegation.ErrExclusiveHold,
			"the operator is told somebody is driving, not that they were never granted this")

		cov, err := ev.Coverage(ctx, valetURI, car, day(11))
		require.NoError(t, err)
		assert.Empty(t, cov.Live)
		assert.ElementsMatch(t, []string{"command:unlock", "command:lock"}, cov.Suspended)
		assert.Contains(t, cov.Historical, "telemetry:read", "seeing the car is not commanding it")
	})

	t.Run("the operator gets its car back when the booking window ends", func(t *testing.T) {
		cov, err := ev.Authorize(ctx, valetURI, valet, "", car, []string{"command:unlock"}, day(16))
		require.NoError(t, err)
		assert.Equal(t, []string{"command:unlock"}, cov.Live)
	})

	t.Run("custody does not outlive the booking window", func(t *testing.T) {
		_, err := ev.Authorize(ctx, custodyURI, renter, "", car, []string{"command:unlock"}, day(16))
		assert.ErrorIs(t, err, delegation.ErrNotValid)
	})

	t.Run("history outlives custody and covers only the drive", func(t *testing.T) {
		cov, err := ev.Authorize(ctx, historyURI, renter, "", car, []string{"telemetry:read"}, day(20))
		require.NoError(t, err)
		window := cov.Historical["telemetry:read"]
		assert.True(t, window.Contains(day(11)), "the day they drove")
		assert.False(t, window.Contains(day(14)), "after they handed the car back")
		assert.False(t, window.Contains(day(9)), "before they picked it up")
	})

	t.Run("history stops when retention runs out", func(t *testing.T) {
		_, err := ev.Authorize(ctx, historyURI, renter, "", car, []string{"telemetry:read"}, day(60))
		assert.ErrorIs(t, err, delegation.ErrNotValid)
	})

	t.Run("nobody else may use the renter's grant", func(t *testing.T) {
		_, err := ev.Authorize(ctx, historyURI, valet, "", car, []string{"telemetry:read"}, day(20))
		assert.ErrorIs(t, err, delegation.ErrUnauthorized)
	})
}

// The insurer behind a damage waiver never had the car, so a grant narrowed by
// the insurer's own custody reads nothing at all. What the waiver buys is a look
// at the customer's drive, and the compiled record has to actually evaluate to
// it: a grant that compiles and then answers ErrNotCovered forever is not a
// product.
func TestInsurerGrantEvaluates(t *testing.T) {
	ctx := context.Background()

	f := newFleet(t, car, avis)
	f.role(avis, backend, RentalCatalog().Abilities(), day(1))
	ev := &delegation.Evaluator{Resolver: f, Policy: CommitPolicy()}

	a := booking()
	a.Services = append(a.Services, Service{
		Code: "waiver", Beneficiary: insurer, Term: span(1, 400),
	})
	a.Custody = []Custody{{Start: day(10), End: tp(day(12))}}
	a.State = StateReturned
	f.hold(renter, day(10), tp(day(12)))
	for _, g := range mustCompile(t, &a, day(13)) {
		f.commit(g.Key, g.Record, day(9))
	}

	uri := "at://" + avis + "/" + delegation.TypeDelegation + "/bk-1/waiver/insurer"
	cov, err := ev.Authorize(ctx, uri, insurer, "", car, []string{"events:read"}, day(20))
	require.NoError(t, err, "the insurer bought a look at the customer's drive")

	window := cov.Historical["events:read"]
	assert.True(t, window.Contains(day(11)), "the day the customer drove")
	assert.False(t, window.Contains(day(14)), "after the car came back")
	assert.False(t, window.Contains(day(9)), "before the customer picked it up")
}

func mustCompile(t *testing.T, a *Agreement, now time.Time) []Grant {
	t.Helper()
	grants, err := Compile(a, RentalCatalog(), now)
	require.NoError(t, err)
	return grants
}
