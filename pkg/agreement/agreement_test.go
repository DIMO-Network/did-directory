package agreement

import (
	"testing"
	"time"

	"github.com/DIMO-Network/did-directory/pkg/delegation"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const (
	avis     = "did:dimo:avis"
	backend  = "did:dimo:avis-backend"
	renter   = "did:dimo:renter"
	insurer  = "did:dimo:insurer"
	roadside = "did:dimo:roadside"
	car      = "did:dimo:car1"
)

func day(d int) time.Time       { return time.Date(2026, 1, d, 0, 0, 0, 0, time.UTC) }
func tp(t time.Time) *time.Time { return &t }
func span(a, b int) delegation.Window {
	return delegation.Window{From: tp(day(a)), To: tp(day(b))}
}

// booking is a paid rental of car from day 10 to day 15, retained for 30 days
// after the car comes back.
func booking() Agreement {
	return Agreement{
		Type:     TypeAgreement,
		ID:       "bk-1",
		Assigner: avis,
		Assignee: renter,
		Target:   Target{Class: "suv-intermediate", Vehicle: car, AssignedAt: tp(day(10))},
		Services: []Service{{Code: "rental"}},
		Duties: []Duty{
			{Action: DutyPay, FulfilledAt: tp(day(2))},
			{Action: DutyReturn, DueBy: tp(day(15))},
			{Action: DutyRetention, Term: 30 * 24 * time.Hour},
		},
		Window:     span(10, 15),
		State:      StatePaid,
		Timestamps: Timestamps{BookedAt: day(1)},
		Terms:      "sha256:9f2c",
		CreatedBy:  backend,
	}
}

func TestValidate(t *testing.T) {
	base := booking()
	assert.NoError(t, base.Validate())

	cases := map[string]func(a *Agreement){
		"unknown type":         func(a *Agreement) { a.Type = "x" },
		"no id":                func(a *Agreement) { a.ID = "" },
		"assigner not a did":   func(a *Agreement) { a.Assigner = "avis" },
		"self agreement":       func(a *Agreement) { a.Assignee = a.Assigner },
		"vehicle not a did":    func(a *Agreement) { a.Target.Vehicle = "car1" },
		"no services":          func(a *Agreement) { a.Services = nil },
		"service without code": func(a *Agreement) { a.Services = []Service{{}} },
		"bad beneficiary":      func(a *Agreement) { a.Services[0].Beneficiary = "insurer" },
		"inverted term":        func(a *Agreement) { a.Services[0].Term = delegation.Window{From: tp(day(5)), To: tp(day(1))} },
		"unknown duty":         func(a *Agreement) { a.Duties[0].Action = "obey" },
		"repeated duty":        func(a *Agreement) { a.Duties = append(a.Duties, Duty{Action: DutyPay}) },
		"negative term":        func(a *Agreement) { a.Duties[2].Term = -time.Hour },
		"no window start":      func(a *Agreement) { a.Window.From = nil },
		"inverted window":      func(a *Agreement) { a.Window = delegation.Window{From: tp(day(15)), To: tp(day(10))} },
		"inverted custody":     func(a *Agreement) { a.Custody = []Custody{{Start: day(12), End: tp(day(11))}} },
		"incident without id":  func(a *Agreement) { a.Incidents = []Incident{{Responder: roadside, OpenedAt: day(11)}} },
		"incident responder":   func(a *Agreement) { a.Incidents = []Incident{{ID: "i1", Responder: "aaa", OpenedAt: day(11)}} },
		"inverted incident": func(a *Agreement) {
			a.Incidents = []Incident{{ID: "i1", Responder: roadside, OpenedAt: day(12), ClosedAt: tp(day(11))}}
		},
		"unknown state":              func(a *Agreement) { a.State = "driving" },
		"cancelled without at":       func(a *Agreement) { a.State = StateCancelled },
		"cancelled at not cancelled": func(a *Agreement) { a.Timestamps.CancelledAt = tp(day(3)) },
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			a := booking()
			mutate(&a)
			assert.Error(t, a.Validate())
		})
	}
}

// A booking with no payment duty is paid: a courtesy car has nothing to
// compensate, and the engine must not invent an obligation the contract omits.
func TestPaid(t *testing.T) {
	a := booking()
	assert.True(t, a.Paid())

	a.Duties[0].FulfilledAt = nil
	assert.False(t, a.Paid())

	a.Duties = a.Duties[1:]
	assert.True(t, a.Paid())
}

// The return-by duty caps the booking window: the contract's deadline wins over
// a window someone typed, and a window with neither is refused.
func TestBookingWindow(t *testing.T) {
	a := booking()
	a.Duties[1].DueBy = tp(day(13))
	w, err := a.BookingWindow()
	require.NoError(t, err)
	assert.Equal(t, day(13), *w.To)

	a.Duties[1].DueBy = tp(day(20))
	w, err = a.BookingWindow()
	require.NoError(t, err)
	assert.Equal(t, day(15), *w.To)

	a.Window.To = nil
	a.Duties[1].DueBy = tp(day(20))
	w, err = a.BookingWindow()
	require.NoError(t, err)
	assert.Equal(t, day(20), *w.To)

	a.Duties = a.Duties[:1]
	_, err = a.BookingWindow()
	assert.ErrorIs(t, err, ErrUnboundedBooking)
}

func TestReturnedAt(t *testing.T) {
	a := booking()
	assert.Nil(t, a.ReturnedAt())

	// An open custody interval means the customer still has the car, whatever the
	// lifecycle state claims.
	a.Custody = []Custody{{Start: day(10), End: tp(day(11))}, {Start: day(12)}}
	a.State = StateReturned
	assert.Nil(t, a.ReturnedAt())

	a.Custody[1].End = tp(day(13))
	assert.Equal(t, day(13), *a.ReturnedAt())

	// No synced custody event: fall back to the operator's own due-back claim,
	// never later, so a device that never syncs cannot extend the window.
	a.Custody = nil
	assert.Equal(t, day(15), *a.ReturnedAt())

	a.State = StatePickedUp
	assert.Nil(t, a.ReturnedAt())

	a.State = StateClosed
	a.Window.To, a.Duties = nil, a.Duties[:1]
	assert.Nil(t, a.ReturnedAt())
}

// Retention bounds the history grant. Without a retention duty it is open-ended,
// which is the operator's contract speaking, not this package.
func TestRetentionWindow(t *testing.T) {
	a := booking()
	w, err := a.RetentionWindow()
	require.NoError(t, err)
	assert.Equal(t, day(10), *w.From)
	assert.Equal(t, day(15).Add(30*24*time.Hour), *w.To)

	a.Duties[2] = Duty{Action: DutyRetention, DueBy: tp(day(200))}
	w, err = a.RetentionWindow()
	require.NoError(t, err)
	assert.Equal(t, day(200), *w.To)

	a.Duties = a.Duties[:2]
	w, err = a.RetentionWindow()
	require.NoError(t, err)
	assert.Nil(t, w.To)

	a.Window.To, a.Duties = nil, a.Duties[:1]
	_, err = a.RetentionWindow()
	assert.ErrorIs(t, err, ErrUnboundedBooking)
}

func TestCatalogValidate(t *testing.T) {
	assert.NoError(t, RentalCatalog().Validate())

	cases := map[string][]Offer{
		"no offers":          {},
		"no name":            {{To: ToCustomer, Abilities: []string{"telemetry:read"}, Validity: ScopeBooking, DataWindow: ScopeCustody}},
		"unknown recipient":  {{Name: "x", To: "landlord", Abilities: []string{"telemetry:read"}, Validity: ScopeBooking, DataWindow: ScopeCustody}},
		"no abilities":       {{Name: "x", To: ToCustomer, Validity: ScopeBooking, DataWindow: ScopeCustody}},
		"repeated abilities": {{Name: "x", To: ToCustomer, Abilities: []string{"a:b", "a:b"}, Validity: ScopeBooking, DataWindow: ScopeCustody}},
		"exclusive not granted": {{Name: "x", To: ToCustomer, Abilities: []string{"telemetry:read"},
			Exclusive: []string{"command:lock"}, Validity: ScopeBooking, DataWindow: ScopeCustody}},
		"exclusive not live": {{Name: "x", To: ToCustomer, Abilities: []string{"telemetry:read"},
			Exclusive: []string{"telemetry:read"}, Validity: ScopeBooking, DataWindow: ScopeCustody}},
		"unknown scope":         {{Name: "x", To: ToCustomer, Abilities: []string{"telemetry:read"}, Validity: "forever", DataWindow: ScopeCustody}},
		"responder no incident": {{Name: "x", To: ToResponder, Abilities: []string{"location:precise"}, Validity: ScopeBooking, DataWindow: ScopeCustody}},
		"incident scope without flag": {{Name: "x", To: ToCustomer, Abilities: []string{"location:precise"},
			Validity: ScopeIncident, DataWindow: ScopeCustody}},
		"duplicate offer": {
			{Name: "x", To: ToCustomer, Abilities: []string{"telemetry:read"}, Validity: ScopeBooking, DataWindow: ScopeCustody},
			{Name: "x", To: ToCustomer, Abilities: []string{"events:read"}, Validity: ScopeBooking, DataWindow: ScopeCustody},
		},
	}
	for name, offers := range cases {
		t.Run(name, func(t *testing.T) {
			assert.Error(t, Catalog{"svc": offers}.Validate())
		})
	}
}
