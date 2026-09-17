// Package agreement models a purchased service as an ODRL agreement and
// compiles it into delegation records.
//
// A renter is not an org member and not a partner. They bought a service, and
// the purchase is what creates the access, so the record worth storing is the
// agreement and the grants are derived from its state. An operator writing
// thousands of bookings a day cannot hand-sign a delegation per booking; a
// booking service holding a constrained role compiles them instead.
//
// The vocabulary is ODRL with a DIMO profile, as the 3.0 fixed choices require:
// an agreement has an assigner, an assignee, a target, permissions (here, the
// services actually purchased) and duties. Duties are what earn ODRL its place:
// they gate the permissions, so an unpaid booking compiles to nothing at all.
//
// The package is a library. It reads no clock, no storage and no network:
// Compile takes the evaluation time as a parameter so the same agreement always
// compiles to the same records at the same instant.
//
// Design: docs/superpowers/specs/2026-09-16-dimo-orgs-fleets-delegation-design.md §12
package agreement

import (
	"errors"
	"fmt"
	"slices"
	"strings"
	"time"

	"github.com/DIMO-Network/did-directory/pkg/delegation"
)

// TypeAgreement is the record type of a stored agreement.
const TypeAgreement = "network.dimo.agreement"

// Compilation errors.
var (
	// ErrUnknownService means the agreement names a line item the catalog does
	// not declare. Silently dropping a purchased service is worse than failing:
	// the customer paid for it.
	ErrUnknownService = errors.New("catalog declares no offer for this service")
	// ErrNoBeneficiary means an offer directs its grant to a third party and the
	// line item names none.
	ErrNoBeneficiary = errors.New("offer needs a beneficiary and the line item names none")
	// ErrNoTerm means an offer's validity is the line item's own term and the
	// line item carries no term.
	ErrNoTerm = errors.New("offer needs the line item's term and the line item carries none")
	// ErrUnboundedBooking means the booking has no end. A live grant with no end
	// is a car that never locks again, so the compiler refuses rather than
	// issuing one.
	ErrUnboundedBooking = errors.New("booking window has no end: set window.to or a return-by duty")
	// ErrDuplicateGrant means two line items compiled to the same grant name over
	// the same agreement, which would make the record key ambiguous.
	ErrDuplicateGrant = errors.New("two line items compile to the same grant")
	// ErrUnknownScope means an offer names a time range the compiler cannot derive.
	ErrUnknownScope = errors.New("unknown scope")
)

// State is where an agreement sits in its lifecycle:
//
//	booked → paid → picked up → returned → closed
//
// with cancelled reachable until pickup. Only cancellation is read from the
// state: payment is read from the duty and custody from the signed custody
// events, so the state can never quietly disagree with the facts that gate a
// grant.
type State string

// Lifecycle states.
const (
	StateBooked    State = "booked"
	StatePaid      State = "paid"
	StatePickedUp  State = "pickedUp"
	StateReturned  State = "returned"
	StateClosed    State = "closed"
	StateCancelled State = "cancelled"
)

// Duty actions. ODRL names the first one; the other two are the DIMO profile.
const (
	// DutyPay is odrl:compensate. Until it is fulfilled nothing is mintable.
	DutyPay = "compensate"
	// DutyReturn obliges the customer to return the vehicle by DueBy. It caps the
	// booking window, and therefore custody.
	DutyReturn = "returnVehicle"
	// DutyRetention bounds how long the provider keeps the customer's history
	// grant alive after custody ends. Without it history is open-ended.
	DutyRetention = "retainData"
)

// Duty is an obligation attached to the agreement. Which duties exist is the
// operator's contract; what an unfulfilled one does is this package's rule.
type Duty struct {
	Action string `json:"action"`
	// DueBy is the deadline, if the duty has one.
	DueBy *time.Time `json:"dueBy,omitempty"`
	// Term is a duration the duty implies, measured from the end of custody. A
	// retention duty uses it.
	Term time.Duration `json:"term,omitempty"`
	// FulfilledAt records when the duty was discharged. A duty with a deadline
	// and no fulfilment is outstanding regardless of the clock; this package
	// never decides that a payment happened because time passed.
	FulfilledAt *time.Time `json:"fulfilledAt,omitempty"`
}

func (d *Duty) fulfilled() bool { return d.FulfilledAt != nil }

// Target is what the agreement is about.
//
// A renter books a class and gets a specific car, so Vehicle is empty until the
// operator assigns one, often minutes before pickup. Nothing compiles until it
// is set, because a grant has to name the car it opens.
type Target struct {
	// Class is the booked vehicle class, e.g. "suv-intermediate". Informational.
	Class string `json:"class,omitempty"`
	// Vehicle is the assigned vehicle DID.
	Vehicle string `json:"vehicle,omitempty"`
	// AssignedAt records when the vehicle was assigned.
	AssignedAt *time.Time `json:"assignedAt,omitempty"`
}

// Service is a purchased line item: what the customer actually bought. ODRL
// calls it a permission; the rental desk calls it a product code.
type Service struct {
	// Code keys into the Catalog.
	Code string `json:"code"`
	// Beneficiary receives grants an offer directs to a third party, such as the
	// insurer behind a damage waiver.
	Beneficiary string `json:"beneficiary,omitempty"`
	// Term is the line item's own term, such as a policy period. Offers whose
	// validity is ScopeTerm require it.
	Term delegation.Window `json:"term,omitempty"`
}

// Custody is an interval during which the customer physically held the vehicle.
//
// The car's device signs custody events offline and syncs later, so these arrive
// after the fact and must never gate access: the renter picks the car up by
// unlocking it, and waiting for a custody record written at pickup means nobody
// can open the door in a garage with no signal (§12.3). Custody narrows the data
// window afterwards; it does not open it.
type Custody struct {
	Start time.Time  `json:"start"`
	End   *time.Time `json:"end,omitempty"`
}

// Incident is an open matter on the rental: a breakdown, a collision. Roadside
// access exists only while one is open, which is one reason Compile takes the
// time as a parameter rather than reading a clock.
type Incident struct {
	ID string `json:"id"`
	// Responder is the party handling it, e.g. the roadside provider.
	Responder string     `json:"responder"`
	OpenedAt  time.Time  `json:"openedAt"`
	ClosedAt  *time.Time `json:"closedAt,omitempty"`
}

func (i *Incident) openAt(t time.Time) bool {
	return !t.Before(i.OpenedAt) && (i.ClosedAt == nil || t.Before(*i.ClosedAt))
}

// Timestamps records the lifecycle moments that no other field already carries.
// Payment lives on its duty and pickup and return live on the custody events, so
// there is exactly one place to look for each fact.
type Timestamps struct {
	BookedAt    time.Time  `json:"bookedAt"`
	CancelledAt *time.Time `json:"cancelledAt,omitempty"`
	ClosedAt    *time.Time `json:"closedAt,omitempty"`
}

// Agreement is a purchase that creates access: a rental booking, a subscription,
// a peer-to-peer listing taken up.
type Agreement struct {
	Type string `json:"$type"`
	// ID is the operator's booking reference. It keys the compiled records, so it
	// must be stable and unique within the issuing repository.
	ID string `json:"id"`
	// Assigner is the provider: the operator that sold the service and that
	// issues the grants. ODRL's assigner.
	Assigner string `json:"assigner"`
	// Assignee is the customer. ODRL's assignee.
	Assignee string `json:"assignee"`
	// Target is the vehicle, assigned at pickup rather than at booking.
	Target Target `json:"target"`
	// Basis is the delegation chain the compiled grants narrow. Empty when the
	// provider is the controller of record, which is the fleet case: Avis owns
	// the cars. A peer-to-peer platform names the host's listing delegation here,
	// and §12.4 is then the same chain with no new concepts.
	Basis []string `json:"basis,omitempty"`
	// Services are the purchased line items.
	Services []Service `json:"services"`
	// Duties gate the permissions.
	Duties []Duty `json:"duties,omitempty"`
	// Window is the booking window: when the customer is entitled to the car.
	Window delegation.Window `json:"window"`
	// Custody is what the vehicle reported about who actually held it.
	Custody []Custody `json:"custody,omitempty"`
	// Incidents are matters opened during the rental.
	Incidents []Incident `json:"incidents,omitempty"`
	// Terms is a hash of the governing rental contract, carried onto every
	// compiled grant so a dispute can name the document.
	Terms string `json:"terms,omitempty"`
	// State and Timestamps are the lifecycle.
	State      State      `json:"state"`
	Timestamps Timestamps `json:"timestamps"`
	// CreatedBy is the booking service that wrote the agreement. Audit only, as
	// in delegation records: validity rests on the repository commit.
	CreatedBy string `json:"createdBy,omitempty"`
}

// Validate checks an agreement's structure. It resolves nothing and consults no
// catalog.
func (a *Agreement) Validate() error {
	if a.Type != TypeAgreement {
		return fmt.Errorf("unknown record type %q", a.Type)
	}
	if a.ID == "" {
		return errors.New("id must not be empty")
	}
	if !isDID(a.Assigner) || !isDID(a.Assignee) {
		return errors.New("assigner and assignee must be DIDs")
	}
	if a.Assigner == a.Assignee {
		return errors.New("assigner and assignee must differ")
	}
	if a.Target.Vehicle != "" && !isDID(a.Target.Vehicle) {
		return errors.New("target.vehicle must be a DID")
	}
	if len(a.Services) == 0 {
		return errors.New("an agreement must purchase at least one service")
	}
	for _, s := range a.Services {
		if s.Code == "" {
			return errors.New("every service must have a code")
		}
		if s.Beneficiary != "" && !isDID(s.Beneficiary) {
			return errors.New("service.beneficiary must be a DID")
		}
		if !ordered(s.Term) {
			return fmt.Errorf("service %s: term.from must be before term.to", s.Code)
		}
	}

	seen := map[string]bool{}
	for _, d := range a.Duties {
		switch d.Action {
		case DutyPay, DutyReturn, DutyRetention:
		default:
			return fmt.Errorf("unknown duty action %q", d.Action)
		}
		if seen[d.Action] {
			return fmt.Errorf("duty %s is declared twice", d.Action)
		}
		seen[d.Action] = true
		if d.Term < 0 {
			return fmt.Errorf("duty %s: term must not be negative", d.Action)
		}
	}

	if a.Window.From == nil {
		return errors.New("window.from is required")
	}
	if !ordered(a.Window) {
		return errors.New("window.from must be before window.to")
	}
	for _, c := range a.Custody {
		if c.End != nil && !c.Start.Before(*c.End) {
			return errors.New("custody.start must be before custody.end")
		}
	}
	for _, i := range a.Incidents {
		if i.ID == "" {
			return errors.New("every incident must have an id")
		}
		if !isDID(i.Responder) {
			return errors.New("incident.responder must be a DID")
		}
		if i.ClosedAt != nil && !i.OpenedAt.Before(*i.ClosedAt) {
			return errors.New("incident.openedAt must be before incident.closedAt")
		}
	}

	switch a.State {
	case StateBooked, StatePaid, StatePickedUp, StateReturned, StateClosed, StateCancelled:
	default:
		return fmt.Errorf("unknown state %q", a.State)
	}
	if a.State == StateCancelled && a.Timestamps.CancelledAt == nil {
		return errors.New("a cancelled agreement must record when")
	}
	if a.State != StateCancelled && a.Timestamps.CancelledAt != nil {
		return errors.New("only a cancelled agreement may record a cancellation time")
	}
	return nil
}

// duty returns the declared duty with this action, or nil.
func (a *Agreement) duty(action string) *Duty {
	for i := range a.Duties {
		if a.Duties[i].Action == action {
			return &a.Duties[i]
		}
	}
	return nil
}

// Paid reports whether the payment duty is discharged.
//
// An agreement that declares no payment duty is paid: a loyalty redemption or a
// courtesy car has nothing to compensate. A declared duty that has not been
// fulfilled blocks everything, and no amount of elapsed time fulfils it.
func (a *Agreement) Paid() bool {
	d := a.duty(DutyPay)
	return d == nil || d.fulfilled()
}

// Cancelled reports whether the agreement was cancelled.
//
// Cancellation is a return, not an erasure. Before pickup it compiles to
// nothing, because there is no custody to cover and no data to keep. Cancelled
// mid-rental it ends custody at the cancellation — the commands stop — and the
// customer keeps the history of the days they actually drove. That record is
// about them, and it is the evidence both sides reach for in the damage or
// billing dispute that usually follows a mid-rental cancellation.
func (a *Agreement) Cancelled() bool { return a.State == StateCancelled }

// Drove reports whether the customer ever took the car, which is what separates
// a cancellation from a cancellation with a drive behind it.
func (a *Agreement) Drove() bool { return len(a.Custody) > 0 }

// BookingWindow is when the customer is entitled to the car, which is what the
// live grants activate on. A return-by duty caps it: the contract's deadline
// wins over a window someone typed.
func (a *Agreement) BookingWindow() (delegation.Window, error) {
	w := copyWindow(a.Window)
	if d := a.duty(DutyReturn); d != nil && d.DueBy != nil {
		if w.To == nil || d.DueBy.Before(*w.To) {
			w.To = copyTime(d.DueBy)
		}
	}
	if w.To == nil {
		return w, ErrUnboundedBooking
	}
	return w, nil
}

// ReturnedAt reports when the rental ended, or nil while the customer still has
// the vehicle.
//
// Two facts decide it, and neither is enough alone. An open custody leg means
// the customer physically has the car, whatever the lifecycle claims: the
// vehicle signs those events. Closed legs say where the car has been, never that
// the rental is over — a valet drop-off or an overnight garage hand-back closes
// a leg in the middle of a booking and the renter takes the car again the next
// morning. So the rental ends when the lifecycle says it ended and no leg is
// still open, and it ends at the last synced return.
//
// A returned or closed booking with no synced event at all falls back to the end
// of the booking window, which is the operator's own claim about when the car was
// due back — never later, so a device that never syncs cannot extend a renter's
// window.
func (a *Agreement) ReturnedAt() *time.Time {
	// A cancellation mid-rental ends custody there and then, even if no return
	// event ever syncs: the car is no longer rented, whatever the device says.
	if a.Cancelled() && a.Timestamps.CancelledAt != nil {
		if end := a.custodyEnd(); end != nil {
			return copyTime(end)
		}
		return copyTime(a.Timestamps.CancelledAt)
	}
	if len(a.Custody) > 0 && a.custodyEnd() == nil {
		return nil
	}
	if a.State != StateReturned && a.State != StateClosed {
		return nil
	}
	if end := a.custodyEnd(); end != nil {
		return copyTime(end)
	}
	w, err := a.BookingWindow()
	if err != nil {
		return nil
	}
	return w.To
}

// custodyEnd is the last synced return, or nil while any period is still open.
func (a *Agreement) custodyEnd() *time.Time {
	if len(a.Custody) == 0 {
		return nil
	}
	var last *time.Time
	for i := range a.Custody {
		c := &a.Custody[i]
		if c.End == nil {
			return nil
		}
		if last == nil || c.End.After(*last) {
			last = c.End
		}
	}
	return last
}

// CustodyWindow is the range the customer actually held the vehicle.
//
// Before any custody event has synced it is the booking window, so a renter can
// read the drive they are on. Once the car is back it is the real interval, and
// the history grant keeps exactly the window they drove.
func (a *Agreement) CustodyWindow() (delegation.Window, error) {
	booking, err := a.BookingWindow()
	if err != nil {
		return delegation.Window{}, err
	}
	w := booking
	for i := range a.Custody {
		if s := a.Custody[i].Start; w.From == nil || s.Before(*w.From) {
			w.From = copyTime(&s)
		}
	}
	if end := a.ReturnedAt(); end != nil {
		w.To = copyTime(end)
	}
	return w, nil
}

// RetentionWindow is how long the customer's history grant stays exercisable: it
// opens with custody and closes when the retention duty says. With no retention
// duty declared it is open-ended, which is a choice the operator's contract
// makes, not one this package makes for them.
//
// A retention duty may state a term, a deadline, or both. Both are ceilings on
// how long the provider keeps the customer's data, so when both are stated the
// earlier one ends the grant: a term measured from the end of custody does not
// run past the contract's deadline, and a deadline does not extend a term that
// expires sooner. Neither branch shadows the other.
func (a *Agreement) RetentionWindow() (delegation.Window, error) {
	custody, err := a.CustodyWindow()
	if err != nil {
		return delegation.Window{}, err
	}
	w := delegation.Window{From: custody.From}
	d := a.duty(DutyRetention)
	if d == nil {
		return w, nil
	}
	if d.Term > 0 && custody.To != nil {
		end := custody.To.Add(d.Term)
		w.To = &end
	}
	if d.DueBy != nil && (w.To == nil || d.DueBy.Before(*w.To)) {
		w.To = copyTime(d.DueBy)
	}
	return w, nil
}

// copyTime and copyWindow keep the agreement's own fields out of the records
// this package hands back. A compiled record is validated once and then
// committed; a window pointing into a caller-mutable agreement would let a later
// edit to the booking rewrite a record an org host has already accepted.
func copyTime(t *time.Time) *time.Time {
	if t == nil {
		return nil
	}
	out := *t
	return &out
}

func copyWindow(w delegation.Window) delegation.Window {
	return delegation.Window{From: copyTime(w.From), To: copyTime(w.To)}
}

func ordered(w delegation.Window) bool {
	return w.From == nil || w.To == nil || w.From.Before(*w.To)
}

func isDID(s string) bool {
	return strings.HasPrefix(s, "did:") && len(s) > len("did:")
}

// nonEmpty reports whether a window covers any time at all.
func nonEmpty(w delegation.Window) bool { return !w.Set().IsEmpty() }

// ended reports whether the window has closed by time now, in which case there
// is nothing left to grant.
func ended(w delegation.Window, now time.Time) bool {
	return w.To != nil && !now.Before(*w.To)
}

func clone(s []string) []string {
	if len(s) == 0 {
		return nil
	}
	return slices.Clone(s)
}
