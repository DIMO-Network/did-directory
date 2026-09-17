package agreement

import (
	"fmt"
	"time"

	"github.com/DIMO-Network/did-directory/pkg/delegation"
)

// Grant is one compiled delegation plus the key it should be committed under.
type Grant struct {
	// Key is stable across compilations: the same agreement state always yields
	// the same keys, so a booking service upserts its records instead of
	// accumulating a new set every time a booking changes.
	Key string
	// Offer names the catalog offer that produced it.
	Offer string
	// Record is what to commit.
	Record delegation.Record
}

// CommitPolicy is the profile a booking service commits under.
//
// delegation.DefaultPolicy makes every live ability need a second approval, and
// no operator writing thousands of bookings a day can put two admins behind each
// unlock grant. The approval belongs one level up and happens once: what a pair
// of admins signs is the fleet delegation that permits exclusive redelegation.
// Everything compiled below it is machine-written, bounded by that basis, and
// re-checked at evaluation.
func CommitPolicy() delegation.Policy {
	p := delegation.DefaultPolicy()
	p.Name = "rental-booking"
	p.ApprovalForLiveAbilities = false
	return p
}

// Compile returns the delegation records an agreement should produce at time
// now, in a stable order: line items in the order they were purchased, offers in
// the order the catalog declares them, incidents in the order they were opened.
//
// It is pure. Nothing is read but the arguments, and now is a parameter because
// the answer genuinely changes over the life of a booking: a grant appears when
// its duties are satisfied, custody narrows the data window once the car is
// back, roadside exists only while an incident is open, and history stops being
// produced when retention runs out.
//
// The result is the complete set for that instant. A caller that committed an
// earlier set should treat records it no longer sees here as revoked, not as
// missing: that is how a returned booking loses custody and keeps history.
func Compile(a *Agreement, cat Catalog, now time.Time) ([]Grant, error) {
	if err := a.Validate(); err != nil {
		return nil, err
	}

	// Duty gating, before anything else is computed.
	//
	// Unpaid means nothing: the purchase is what creates the access, and an
	// unfulfilled payment duty means nothing was purchased yet. No assigned
	// vehicle means nothing: a renter books a class and a grant has to name the
	// car it opens, so the booking compiles to an empty set until the desk hands
	// over a key. Cancelled before pickup means nothing either — no custody, so
	// no history to keep.
	if !a.Paid() || a.Target.Vehicle == "" {
		return nil, nil
	}
	if a.Cancelled() && !a.Drove() {
		return nil, nil
	}

	// Cancellation mid-rental is a return: custody stops, history stays.
	returned := a.ReturnedAt() != nil || a.Cancelled()
	keys := map[string]bool{}
	var grants []Grant

	for i := range a.Services {
		svc := &a.Services[i]
		offers, ok := cat[svc.Code]
		if !ok {
			return nil, fmt.Errorf("%w: %s", ErrUnknownService, svc.Code)
		}
		for j := range offers {
			off := &offers[j]
			// Custody dies at return. History does not, which is why they are two
			// records and not one.
			if off.EndsAtReturn && returned {
				continue
			}
			if !off.PerOpenIncident {
				g, err := a.grant(off, svc, nil, now)
				if err != nil {
					return nil, err
				}
				if g != nil {
					grants = append(grants, *g)
				}
				continue
			}
			for k := range a.Incidents {
				inc := &a.Incidents[k]
				if !inc.openAt(now) {
					continue
				}
				g, err := a.grant(off, svc, inc, now)
				if err != nil {
					return nil, err
				}
				if g != nil {
					grants = append(grants, *g)
				}
			}
		}
	}

	for _, g := range grants {
		if keys[g.Key] {
			return nil, fmt.Errorf("%w: %s", ErrDuplicateGrant, g.Key)
		}
		keys[g.Key] = true
	}
	return grants, nil
}

// grant builds one record, or returns nil when the offer produces nothing for
// this agreement at this time.
func (a *Agreement) grant(off *Offer, svc *Service, inc *Incident, now time.Time) (*Grant, error) {
	if err := off.validate(); err != nil {
		return nil, err
	}

	to, err := a.recipient(off, svc, inc)
	if err != nil {
		return nil, err
	}
	// A grant from the provider to itself is not written. The operator already
	// holds the ability as controller of record, and delegation records reject
	// from == to. This is the in-house roadside desk and the self-insured fleet.
	if to == a.Assigner {
		return nil, nil
	}

	validity, err := a.scope(off.Validity, svc, inc)
	if err != nil {
		return nil, err
	}
	dataWindow, err := a.scope(off.DataWindow, svc, inc)
	if err != nil {
		return nil, err
	}
	// A window that has already closed grants nothing: this is how a retention
	// term expiring stops the history grant from being produced, and how a
	// booking whose window has passed stops producing custody even if nobody
	// wrote a return event.
	if !nonEmpty(validity) || ended(validity, now) {
		return nil, nil
	}
	if !nonEmpty(dataWindow) {
		return nil, nil
	}

	// The service code is part of the key. Offer names are unique per code and
	// that is all a catalog can enforce, so two products may legitimately both
	// call their grant "custody"; keying on the name alone would make a live
	// two-service booking compile to nothing at all.
	key := a.ID + "/" + svc.Code + "/" + off.Name
	if inc != nil {
		key += "/" + inc.ID
	}
	terms := off.Terms
	if terms == "" {
		terms = a.Terms
	}

	rec := delegation.Record{
		Type:       delegation.TypeDelegation,
		From:       a.Assigner,
		To:         to,
		Basis:      clone(a.Basis),
		Covers:     delegation.Covers{Vehicle: a.Target.Vehicle},
		Abilities:  clone(off.Abilities),
		DataWindow: dataWindow,
		// A custody-scoped data window is a hull: one Window cannot express a car
		// handed back and re-taken. NarrowToCustody makes the evaluator intersect
		// the real intervals, so the hull is only ever an outer bound.
		//
		// The evaluator narrows by the custody of the recipient, so this can only
		// be claimed for a grant that goes to the customer. The insurer behind a
		// damage waiver never had the car: narrowing their grant to their own
		// custody would read nothing at all, and a grant that compiles and then
		// answers ErrNotCovered forever is not a product. What bounds the insurer
		// is the hull — the customer's drive — which is what the waiver bought.
		NarrowToCustody: off.DataWindow == ScopeCustody && to == a.Assignee,
		Validity:        validity,
		Redelegate:      off.Redelegate,
		RevocableBy:     off.RevocableBy,
		AfterRemoval:    off.AfterRemoval,
		AfterTransfer:   off.AfterTransfer,
		Purpose:         off.purpose(),
		Terms:           terms,
		Exclusive:       clone(off.Exclusive),
		CreatedBy:       a.CreatedBy,
		CreatedAt:       now,
	}
	if err := rec.Validate(); err != nil {
		return nil, fmt.Errorf("offer %s: %w", off.Name, err)
	}
	return &Grant{Key: key, Offer: off.Name, Record: rec}, nil
}

func (a *Agreement) recipient(off *Offer, svc *Service, inc *Incident) (string, error) {
	switch off.To {
	case ToCustomer:
		return a.Assignee, nil
	case ToBeneficiary:
		if svc.Beneficiary == "" {
			return "", fmt.Errorf("%w: service %s, offer %s", ErrNoBeneficiary, svc.Code, off.Name)
		}
		return svc.Beneficiary, nil
	case ToResponder:
		return inc.Responder, nil
	default:
		return "", fmt.Errorf("offer %s: unknown recipient %q", off.Name, off.To)
	}
}

// scope resolves an offer's scope against this agreement's facts. Every branch
// returns times of its own: nothing in a compiled record may point back into the
// agreement it was compiled from.
func (a *Agreement) scope(s Scope, svc *Service, inc *Incident) (delegation.Window, error) {
	switch s {
	case ScopeBooking:
		return a.BookingWindow()
	case ScopeCustody:
		return a.CustodyWindow()
	case ScopeRetention:
		return a.RetentionWindow()
	case ScopeTerm:
		if svc.Term.From == nil && svc.Term.To == nil {
			return delegation.Window{}, fmt.Errorf("%w: service %s", ErrNoTerm, svc.Code)
		}
		return copyWindow(svc.Term), nil
	case ScopeIncident:
		return copyWindow(delegation.Window{From: &inc.OpenedAt, To: inc.ClosedAt}), nil
	case ScopeUnbounded:
		return delegation.Window{}, nil
	default:
		return delegation.Window{}, fmt.Errorf("%w %q", ErrUnknownScope, s)
	}
}
