package agreement

import (
	"errors"
	"fmt"
	"maps"
	"slices"

	"github.com/DIMO-Network/did-directory/pkg/delegation"
)

// Recipient names who a compiled grant goes to.
type Recipient string

// Recipients.
const (
	// ToCustomer sends the grant to the agreement's assignee: the renter.
	ToCustomer Recipient = "customer"
	// ToBeneficiary sends it to the DID the line item names, such as the insurer
	// behind a damage waiver.
	ToBeneficiary Recipient = "beneficiary"
	// ToResponder sends it to the party handling the open incident.
	ToResponder Recipient = "responder"
)

// Scope names a time range the compiler derives from the agreement's own facts.
// An offer never states dates; it states which of the agreement's ranges it
// wants, and the compiler resolves them against the booking.
type Scope string

// Scopes.
const (
	// ScopeBooking is the booking window. Live grants activate on it, because the
	// renter opens the car by unlocking it and access cannot wait on a pickup
	// record (§12.3).
	ScopeBooking Scope = "booking"
	// ScopeCustody is the range the customer actually held the vehicle: the
	// booking window until custody events sync, the real interval afterwards.
	ScopeCustody Scope = "custody"
	// ScopeRetention runs from the start of custody to the end of the retention
	// duty's term.
	ScopeRetention Scope = "retention"
	// ScopeTerm is the line item's own term, such as an insurance policy period.
	ScopeTerm Scope = "term"
	// ScopeIncident is the interval of the incident that produced the grant.
	ScopeIncident Scope = "incident"
	// ScopeUnbounded places no limit. Only sensible for the data window of a
	// grant that reads no data.
	ScopeUnbounded Scope = "unbounded"
)

// Offer is what one purchased line item compiles to.
//
// Operators sell different products in different markets, and the same product
// code means different things at two rental desks, so the mapping from a code to
// abilities is declared by the caller. Nothing in this package switches on a
// product name.
type Offer struct {
	// Name labels the grant and forms part of its record key, so it must be
	// stable: the same agreement state has to compile to the same keys for a
	// booking service to upsert rather than accumulate records.
	Name string
	// To names the recipient.
	To Recipient
	// Abilities is what the grant confers.
	Abilities []string
	// Exclusive lists abilities held exclusively while the grant is live. Custody
	// claims the commands here: an operator must not immobilise a car somebody
	// else is driving, and that is a safety property, not a permissions question
	// (§12.2). The basis has to permit the claim, which a host does once at
	// listing time by setting delegation.Redelegate.Exclusive.
	Exclusive []string
	// Validity is when the grant can be exercised.
	Validity Scope
	// DataWindow is the range of data timestamps it may read.
	DataWindow Scope
	// EndsAtReturn drops the grant once the customer has returned the vehicle.
	// Custody sets it and history does not, which is the entire reason the two
	// are separate records: custody dies at return while the renter keeps the
	// window they actually drove, separately revocable.
	EndsAtReturn bool
	// PerOpenIncident produces one grant for each incident open at the
	// compilation time, and none when there is no incident.
	PerOpenIncident bool
	// Redelegate, RevocableBy, AfterRemoval and AfterTransfer map straight onto
	// the delegation record. Their zero values are the delegation package's
	// defaults: no redelegation, revocable by the issuer, history retained.
	Redelegate    delegation.Redelegate
	RevocableBy   string
	AfterRemoval  string
	AfterTransfer string
	// Purpose is shown to the vehicle's controller. It defaults to Name.
	Purpose string
	// Terms overrides the agreement's contract hash for this grant.
	Terms string
}

// Catalog declares what each purchased service code compiles to.
//
// One line item can imply several grants: a rental is custody plus history, two
// records on purpose. The caller supplies the catalog because line items vary
// per operator and per market, and a hardcoded switch would make every new
// product a code change.
type Catalog map[string][]Offer

// Validate checks that every offer is structurally sound, so a catalog can be
// checked once at startup rather than failing on a booking.
func (c Catalog) Validate() error {
	for code, offers := range c {
		if len(offers) == 0 {
			return fmt.Errorf("service %s: declares no offers", code)
		}
		names := map[string]bool{}
		for i := range offers {
			o := &offers[i]
			if err := o.validate(); err != nil {
				return fmt.Errorf("service %s: %w", code, err)
			}
			if names[o.Name] {
				return fmt.Errorf("service %s: offer %s is declared twice", code, o.Name)
			}
			names[o.Name] = true
		}
	}
	return nil
}

func (o *Offer) validate() error {
	if o.Name == "" {
		return errors.New("offer must have a name")
	}
	switch o.To {
	case ToCustomer, ToBeneficiary, ToResponder:
	default:
		return fmt.Errorf("offer %s: unknown recipient %q", o.Name, o.To)
	}
	if len(o.Abilities) == 0 {
		return fmt.Errorf("offer %s: abilities must not be empty", o.Name)
	}
	if len(slices.Compact(slices.Sorted(slices.Values(o.Abilities)))) != len(o.Abilities) {
		return fmt.Errorf("offer %s: abilities must not repeat", o.Name)
	}
	for _, a := range o.Exclusive {
		if !slices.Contains(o.Abilities, a) {
			return fmt.Errorf("offer %s: exclusive ability %s is not granted by this offer", o.Name, a)
		}
		if delegation.ClassOf(a) != delegation.Live {
			return fmt.Errorf("offer %s: only live abilities can be exclusive, got %s", o.Name, a)
		}
	}
	for _, s := range []Scope{o.Validity, o.DataWindow} {
		switch s {
		case ScopeBooking, ScopeCustody, ScopeRetention, ScopeTerm, ScopeIncident, ScopeUnbounded:
		default:
			return fmt.Errorf("offer %s: %w %q", o.Name, ErrUnknownScope, s)
		}
	}
	if o.To == ToResponder && !o.PerOpenIncident {
		// There is no such thing as a responder with no incident: the incident is
		// what names the responder.
		return fmt.Errorf("offer %s: a responder grant must be per open incident", o.Name)
	}
	if !o.PerOpenIncident && (o.Validity == ScopeIncident || o.DataWindow == ScopeIncident) {
		return fmt.Errorf("offer %s: an incident scope requires perOpenIncident", o.Name)
	}
	return nil
}

// Abilities returns every ability the catalog can grant, plus delegation:create,
// sorted.
//
// A booking service authors grants on the operator's behalf, and the evaluator
// requires such an author to hold a role covering delegation:create and every
// ability in the record it wrote. Provisioning that role from the catalog keeps
// the two from drifting: add a product and the role widens with it, instead of
// the service silently writing grants that fail to evaluate.
func (c Catalog) Abilities() []string {
	seen := map[string]bool{"delegation:create": true}
	for _, offers := range c {
		for i := range offers {
			for _, a := range offers[i].Abilities {
				seen[a] = true
			}
		}
	}
	return slices.Sorted(maps.Keys(seen))
}

func (o *Offer) purpose() string {
	if o.Purpose != "" {
		return o.Purpose
	}
	return o.Name
}

// RentalCatalog is the worked example from the design's §12.1 table: what a car
// rental booking compiles to.
//
// It is a starting point, not a standard. Operators are expected to copy it and
// edit the codes, the abilities and the redelegation rules to match what they
// actually sell.
func RentalCatalog() Catalog {
	commands := []string{"command:unlock", "command:lock", "command:charge"}
	return Catalog{
		// The rental itself: two grants, one that dies at return and one that does not.
		"rental": {
			{
				Name:      "custody",
				To:        ToCustomer,
				Abilities: clone(commands),
				Exclusive: clone(commands),
				Validity:  ScopeBooking,
				// Commands read no history, so the data window is a formality; it is
				// custody for consistency with the table and so a widened offer stays
				// bounded by the drive.
				DataWindow:    ScopeCustody,
				EndsAtReturn:  true,
				AfterTransfer: delegation.Drop,
				AfterRemoval:  delegation.Drop,
				Purpose:       "rental-custody",
			},
			{
				Name:          "history",
				To:            ToCustomer,
				Abilities:     []string{"telemetry:read"},
				Validity:      ScopeRetention,
				DataWindow:    ScopeCustody,
				AfterTransfer: delegation.RetainHistory,
				AfterRemoval:  delegation.RetainHistory,
				Purpose:       "rental-history",
			},
		},
		// A damage waiver buys the insurer a look at what happened while the
		// customer had the car, for as long as the policy runs.
		"waiver": {
			{
				Name:          "insurer",
				To:            ToBeneficiary,
				Abilities:     []string{"events:read"},
				Validity:      ScopeTerm,
				DataWindow:    ScopeCustody,
				AfterTransfer: delegation.RetainHistory,
				AfterRemoval:  delegation.RetainHistory,
				Purpose:       "rental-claims",
			},
		},
		// Roadside exists only while something is wrong. No incident, no location.
		"roadside": {
			{
				Name:            "roadside",
				To:              ToResponder,
				Abilities:       []string{"location:precise"},
				Validity:        ScopeIncident,
				DataWindow:      ScopeIncident,
				PerOpenIncident: true,
				AfterTransfer:   delegation.Drop,
				AfterRemoval:    delegation.Drop,
				Purpose:         "rental-roadside",
			},
		},
	}
}
