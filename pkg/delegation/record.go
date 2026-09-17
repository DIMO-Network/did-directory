// Package delegation implements narrowing-only delegations over vehicles and
// tags: record validation, chain evaluation, time-based coverage and commit-time
// policy. It is transport- and storage-agnostic; callers supply a Resolver backed
// by org repositories and the DID directory.
//
// Design: docs/superpowers/specs/2026-09-16-dimo-orgs-fleets-delegation-design.md
package delegation

import (
	"errors"
	"fmt"
	"slices"
	"strings"
	"time"
)

// Record types and collections.
const (
	TypeDelegation = "network.dimo.delegation"
	TypeRole       = "network.dimo.org.role"
	CollectionTag  = "network.dimo.org.tag"
)

// Redelegation modes.
const (
	RedelegateNone       = "none"
	RedelegateAttenuated = "attenuated"
	RedelegateAllowlist  = "allowlist"
)

// Revocation authority.
const (
	RevocableByFrom   = "from"
	RevocableByTo     = "to"
	RevocableByEither = "either"
)

// What happens to historical access when a car leaves a tag or changes controller.
const (
	RetainHistory = "retainHistory"
	Drop          = "drop"
)

// MaxChainDepth is the default maximum delegation chain length (root included).
const MaxChainDepth = 5

// Record is a delegation or role record as stored in an org repository.
type Record struct {
	Type            string     `json:"$type"`
	From            string     `json:"from"`
	To              string     `json:"to"`
	Basis           []string   `json:"basis"`
	Covers          Covers     `json:"covers"`
	Abilities       []string   `json:"abilities"`
	DataWindow      Window     `json:"dataWindow"`
	Validity        Window     `json:"validity"`
	Redelegate      Redelegate `json:"redelegate"`
	RevocableBy     string     `json:"revocableBy,omitempty"`
	AfterRemoval    string     `json:"afterRemoval,omitempty"`
	AfterTransfer   string     `json:"afterTransfer,omitempty"`
	Purpose         string     `json:"purpose,omitempty"`
	Terms           string     `json:"terms,omitempty"`
	ClientAllowlist []string   `json:"clientAllowlist,omitempty"`
	// Exclusive lists live abilities this record holds exclusively while it is
	// live: nobody else, the controller included, may exercise them over the same
	// vehicle. Custody uses it, because an operator must not immobilise a car
	// somebody else is driving.
	Exclusive []string `json:"exclusive,omitempty"`
	// Recovery marks a record that may act despite someone else's exclusive hold.
	// Every such use is reported so the issuer can log it.
	Recovery bool `json:"recovery,omitempty"`
	// NarrowToCustody intersects this record's historical coverage with the times
	// its recipient actually held the vehicle (§12.3). A rental history grant sets
	// it so a renter who returns the car early keeps only the days they drove.
	// Live abilities are untouched: they are governed by validity and exclusivity.
	NarrowToCustody bool `json:"narrowToCustody,omitempty"`
	// Constraints bound the shape of what this role's holder may issue. Roles only.
	Constraints *RoleConstraints `json:"constraints,omitempty"`
	CreatedBy   string           `json:"createdBy,omitempty"`
	CreatedAt   time.Time        `json:"createdAt"`
}

// RoleConstraints bound the shape of the grants a role's holder may author.
//
// A role's abilities say what its holder may do; they say nothing about the
// shape of what it may hand out. A booking service needs delegation:create with
// command:* over the whole fleet to issue a custody grant at every pickup,
// unattended, thousands of times a day. Without a bound on shape, one
// compromised booking service writes itself a fleet-wide, permanent,
// command-bearing grant with exactly the authority it legitimately holds. These
// are the dimensions that separate "issue one custody grant" from "take the
// fleet": how many cars, for how long, which abilities, whether the grant can
// seed a chain or lock the operator out — and how far back in time it reaches.
// Reach backwards is the one that is easy to miss, because it is invisible in
// every dimension the others measure: the narrowest role the design offers, one
// car for one booking with telemetry:read, still hands out every trip every
// prior renter took unless the data window is bounded too.
//
// A nil RoleConstraints is unbounded, which is what every role that predates
// this field means. Zero values inside it are likewise unbounded, so a
// constraint is only ever a restriction someone chose.
type RoleConstraints struct {
	// MaxVehicles is the most vehicles a single issued record may cover. Zero is
	// unlimited. Counted at evaluation time, because a tag that grows later would
	// otherwise carry a grant past the limit it was issued under.
	MaxVehicles int `json:"maxVehicles,omitempty"`
	// MaxValidity is the longest validity window an issued record may have. Zero
	// is unlimited; when set, an unbounded validity is refused, since "forever" is
	// the shape being guarded against. JSON-encoded as nanoseconds.
	MaxValidity time.Duration `json:"maxValidity,omitempty"`
	// MaxDataReach bounds how far before its own validity an issued record's data
	// window may reach back. Zero is unlimited; when set, a data window with no
	// start is refused, and so is a record whose validity has no start to measure
	// the reach against — "everything, from the beginning of time" is the shape
	// being guarded against, and an unbounded end is how it is usually written.
	//
	// It is measured against the record's own validity rather than a clock so the
	// answer is a property of the record and does not change between the commit
	// check and the evaluation weeks later. JSON-encoded as nanoseconds.
	MaxDataReach time.Duration `json:"maxDataReach,omitempty"`
	// Abilities is the set an issued record may grant. Empty means any ability the
	// role itself holds. It is narrower than the role's own abilities on purpose:
	// a service that may read telemetry itself need not be able to hand that out.
	Abilities []string `json:"abilities,omitempty"`
	// AllowRedelegation lets issued records be redelegable. Off by default, so a
	// grant this role issues is a leaf and cannot seed a chain the org never saw.
	AllowRedelegation bool `json:"allowRedelegation,omitempty"`
	// AllowExclusive lets issued records claim exclusivity, and with it recovery,
	// its override. Custody grants need this; nothing else should have it.
	AllowExclusive bool `json:"allowExclusive,omitempty"`
}

// validate checks the constraints against the abilities of the role carrying them.
func (c *RoleConstraints) validate(roleAbilities []string) error {
	if c.MaxVehicles < 0 {
		return errors.New("constraints.maxVehicles must not be negative")
	}
	if c.MaxValidity < 0 {
		return errors.New("constraints.maxValidity must not be negative")
	}
	if c.MaxDataReach < 0 {
		return errors.New("constraints.maxDataReach must not be negative")
	}
	for _, a := range c.Abilities {
		if !slices.Contains(roleAbilities, a) {
			return fmt.Errorf("constraints.abilities lists %s, which the role does not hold", a)
		}
	}
	return nil
}

// check reports whether a record authored under this role stays inside it.
// coveredVehicles is how many vehicles the record applies to. A nil receiver is
// an unconstrained role and accepts everything.
func (c *RoleConstraints) check(rec *Record, coveredVehicles int) error {
	if c == nil {
		return nil
	}
	if len(c.Abilities) > 0 {
		for _, a := range rec.Abilities {
			if !slices.Contains(c.Abilities, a) {
				return fmt.Errorf("%w: may not issue %s", ErrExceedsRole, a)
			}
		}
	}
	if c.MaxVehicles > 0 && coveredVehicles > c.MaxVehicles {
		return fmt.Errorf("%w: covers %d vehicles, limit %d", ErrExceedsRole, coveredVehicles, c.MaxVehicles)
	}
	if c.MaxValidity > 0 {
		switch w := rec.Validity; {
		case w.From == nil || w.To == nil:
			return fmt.Errorf("%w: validity must be bounded at both ends, limit %s", ErrExceedsRole, c.MaxValidity)
		case w.To.Sub(*w.From) > c.MaxValidity:
			return fmt.Errorf("%w: validity of %s exceeds limit %s", ErrExceedsRole, w.To.Sub(*w.From), c.MaxValidity)
		}
	}
	if c.MaxDataReach > 0 {
		switch d, v := rec.DataWindow, rec.Validity; {
		case d.From == nil:
			return fmt.Errorf("%w: dataWindow must have a start, limit %s of reach back", ErrExceedsRole, c.MaxDataReach)
		case v.From == nil:
			return fmt.Errorf("%w: validity must have a start to measure dataWindow reach against", ErrExceedsRole)
		case v.From.Sub(*d.From) > c.MaxDataReach:
			return fmt.Errorf("%w: dataWindow reaches %s before validity, limit %s", ErrExceedsRole, v.From.Sub(*d.From), c.MaxDataReach)
		}
	}
	if !c.AllowRedelegation && rec.redelegateMode() != RedelegateNone {
		return fmt.Errorf("%w: may not issue redelegable grants", ErrExceedsRole)
	}
	if !c.AllowExclusive && (len(rec.Exclusive) > 0 || rec.Recovery) {
		return fmt.Errorf("%w: may not issue exclusive or recovery grants", ErrExceedsRole)
	}
	return nil
}

// Covers selects what a record applies to. Exactly one field is set.
type Covers struct {
	Vehicle string `json:"vehicle,omitempty"`
	Tag     string `json:"tag,omitempty"`
	Inherit bool   `json:"inherit,omitempty"`
}

// Window is a time range; nil ends are unbounded.
type Window struct {
	From *time.Time `json:"from,omitempty"`
	To   *time.Time `json:"to,omitempty"`
}

// Set returns the window as an interval set.
func (w Window) Set() Set { return Span(w.From, w.To) }

// Redelegate controls whether the recipient may delegate further.
type Redelegate struct {
	Mode     string   `json:"mode"`
	MaxDepth int      `json:"maxDepth,omitempty"`
	Grantees []string `json:"grantees,omitempty"`
	// Exclusive lets a child claim abilities exclusively (see Record.Exclusive).
	// A host permits it once; the booking that claims it is time-bounded, so the
	// host only loses control for the custody window.
	Exclusive bool `json:"exclusive,omitempty"`
}

// AbilityClass determines how time applies to an ability.
type AbilityClass int

const (
	// Historical abilities are checked against data timestamps.
	Historical AbilityClass = iota
	// Live abilities are checked against the time of the request.
	Live
	// Admin abilities act inside an org and are checked at request time.
	Admin
)

// IsActuating reports whether an ability makes the vehicle do something —
// unlock, start, charge. Actuation is what a second approval is for, and what
// custody suspends; writing data is neither.
func IsActuating(ability string) bool {
	return strings.HasPrefix(ability, "command:")
}

// ClassOf classifies an ability by namespace.
//
// Writing and delivering data are live: a device sending a reading is doing it
// now, so the check is against the time of the request, not against the
// timestamps of data it has yet to produce. Checking a write against a data
// window would ask whether a device may write a reading it has not taken.
func ClassOf(ability string) AbilityClass {
	switch {
	// Admin namespaces first: tag:write edits a tag, it does not write vehicle data.
	case strings.HasPrefix(ability, "delegation:"), strings.HasPrefix(ability, "tag:"),
		strings.HasPrefix(ability, "org:"), strings.HasPrefix(ability, "license:"):
		return Admin
	case strings.HasPrefix(ability, "command:"), strings.HasPrefix(ability, "stream:"),
		strings.HasSuffix(ability, ":write"), strings.HasSuffix(ability, ":deliver"):
		return Live
	default:
		return Historical
	}
}

func (r *Record) revocableBy() string   { return orDefault(r.RevocableBy, RevocableByFrom) }
func (r *Record) afterRemoval() string  { return orDefault(r.AfterRemoval, RetainHistory) }
func (r *Record) afterTransfer() string { return orDefault(r.AfterTransfer, RetainHistory) }
func (r *Record) redelegateMode() string {
	return orDefault(r.Redelegate.Mode, RedelegateNone)
}

func orDefault(v, def string) string {
	if v == "" {
		return def
	}
	return v
}

// Validate checks a record's structure. It does not resolve anything.
func (r *Record) Validate() error {
	if r.Type != TypeDelegation && r.Type != TypeRole {
		return fmt.Errorf("unknown record type %q", r.Type)
	}
	if !isDID(r.From) || !isDID(r.To) {
		return errors.New("from and to must be DIDs")
	}
	if r.From == r.To {
		return errors.New("from and to must differ")
	}

	set := 0
	if r.Covers.Vehicle != "" {
		set++
		if !isDID(r.Covers.Vehicle) {
			return errors.New("covers.vehicle must be a DID")
		}
	}
	if r.Covers.Tag != "" {
		set++
		if _, err := TagAuthority(r.Covers.Tag); err != nil {
			return err
		}
	}
	if r.Covers.Inherit {
		set++
		if len(r.Basis) == 0 && r.Type == TypeDelegation {
			return errors.New("covers.inherit requires a basis")
		}
	}
	if set != 1 {
		return errors.New("covers must set exactly one of vehicle, tag or inherit")
	}

	if len(r.Abilities) == 0 {
		return errors.New("abilities must not be empty")
	}
	if len(slices.Compact(slices.Sorted(slices.Values(r.Abilities)))) != len(r.Abilities) {
		return errors.New("abilities must not repeat")
	}

	for name, w := range map[string]Window{"dataWindow": r.DataWindow, "validity": r.Validity} {
		if w.From != nil && w.To != nil && !w.From.Before(*w.To) {
			return fmt.Errorf("%s.from must be before %s.to", name, name)
		}
	}

	switch r.redelegateMode() {
	case RedelegateNone:
	case RedelegateAttenuated:
		if r.Redelegate.MaxDepth < 1 {
			return errors.New("attenuated redelegation requires maxDepth >= 1")
		}
	case RedelegateAllowlist:
		if len(r.Redelegate.Grantees) == 0 {
			return errors.New("allowlist redelegation requires grantees")
		}
	default:
		return fmt.Errorf("unknown redelegate mode %q", r.Redelegate.Mode)
	}

	if !slices.Contains([]string{RevocableByFrom, RevocableByTo, RevocableByEither}, r.revocableBy()) {
		return fmt.Errorf("unknown revocableBy %q", r.RevocableBy)
	}
	for _, v := range []string{r.afterRemoval(), r.afterTransfer()} {
		if v != RetainHistory && v != Drop {
			return fmt.Errorf("unknown history policy %q", v)
		}
	}

	for _, a := range r.Exclusive {
		if !slices.Contains(r.Abilities, a) {
			return fmt.Errorf("exclusive ability %s is not granted by this record", a)
		}
		if ClassOf(a) != Live {
			return fmt.Errorf("only live abilities can be exclusive, got %s", a)
		}
	}
	if r.Recovery && !slices.ContainsFunc(r.Abilities, func(a string) bool { return ClassOf(a) == Live }) {
		return errors.New("recovery requires at least one live ability")
	}

	if r.Constraints != nil {
		if r.Type != TypeRole {
			return errors.New("only roles carry issue constraints")
		}
		if err := r.Constraints.validate(r.Abilities); err != nil {
			return err
		}
	}

	if r.Type == TypeRole {
		if len(r.Basis) != 0 {
			return errors.New("roles must not have a basis")
		}
		if r.NarrowToCustody {
			return errors.New("roles are not narrowed by custody")
		}
		if r.redelegateMode() != RedelegateNone {
			return errors.New("roles cannot be redelegated")
		}
		if r.revocableBy() != RevocableByFrom {
			return errors.New("roles are revocable only by the org")
		}
		if len(r.Exclusive) != 0 || r.Recovery {
			return errors.New("roles cannot be exclusive or recovery records")
		}
	}
	return nil
}

// TagAuthority returns the org DID that owns a tag URI of the form
// at://<did>/network.dimo.org.tag/<slug>.
func TagAuthority(uri string) (string, error) {
	authority, collection, rkey, err := ParseURI(uri)
	if err != nil {
		return "", err
	}
	if collection != CollectionTag || rkey == "" {
		return "", fmt.Errorf("not a tag URI: %s", uri)
	}
	return authority, nil
}

// ParseURI splits at://<authority>/<collection>/<rkey>.
func ParseURI(uri string) (authority, collection, rkey string, err error) {
	rest, ok := strings.CutPrefix(uri, "at://")
	if !ok {
		return "", "", "", fmt.Errorf("URI must start with at://: %s", uri)
	}
	parts := strings.Split(rest, "/")
	if len(parts) != 3 || !isDID(parts[0]) || parts[1] == "" || parts[2] == "" {
		return "", "", "", fmt.Errorf("URI must be at://<did>/<collection>/<rkey>: %s", uri)
	}
	return parts[0], parts[1], parts[2], nil
}

func isDID(s string) bool {
	return strings.HasPrefix(s, "did:") && len(s) > len("did:")
}

// windowWithin reports whether inner ⊆ outer.
func windowWithin(inner, outer Window) bool {
	return outer.Set().Covers(inner.Set())
}
