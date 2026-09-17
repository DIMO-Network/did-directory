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
	CreatedBy       string     `json:"createdBy,omitempty"`
	CreatedAt       time.Time  `json:"createdAt"`
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

// ClassOf classifies an ability by namespace.
func ClassOf(ability string) AbilityClass {
	switch {
	case strings.HasPrefix(ability, "command:"), strings.HasPrefix(ability, "stream:"):
		return Live
	case strings.HasPrefix(ability, "delegation:"), strings.HasPrefix(ability, "tag:"),
		strings.HasPrefix(ability, "org:"), strings.HasPrefix(ability, "license:"):
		return Admin
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

	if r.Type == TypeRole {
		if len(r.Basis) != 0 {
			return errors.New("roles must not have a basis")
		}
		if r.redelegateMode() != RedelegateNone {
			return errors.New("roles cannot be redelegated")
		}
		if r.revocableBy() != RevocableByFrom {
			return errors.New("roles are revocable only by the org")
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
