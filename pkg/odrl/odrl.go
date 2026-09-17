// Package odrl is the wire format for DIMO grants.
//
// The fixed choices for DIMO 3.0 say permissions are expressed in ODRL with a
// DIMO profile. A delegation.Record is the parsed form the evaluator works on;
// this package is what crosses a wire, lands in an org's repository, or is shown
// to a counterparty's lawyer. The two are the same grant in two shapes, and the
// round trip is lossless — a term nobody can read back is a term nobody agreed
// to.
//
// The mapping follows ODRL 2.2 where ODRL has the concept and the DIMO profile
// where it does not:
//
//	assigner / assignee      from / to
//	target                   covers — an AssetCollection for a tag, an Asset for a vehicle
//	action                   abilities, as profile IRIs
//	constraint dateTime      validity
//	constraint dimo:dataTime the data window
//	duty                     what code cannot enforce: payment, retention, refunds
//
// Delegation, exclusivity, custody narrowing and issue constraints have no ODRL
// equivalent, so they are profile terms under the dimo: prefix rather than
// bent-out-of-shape ODRL.
package odrl

import (
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"strings"
	"time"

	"github.com/DIMO-Network/did-directory/pkg/delegation"
)

// Vocabulary.
const (
	ContextODRL = "http://www.w3.org/ns/odrl.jsonld"
	ContextDIMO = "https://schema.dimo.zone/odrl/v1"
	Profile     = ContextDIMO

	TypeAgreement = "Agreement"
	TypeSet       = "Set"

	// Prefix namespaces every profile term and every ability IRI.
	Prefix = "dimo:"
)

// Errors.
var (
	ErrNotODRL      = errors.New("not an ODRL policy")
	ErrUnsupported  = errors.New("unsupported ODRL policy")
	ErrNoPermission = errors.New("policy carries no permission")
)

// Policy is an ODRL policy carrying one DIMO grant.
type Policy struct {
	Context    []string     `json:"@context"`
	Type       string       `json:"@type"`
	UID        string       `json:"uid,omitempty"`
	Profile    string       `json:"profile"`
	Assigner   string       `json:"assigner"`
	Assignee   string       `json:"assignee"`
	Permission []Permission `json:"permission"`
	Duty       []Duty       `json:"obligation,omitempty"`

	// Profile terms. ODRL has no delegation primitive, no exclusivity and no
	// notion of a grant that narrows another, so these stay explicit rather than
	// being forced into ODRL shapes that would mislead a reader who knows ODRL.
	Basis         []string     `json:"dimo:basis,omitempty"`
	Redelegate    *Redelegate  `json:"dimo:redelegate,omitempty"`
	RevocableBy   string       `json:"dimo:revocableBy,omitempty"`
	AfterRemoval  string       `json:"dimo:afterRemoval,omitempty"`
	AfterTransfer string       `json:"dimo:afterTransfer,omitempty"`
	Exclusive     []string     `json:"dimo:exclusive,omitempty"`
	Recovery      bool         `json:"dimo:recovery,omitempty"`
	Custody       bool         `json:"dimo:narrowToCustody,omitempty"`
	Constraints   *Constraints `json:"dimo:issueConstraints,omitempty"`
	Terms         string       `json:"dimo:terms,omitempty"`
	CreatedBy     string       `json:"dimo:createdBy,omitempty"`
	CreatedAt     string       `json:"dcterms:issued,omitempty"`
}

// Permission is an ODRL permission: what may be done, to what, under which
// constraints.
type Permission struct {
	Target     string       `json:"target"`
	TargetType string       `json:"@type,omitempty"`
	Action     []string     `json:"action"`
	Constraint []Constraint `json:"constraint,omitempty"`
	Duty       []Duty       `json:"duty,omitempty"`
}

// Constraint is an ODRL constraint.
type Constraint struct {
	LeftOperand  string `json:"leftOperand"`
	Operator     string `json:"operator"`
	RightOperand any    `json:"rightOperand"`
}

// Duty carries what code cannot enforce: payment, retention, a refund promise.
// It rides through the codec untouched so nothing agreed is lost in transit.
type Duty struct {
	Action     string       `json:"action"`
	Constraint []Constraint `json:"constraint,omitempty"`
	Target     string       `json:"target,omitempty"`
}

// Redelegate mirrors delegation.Redelegate.
type Redelegate struct {
	Mode      string   `json:"mode"`
	MaxDepth  int      `json:"maxDepth,omitempty"`
	Grantees  []string `json:"grantees,omitempty"`
	Exclusive bool     `json:"exclusive,omitempty"`
}

// Constraints mirrors delegation.RoleConstraints. MaxValidity is seconds, not Go
// nanoseconds: this is a cross-language format and a duration nobody else can
// read is not a term.
type Constraints struct {
	MaxVehicles       int      `json:"maxVehicles,omitempty"`
	MaxValiditySecs   int64    `json:"maxValiditySeconds,omitempty"`
	Abilities         []string `json:"abilities,omitempty"`
	AllowRedelegation bool     `json:"allowRedelegation,omitempty"`
	AllowExclusive    bool     `json:"allowExclusive,omitempty"`
}

// Operators and left operands used by the profile.
const (
	OpGTEQ    = "gteq"
	OpLTEQ    = "lteq"
	OpEQ      = "eq"
	OpIsAnyOf = "isAnyOf"

	LeftDateTime = "dateTime"
	LeftPurpose  = "purpose"
	LeftDataTime = "dimo:dataTime"
	LeftClient   = "dimo:client"
)

// Action converts an ability to its profile IRI. The colon becomes a dot so the
// result is a valid compact IRI: "telemetry:read" would otherwise read as the
// prefix "telemetry".
func Action(ability string) string {
	return Prefix + strings.Replace(ability, ":", ".", 1)
}

// Ability converts a profile IRI back to an ability.
func Ability(action string) (string, error) {
	rest, ok := strings.CutPrefix(action, Prefix)
	if !ok {
		return "", fmt.Errorf("%w: action %q is outside the DIMO profile", ErrUnsupported, action)
	}
	return strings.Replace(rest, ".", ":", 1), nil
}

// Marshal renders a record as an ODRL policy. Duties are the terms code cannot
// enforce; pass any the agreement carries.
func Marshal(rec *delegation.Record, uid string, duties ...Duty) ([]byte, error) {
	p, err := ToPolicy(rec, uid, duties...)
	if err != nil {
		return nil, err
	}
	return json.MarshalIndent(p, "", "  ")
}

// ToPolicy converts a record to an ODRL policy.
func ToPolicy(rec *delegation.Record, uid string, duties ...Duty) (*Policy, error) {
	if err := rec.Validate(); err != nil {
		return nil, err
	}

	perm := Permission{Target: target(rec.Covers), TargetType: targetType(rec.Covers)}
	for _, a := range rec.Abilities {
		perm.Action = append(perm.Action, Action(a))
	}
	perm.Constraint = append(perm.Constraint, window(LeftDateTime, rec.Validity)...)
	perm.Constraint = append(perm.Constraint, window(LeftDataTime, rec.DataWindow)...)
	if rec.Purpose != "" {
		perm.Constraint = append(perm.Constraint, Constraint{LeftPurpose, OpEQ, rec.Purpose})
	}
	if len(rec.ClientAllowlist) > 0 {
		perm.Constraint = append(perm.Constraint, Constraint{LeftClient, OpIsAnyOf, rec.ClientAllowlist})
	}

	p := &Policy{
		Context:       []string{ContextODRL, ContextDIMO},
		Type:          policyType(rec.Type),
		UID:           uid,
		Profile:       Profile,
		Assigner:      rec.From,
		Assignee:      rec.To,
		Permission:    []Permission{perm},
		Duty:          duties,
		Basis:         rec.Basis,
		RevocableBy:   rec.RevocableBy,
		AfterRemoval:  rec.AfterRemoval,
		AfterTransfer: rec.AfterTransfer,
		Exclusive:     exclusiveActions(rec.Exclusive),
		Recovery:      rec.Recovery,
		Custody:       rec.NarrowToCustody,
		Terms:         rec.Terms,
		CreatedBy:     rec.CreatedBy,
	}
	if !rec.CreatedAt.IsZero() {
		p.CreatedAt = rec.CreatedAt.UTC().Format(time.RFC3339)
	}
	if rec.Redelegate.Mode != "" {
		p.Redelegate = &Redelegate{
			Mode:      rec.Redelegate.Mode,
			MaxDepth:  rec.Redelegate.MaxDepth,
			Grantees:  rec.Redelegate.Grantees,
			Exclusive: rec.Redelegate.Exclusive,
		}
	}
	if c := rec.Constraints; c != nil {
		p.Constraints = &Constraints{
			MaxVehicles:       c.MaxVehicles,
			MaxValiditySecs:   int64(c.MaxValidity / time.Second),
			Abilities:         c.Abilities,
			AllowRedelegation: c.AllowRedelegation,
			AllowExclusive:    c.AllowExclusive,
		}
	}
	return p, nil
}

// Unmarshal parses an ODRL policy into a record, returning its uid and any
// duties it carried.
func Unmarshal(data []byte) (*delegation.Record, string, []Duty, error) {
	var p Policy
	if err := json.Unmarshal(data, &p); err != nil {
		return nil, "", nil, fmt.Errorf("%w: %w", ErrNotODRL, err)
	}
	rec, err := FromPolicy(&p)
	if err != nil {
		return nil, "", nil, err
	}
	return rec, p.UID, p.Duty, nil
}

// FromPolicy converts an ODRL policy to a record.
func FromPolicy(p *Policy) (*delegation.Record, error) {
	if !slices.Contains(p.Context, ContextODRL) {
		return nil, fmt.Errorf("%w: missing the ODRL context", ErrNotODRL)
	}
	if p.Profile != Profile {
		return nil, fmt.Errorf("%w: profile %q", ErrUnsupported, p.Profile)
	}
	if len(p.Permission) != 1 {
		// One grant per policy: a permission set with several targets would be
		// several grants, each with its own basis and revocation.
		return nil, fmt.Errorf("%w: expected one permission, got %d", ErrNoPermission, len(p.Permission))
	}

	perm := p.Permission[0]
	rec := &delegation.Record{
		Type:            recordType(p.Type),
		From:            p.Assigner,
		To:              p.Assignee,
		Basis:           p.Basis,
		RevocableBy:     p.RevocableBy,
		AfterRemoval:    p.AfterRemoval,
		AfterTransfer:   p.AfterTransfer,
		Recovery:        p.Recovery,
		NarrowToCustody: p.Custody,
		Terms:           p.Terms,
		CreatedBy:       p.CreatedBy,
	}

	covers, err := covers(perm.Target, perm.TargetType, p.Basis)
	if err != nil {
		return nil, err
	}
	rec.Covers = covers

	for _, a := range perm.Action {
		ability, err := Ability(a)
		if err != nil {
			return nil, err
		}
		rec.Abilities = append(rec.Abilities, ability)
	}
	for _, e := range p.Exclusive {
		ability, err := Ability(e)
		if err != nil {
			return nil, err
		}
		rec.Exclusive = append(rec.Exclusive, ability)
	}

	for _, c := range perm.Constraint {
		if err := applyConstraint(rec, c); err != nil {
			return nil, err
		}
	}

	if p.CreatedAt != "" {
		t, err := time.Parse(time.RFC3339, p.CreatedAt)
		if err != nil {
			return nil, fmt.Errorf("%w: dcterms:issued: %w", ErrNotODRL, err)
		}
		rec.CreatedAt = t
	}
	if r := p.Redelegate; r != nil {
		rec.Redelegate = delegation.Redelegate{
			Mode:      r.Mode,
			MaxDepth:  r.MaxDepth,
			Grantees:  r.Grantees,
			Exclusive: r.Exclusive,
		}
	}
	if c := p.Constraints; c != nil {
		rec.Constraints = &delegation.RoleConstraints{
			MaxVehicles:       c.MaxVehicles,
			MaxValidity:       time.Duration(c.MaxValiditySecs) * time.Second,
			Abilities:         c.Abilities,
			AllowRedelegation: c.AllowRedelegation,
			AllowExclusive:    c.AllowExclusive,
		}
	}

	if err := rec.Validate(); err != nil {
		return nil, err
	}
	return rec, nil
}

func applyConstraint(rec *delegation.Record, c Constraint) error {
	switch c.LeftOperand {
	case LeftDateTime:
		return timeBound(&rec.Validity, c)
	case LeftDataTime:
		return timeBound(&rec.DataWindow, c)
	case LeftPurpose:
		s, ok := c.RightOperand.(string)
		if !ok {
			return fmt.Errorf("%w: purpose must be a string", ErrNotODRL)
		}
		rec.Purpose = s
		return nil
	case LeftClient:
		list, err := strList(c.RightOperand)
		if err != nil {
			return fmt.Errorf("%w: client allowlist: %w", ErrNotODRL, err)
		}
		rec.ClientAllowlist = list
		return nil
	default:
		// An unknown constraint is a term this reader cannot honour. Refusing is
		// the only safe answer: silently dropping it would grant more than the
		// policy says.
		return fmt.Errorf("%w: constraint %q", ErrUnsupported, c.LeftOperand)
	}
}

func timeBound(w *delegation.Window, c Constraint) error {
	s, ok := c.RightOperand.(string)
	if !ok {
		return fmt.Errorf("%w: %s must be a timestamp", ErrNotODRL, c.LeftOperand)
	}
	t, err := time.Parse(time.RFC3339, s)
	if err != nil {
		return fmt.Errorf("%w: %s: %w", ErrNotODRL, c.LeftOperand, err)
	}
	t = t.UTC()
	switch c.Operator {
	case OpGTEQ:
		w.From = &t
	case OpLTEQ:
		w.To = &t
	default:
		return fmt.Errorf("%w: operator %q on %s", ErrUnsupported, c.Operator, c.LeftOperand)
	}
	return nil
}

func window(left string, w delegation.Window) []Constraint {
	var out []Constraint
	if w.From != nil {
		out = append(out, Constraint{left, OpGTEQ, w.From.UTC().Format(time.RFC3339)})
	}
	if w.To != nil {
		out = append(out, Constraint{left, OpLTEQ, w.To.UTC().Format(time.RFC3339)})
	}
	return out
}

func target(c delegation.Covers) string {
	switch {
	case c.Vehicle != "":
		return c.Vehicle
	case c.Tag != "":
		return c.Tag
	default:
		return Prefix + "inherit"
	}
}

// targetType names what the target is. A tag is an ODRL AssetCollection, which
// is the concept ODRL already has for "a set that changes over time".
func targetType(c delegation.Covers) string {
	switch {
	case c.Tag != "":
		return "AssetCollection"
	case c.Vehicle != "":
		return "Asset"
	default:
		return ""
	}
}

func covers(target, targetType string, basis []string) (delegation.Covers, error) {
	switch {
	case target == Prefix+"inherit":
		if len(basis) == 0 {
			return delegation.Covers{}, fmt.Errorf("%w: an inherited target needs a basis", ErrNotODRL)
		}
		return delegation.Covers{Inherit: true}, nil
	case targetType == "AssetCollection", strings.Contains(target, "/"+delegation.CollectionTag+"/"):
		return delegation.Covers{Tag: target}, nil
	default:
		return delegation.Covers{Vehicle: target}, nil
	}
}

func exclusiveActions(abilities []string) []string {
	var out []string
	for _, a := range abilities {
		out = append(out, Action(a))
	}
	return out
}

func policyType(recordType string) string {
	if recordType == delegation.TypeRole {
		// A role is an org's own rule about its staff, not a bargain between two
		// parties: ODRL calls that a Set.
		return TypeSet
	}
	return TypeAgreement
}

func recordType(policyType string) string {
	if policyType == TypeSet {
		return delegation.TypeRole
	}
	return delegation.TypeDelegation
}

// strList reads a list of strings from either a policy built in Go, where the
// value is already []string, or one parsed from JSON, where it is []any.
func strList(v any) ([]string, error) {
	if ss, ok := v.([]string); ok {
		return ss, nil
	}
	items, ok := v.([]any)
	if !ok {
		return nil, errors.New("expected a list")
	}
	out := make([]string, 0, len(items))
	for _, it := range items {
		s, ok := it.(string)
		if !ok {
			return nil, errors.New("expected a list of strings")
		}
		out = append(out, s)
	}
	return out, nil
}
