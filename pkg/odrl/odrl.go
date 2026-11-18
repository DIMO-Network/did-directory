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
	"bytes"
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

	// TypeAgreement and TypeSet are the two policy types that carry a grant: an
	// Agreement is a bargain between two parties, a Set is an org's own rule about
	// its staff.
	TypeAgreement = "Agreement"
	TypeSet       = "Set"

	// TypeOffer and TypeRequest are ODRL policy types that grant nothing. An Offer
	// is a proposal open for acceptance and a Request is someone asking for
	// access; neither is agreed, and neither parses into a delegation here.
	TypeOffer   = "Offer"
	TypeRequest = "Request"

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
	// Prohibition is here so it can be refused. This codec produces a grant, and a
	// prohibition forbids an action outright; a reader that cannot enforce one
	// must not quietly drop it and hand back a permission the policy qualified.
	Prohibition []Prohibition `json:"prohibition,omitempty"`

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

// Prohibition is an ODRL prohibition: an action the policy forbids, with an
// optional remedy if it happens anyway. Nothing in the delegation record can
// express one, so a policy carrying a prohibition is refused rather than parsed.
type Prohibition struct {
	Target     string       `json:"target"`
	Action     []string     `json:"action"`
	Constraint []Constraint `json:"constraint,omitempty"`
	Remedy     []Duty       `json:"remedy,omitempty"`
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

// Constraints mirrors delegation.RoleConstraints. Durations are seconds, not Go
// nanoseconds: this is a cross-language format and a duration nobody else can
// read is not a term.
type Constraints struct {
	MaxVehicles       int      `json:"maxVehicles,omitempty"`
	MaxValiditySecs   int64    `json:"maxValiditySeconds,omitempty"`
	MaxDataReachSecs  int64    `json:"maxDataReachSeconds,omitempty"`
	Abilities         []string `json:"abilities,omitempty"`
	AllowRedelegation bool     `json:"allowRedelegation,omitempty"`
	AllowExclusive    bool     `json:"allowExclusive,omitempty"`
	Policy            string   `json:"policy,omitempty"`
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
		p.CreatedAt = rec.CreatedAt.UTC().Format(time.RFC3339Nano)
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
		// Seconds are the unit and zero means unlimited, so a sub-second cap would
		// truncate to zero and become no cap at all: the one rounding error in this
		// codec that widens a term instead of narrowing it. A duration the format
		// cannot carry is refused, not rounded.
		for name, d := range map[string]time.Duration{"maxValidity": c.MaxValidity, "maxDataReach": c.MaxDataReach} {
			if d%time.Second != 0 {
				return nil, fmt.Errorf("%w: %s %s is not a whole number of seconds and the wire format carries seconds",
					ErrUnsupported, name, d)
			}
		}
		p.Constraints = &Constraints{
			MaxVehicles:       c.MaxVehicles,
			MaxValiditySecs:   int64(c.MaxValidity / time.Second),
			MaxDataReachSecs:  int64(c.MaxDataReach / time.Second),
			Abilities:         c.Abilities,
			AllowRedelegation: c.AllowRedelegation,
			AllowExclusive:    c.AllowExclusive,
			Policy:            c.Policy,
		}
	}
	return p, nil
}

// Unmarshal parses an ODRL policy into a record, returning its uid and any
// duties it carried.
//
// A key this profile does not define is refused, at any depth, for the same
// reason an unknown constraint is: a reader that drops a term hands back more
// authority than the policy carries.
func Unmarshal(data []byte) (*delegation.Record, string, []Duty, error) {
	p, err := parse(data)
	if err != nil {
		return nil, "", nil, err
	}
	rec, err := FromPolicy(p)
	if err != nil {
		return nil, "", nil, err
	}
	return rec, p.UID, p.Duty, nil
}

// Decode parses a stored policy into the record the evaluator works on.
func Decode(data []byte) (*delegation.Record, error) {
	rec, _, _, err := Unmarshal(data)
	return rec, err
}

// Normalize parses a policy and renders it again in the one form this codec
// produces, with uid as its identifier. A policy that already names a
// different uid is refused: the identifier is where the grant lives, and a
// document claiming to live elsewhere is not the document being written.
//
// Storing the normalized form rather than the submitted bytes means nothing is
// signed that the codec could not read back, and two spellings of the same
// grant commit as one.
func Normalize(data []byte, uid string) ([]byte, *delegation.Record, error) {
	rec, got, duties, err := Unmarshal(data)
	if err != nil {
		return nil, nil, err
	}
	if got != "" && got != uid {
		return nil, nil, fmt.Errorf("%w: uid is %s, but the policy is written at %s", ErrNotODRL, got, uid)
	}
	p, err := ToPolicy(rec, uid, duties...)
	if err != nil {
		return nil, nil, err
	}
	out, err := json.Marshal(p)
	if err != nil {
		return nil, nil, err
	}
	return out, rec, nil
}

func parse(data []byte) (*Policy, error) {
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	var p Policy
	if err := dec.Decode(&p); err != nil {
		return nil, fmt.Errorf("%w: %w", ErrNotODRL, err)
	}
	if dec.More() {
		return nil, fmt.Errorf("%w: trailing data after the policy", ErrNotODRL)
	}
	return &p, nil
}

// FromPolicy converts an ODRL policy to a record.
func FromPolicy(p *Policy) (*delegation.Record, error) {
	if !slices.Contains(p.Context, ContextODRL) {
		return nil, fmt.Errorf("%w: missing the ODRL context", ErrNotODRL)
	}
	for _, c := range p.Context {
		// A context defines what the terms mean to anyone reading the policy as
		// JSON-LD, so one this profile does not know could redefine a term the
		// evaluator reads by name.
		if c != ContextODRL && c != ContextDIMO {
			return nil, fmt.Errorf("%w: context %q", ErrUnsupported, c)
		}
	}
	if p.Profile != Profile {
		return nil, fmt.Errorf("%w: profile %q", ErrUnsupported, p.Profile)
	}
	recType, err := recordType(p.Type)
	if err != nil {
		return nil, err
	}
	if len(p.Prohibition) > 0 {
		// A prohibition forbids an action outright. There is nothing in a
		// delegation record that says "not this", so honouring it is impossible and
		// dropping it would hand back a permission the policy qualified.
		return nil, fmt.Errorf("%w: policy carries a prohibition, which this profile cannot express", ErrUnsupported)
	}
	if len(p.Permission) != 1 {
		// One grant per policy: a permission set with several targets would be
		// several grants, each with its own basis and revocation.
		return nil, fmt.Errorf("%w: expected one permission, got %d", ErrNoPermission, len(p.Permission))
	}
	if len(p.Permission[0].Duty) > 0 {
		// A duty on a permission gates it: the permission holds only while the duty
		// is met. The policy-level obligations ride through untouched for the caller
		// to enforce, but one attached to the permission would turn into an
		// unconditional grant here, which is the opposite of what it says.
		return nil, fmt.Errorf("%w: the permission carries a duty, which gates it and this reader cannot enforce", ErrUnsupported)
	}

	perm := p.Permission[0]
	rec := &delegation.Record{
		Type:            recType,
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

	covers, err := covers(perm.Target, perm.TargetType)
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
		rec.CreatedAt = t.UTC()
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
			MaxDataReach:      time.Duration(c.MaxDataReachSecs) * time.Second,
			Abilities:         c.Abilities,
			AllowRedelegation: c.AllowRedelegation,
			AllowExclusive:    c.AllowExclusive,
			Policy:            c.Policy,
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
		out = append(out, Constraint{left, OpGTEQ, w.From.UTC().Format(time.RFC3339Nano)})
	}
	if w.To != nil {
		out = append(out, Constraint{left, OpLTEQ, w.To.UTC().Format(time.RFC3339Nano)})
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

func covers(target, targetType string) (delegation.Covers, error) {
	switch {
	case target == Prefix+"inherit":
		// A delegation inherits its basis's coverage and a role with no basis
		// covers everything the org controls; which one is allowed is the
		// record's to say (delegation.Record.Validate).
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

// recordType maps a policy type to a record type and refuses everything that is
// not a grant.
//
// ODRL has more policy types than this profile carries, and the difference is
// not decorative: an Offer is a proposal open for acceptance, a Request is
// someone asking. Treating either as an Agreement would turn a document that
// grants nothing into a live delegation, so they are refused for the same reason
// an unknown constraint is — reading a policy as more than it says is the one
// failure this codec must never have.
func recordType(policyType string) (string, error) {
	switch policyType {
	case TypeAgreement:
		return delegation.TypeDelegation, nil
	case TypeSet:
		return delegation.TypeRole, nil
	case "":
		return "", fmt.Errorf("%w: policy has no @type, expected %q or %q", ErrNotODRL, TypeAgreement, TypeSet)
	default:
		return "", fmt.Errorf("%w: policy @type %q grants nothing, expected %q or %q",
			ErrUnsupported, policyType, TypeAgreement, TypeSet)
	}
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
