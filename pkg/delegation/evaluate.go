package delegation

import (
	"context"
	"errors"
	"fmt"
	"maps"
	"slices"
	"time"

	"github.com/DIMO-Network/did-directory/pkg/control"
)

// Evaluation errors.
var (
	ErrNotCovered       = errors.New("vehicle is not covered")
	ErrRevoked          = errors.New("delegation has been revoked")
	ErrNotValid         = errors.New("delegation is not valid at this time")
	ErrNotNarrowing     = errors.New("delegation does not narrow its basis")
	ErrUnauthorized     = errors.New("caller is not authorized to use this delegation")
	ErrClientNotAllowed = errors.New("client is not allowed to use this delegation")
	ErrChainTooDeep     = errors.New("delegation chain is too deep")
	ErrLienNotAllowed   = errors.New("only an org may issue a delegation revocable only by its recipient")
)

// Kind is the kind of principal behind a DID.
type Kind int

const (
	KindUnknown Kind = iota
	KindPerson
	KindOrg
)

// Stored is a committed record plus repository metadata.
type Stored struct {
	URI         string
	Record      Record
	CommittedAt time.Time
	Tombstone   *Tombstone
}

// Tombstone marks a revoked record. By is the principal whose repository write
// revoked it; tombstones by a principal not allowed by revocableBy are ignored.
type Tombstone struct {
	At time.Time
	By string
}

// Membership is one interval of a vehicle in a tag.
type Membership struct {
	Tag         string
	Vehicle     string
	JoinedAt    time.Time
	LeftAt      *time.Time
	CreatedBy   string
	CommittedAt time.Time
}

// Resolver supplies repository and directory data to the evaluator.
type Resolver interface {
	// Record returns a delegation or role record by URI.
	Record(ctx context.Context, uri string) (*Stored, error)
	// Memberships returns every membership interval of vehicle in tag.
	Memberships(ctx context.Context, tag, vehicle string) ([]Membership, error)
	// Roles returns role records issued by org to member, including tombstoned ones.
	Roles(ctx context.Context, org, member string) ([]Stored, error)
	// ControlState returns the vehicle's control eras from the DID directory.
	ControlState(ctx context.Context, vehicle string) (*control.State, error)
	// Opening returns controller's opening for the vehicle's era, or nil if the
	// controller holds none.
	Opening(ctx context.Context, vehicle string, era uint64, controller string) (*control.Opening, error)
	// Kind returns the principal kind of a DID.
	Kind(ctx context.Context, did string) (Kind, error)
}

// Coverage is what a delegation grants over one vehicle at a point in time.
type Coverage struct {
	Vehicle string `json:"vehicle"`
	// Historical maps each historical ability to the data-timestamp windows it may read.
	Historical map[string]Set `json:"historical,omitempty"`
	// Live lists live and admin abilities usable at the evaluation time.
	Live []string `json:"live,omitempty"`
	// Chain lists record URIs from the evaluated record to its root.
	Chain []string `json:"chain"`
}

// Empty reports whether the coverage grants nothing.
func (c *Coverage) Empty() bool {
	return len(c.Live) == 0 && !slices.ContainsFunc(slices.Collect(maps.Values(c.Historical)), func(s Set) bool { return !s.IsEmpty() })
}

// anyClient disables client allowlist checks for caller-less evaluation.
const anyClient = "\x00any"

// Evaluator resolves delegation chains into coverage.
type Evaluator struct {
	Resolver Resolver
	// MaxDepth bounds chain length; zero means MaxChainDepth.
	MaxDepth int
}

// Authorize checks that caller (optionally using clientID) may exercise the
// delegation at uri over vehicle at time at, and returns the coverage filtered to
// the requested abilities. The caller must be the recipient or a member of the
// recipient org holding a role with the requested abilities.
func (e *Evaluator) Authorize(ctx context.Context, uri, caller, clientID, vehicle string, abilities []string, at time.Time) (*Coverage, error) {
	s, err := e.Resolver.Record(ctx, uri)
	if err != nil {
		return nil, err
	}
	if s.Record.Type != TypeDelegation {
		return nil, fmt.Errorf("%s is not a delegation", uri)
	}
	if s.Record.To != caller {
		ok, err := e.useRole(ctx, s.Record.To, caller, vehicle, abilities, at)
		if err != nil {
			return nil, err
		}
		if !ok {
			return nil, ErrUnauthorized
		}
	}

	cov, err := e.evaluate(ctx, s, vehicle, clientID, at, 1, map[string]bool{})
	if err != nil {
		return nil, err
	}

	filtered := &Coverage{Vehicle: vehicle, Historical: map[string]Set{}, Chain: cov.Chain}
	for _, a := range abilities {
		if w, ok := cov.Historical[a]; ok && !w.IsEmpty() {
			filtered.Historical[a] = w
		}
		if slices.Contains(cov.Live, a) {
			filtered.Live = append(filtered.Live, a)
		}
	}
	if filtered.Empty() {
		return nil, ErrNotCovered
	}
	return filtered, nil
}

// Coverage evaluates the delegation at uri over vehicle at time at, without a
// caller check.
func (e *Evaluator) Coverage(ctx context.Context, uri, vehicle string, at time.Time) (*Coverage, error) {
	s, err := e.Resolver.Record(ctx, uri)
	if err != nil {
		return nil, err
	}
	return e.evaluate(ctx, s, vehicle, anyClient, at, 1, map[string]bool{})
}

func (e *Evaluator) maxDepth() int {
	if e.MaxDepth > 0 {
		return e.MaxDepth
	}
	return MaxChainDepth
}

func (e *Evaluator) evaluate(ctx context.Context, s *Stored, vehicle, clientID string, at time.Time, depth int, seen map[string]bool) (*Coverage, error) {
	rec := &s.Record
	if depth > e.maxDepth() {
		return nil, ErrChainTooDeep
	}
	if seen[s.URI] {
		return nil, fmt.Errorf("delegation cycle at %s", s.URI)
	}
	seen[s.URI] = true
	defer delete(seen, s.URI)

	if rec.Type != TypeDelegation {
		return nil, fmt.Errorf("%s is not a delegation", s.URI)
	}
	if err := rec.Validate(); err != nil {
		return nil, fmt.Errorf("invalid delegation %s: %w", s.URI, err)
	}
	if revokedAt(rec, s.Tombstone, at) {
		return nil, ErrRevoked
	}
	if !rec.Validity.Set().Contains(at) {
		return nil, ErrNotValid
	}
	if clientID != anyClient && len(rec.ClientAllowlist) > 0 && !slices.Contains(rec.ClientAllowlist, clientID) {
		return nil, ErrClientNotAllowed
	}

	fromKind, err := e.Resolver.Kind(ctx, rec.From)
	if err != nil {
		return nil, err
	}
	if rec.revocableBy() == RevocableByTo && fromKind != KindOrg {
		return nil, ErrLienNotAllowed
	}

	// A member authoring on behalf of an org needs delegation:create over the scope.
	if rec.CreatedBy != "" && rec.CreatedBy != rec.From {
		if fromKind != KindOrg {
			return nil, fmt.Errorf("%s authored by %s, but %s is not an org", s.URI, rec.CreatedBy, rec.From)
		}
		need := append([]string{"delegation:create"}, rec.Abilities...)
		ok, err := e.hasRole(ctx, rec.From, rec.CreatedBy, rec.Covers, need, s.CommittedAt)
		if err != nil {
			return nil, err
		}
		if !ok {
			return nil, fmt.Errorf("%s: author %s lacked authority when committed", s.URI, rec.CreatedBy)
		}
	}

	member, liveMember, err := e.membership(ctx, rec, vehicle, at)
	if err != nil {
		return nil, err
	}

	var authority map[string]Set
	var liveAuthority map[string]bool
	var chain []string
	if len(rec.Basis) == 0 {
		authority, liveAuthority, err = e.root(ctx, s, vehicle, at)
	} else {
		authority, liveAuthority, chain, err = e.parents(ctx, s, vehicle, clientID, at, depth, seen)
	}
	if err != nil {
		return nil, err
	}

	cov := &Coverage{Vehicle: vehicle, Historical: map[string]Set{}, Chain: []string{s.URI}}
	base := member.Intersect(rec.DataWindow.Set())
	for _, a := range rec.Abilities {
		if ClassOf(a) == Historical {
			if w := base.Intersect(authority[a]); !w.IsEmpty() {
				cov.Historical[a] = w
			}
			continue
		}
		if liveMember && liveAuthority[a] {
			cov.Live = append(cov.Live, a)
		}
	}
	cov.Chain = append(cov.Chain, chain...)
	if cov.Empty() {
		return nil, ErrNotCovered
	}
	return cov, nil
}

// membership returns the data-time set over which rec covers vehicle, and whether
// the vehicle is covered at time at.
func (e *Evaluator) membership(ctx context.Context, rec *Record, vehicle string, at time.Time) (Set, bool, error) {
	switch {
	case rec.Covers.Inherit:
		return All(), true, nil
	case rec.Covers.Vehicle != "":
		if rec.Covers.Vehicle != vehicle {
			return nil, false, ErrNotCovered
		}
		return All(), true, nil
	}

	org, _ := TagAuthority(rec.Covers.Tag)
	if org != rec.From {
		return nil, false, fmt.Errorf("%w: tag %s is not owned by %s", ErrNotNarrowing, rec.Covers.Tag, rec.From)
	}
	memberships, err := e.Resolver.Memberships(ctx, rec.Covers.Tag, vehicle)
	if err != nil {
		return nil, false, err
	}

	var set Set
	live := false
	need := append([]string{"tag:write"}, rec.Abilities...)
	for _, m := range memberships {
		// Tag edits widen every delegation over the tag, so they count only when the
		// author could have granted these abilities at commit time.
		if m.CreatedBy != "" && m.CreatedBy != org {
			ok, err := e.hasRole(ctx, org, m.CreatedBy, Covers{Tag: rec.Covers.Tag}, need, m.CommittedAt)
			if err != nil {
				return nil, false, err
			}
			if !ok {
				continue
			}
		}
		left := m.LeftAt != nil && !m.LeftAt.After(at)
		if left && rec.afterRemoval() == Drop {
			continue
		}
		set = set.Union(Span(&m.JoinedAt, m.LeftAt))
		if !at.Before(m.JoinedAt) && !left {
			live = true
		}
	}
	if set.IsEmpty() {
		return nil, false, ErrNotCovered
	}
	return set, live, nil
}

// root computes authority for a delegation with no basis: from must be the
// controller of record, proven by an opening, in each era counted.
func (e *Evaluator) root(ctx context.Context, s *Stored, vehicle string, at time.Time) (map[string]Set, map[string]bool, error) {
	rec := &s.Record
	state, err := e.Resolver.ControlState(ctx, vehicle)
	if err != nil {
		return nil, nil, err
	}

	var eras Set
	liveEra := false
	for i := range state.Eras {
		era := &state.Eras[i]
		opening, err := e.Resolver.Opening(ctx, vehicle, era.Number, rec.From)
		if err != nil {
			return nil, nil, err
		}
		if opening == nil || opening.Controller != rec.From || opening.Era != era.Number {
			continue
		}
		if control.Verify(era.Commitment, *opening) != nil {
			continue
		}
		if era.Revoked(s.CommittedAt) {
			continue
		}
		ended := era.End != nil && !era.End.After(at)
		if ended && rec.afterTransfer() == Drop {
			continue
		}
		eraSpan := Span(era.Start, era.End)
		eras = eras.Union(eraSpan)
		if eraSpan.Contains(at) {
			liveEra = true
		}
	}
	if eras.IsEmpty() {
		return nil, nil, fmt.Errorf("%w: %s is not the controller of record", ErrNotCovered, rec.From)
	}

	hist := map[string]Set{}
	live := map[string]bool{}
	for _, a := range rec.Abilities {
		hist[a] = eras
		live[a] = liveEra
	}
	return hist, live, nil
}

// parents computes authority for a delegation with a basis: the union of what
// each valid, narrowed parent grants, plus the chains of those parents.
func (e *Evaluator) parents(ctx context.Context, s *Stored, vehicle, clientID string, at time.Time, depth int, seen map[string]bool) (map[string]Set, map[string]bool, []string, error) {
	rec := &s.Record
	hist := map[string]Set{}
	live := map[string]bool{}
	var chain []string
	var lastErr error = ErrNotCovered

	for _, uri := range rec.Basis {
		p, err := e.Resolver.Record(ctx, uri)
		if err != nil {
			lastErr = err
			continue
		}
		if err := narrows(rec, &p.Record); err != nil {
			lastErr = fmt.Errorf("%s over %s: %w", s.URI, uri, err)
			continue
		}
		pc, err := e.evaluate(ctx, p, vehicle, clientID, at, depth+1, seen)
		if err != nil {
			lastErr = err
			continue
		}
		for a, w := range pc.Historical {
			hist[a] = hist[a].Union(w)
		}
		for _, a := range pc.Live {
			live[a] = true
		}
		chain = append(chain, pc.Chain...)
	}
	if len(hist) == 0 && len(live) == 0 {
		return nil, nil, nil, lastErr
	}

	if rec.afterTransfer() == Drop {
		state, err := e.Resolver.ControlState(ctx, vehicle)
		if err != nil {
			return nil, nil, nil, err
		}
		if cur := state.EraAt(at); cur != nil {
			current := Span(cur.Start, cur.End)
			for a, w := range hist {
				hist[a] = w.Intersect(current)
			}
		}
	}
	return hist, live, chain, nil
}

// narrows checks the static rules a child must satisfy against a parent.
func narrows(child, parent *Record) error {
	if parent.Type != TypeDelegation {
		return errors.New("basis must be a delegation")
	}
	if child.From != parent.To {
		return fmt.Errorf("%w: from %s is not the recipient %s", ErrNotNarrowing, child.From, parent.To)
	}

	switch parent.redelegateMode() {
	case RedelegateNone:
		return fmt.Errorf("%w: basis does not allow redelegation", ErrNotNarrowing)
	case RedelegateAttenuated:
		if child.redelegateMode() != RedelegateNone && parent.Redelegate.MaxDepth < 2 {
			return fmt.Errorf("%w: redelegation depth exhausted", ErrNotNarrowing)
		}
		if child.redelegateMode() == RedelegateAttenuated && child.Redelegate.MaxDepth > parent.Redelegate.MaxDepth-1 {
			return fmt.Errorf("%w: maxDepth exceeds basis", ErrNotNarrowing)
		}
	case RedelegateAllowlist:
		if !slices.Contains(parent.Redelegate.Grantees, child.To) {
			return fmt.Errorf("%w: %s is not on the basis allowlist", ErrNotNarrowing, child.To)
		}
		switch child.redelegateMode() {
		case RedelegateNone:
		case RedelegateAllowlist:
			for _, g := range child.Redelegate.Grantees {
				if !slices.Contains(parent.Redelegate.Grantees, g) {
					return fmt.Errorf("%w: allowlist grantee %s not in basis allowlist", ErrNotNarrowing, g)
				}
			}
		default:
			return fmt.Errorf("%w: allowlist basis permits only none or a narrower allowlist", ErrNotNarrowing)
		}
	}

	for _, a := range child.Abilities {
		if !slices.Contains(parent.Abilities, a) {
			return fmt.Errorf("%w: ability %s not in basis", ErrNotNarrowing, a)
		}
	}
	if !windowWithin(child.DataWindow, parent.DataWindow) {
		return fmt.Errorf("%w: dataWindow exceeds basis", ErrNotNarrowing)
	}
	if !windowWithin(child.Validity, parent.Validity) {
		return fmt.Errorf("%w: validity exceeds basis", ErrNotNarrowing)
	}
	return nil
}

// hasRole reports whether member held, at time at, a role in org covering scope
// with every ability in need.
func (e *Evaluator) hasRole(ctx context.Context, org, member string, scope Covers, need []string, at time.Time) (bool, error) {
	roles, err := e.Resolver.Roles(ctx, org, member)
	if err != nil {
		return false, err
	}
	for i := range roles {
		r := &roles[i]
		if !roleActive(r, org, member, at) {
			continue
		}
		if !roleScopeCovers(r.Record.Covers, scope) {
			continue
		}
		if containsAll(r.Record.Abilities, need) {
			return true, nil
		}
	}
	return false, nil
}

// useRole reports whether member may use delegations addressed to org for
// vehicle with the given abilities.
func (e *Evaluator) useRole(ctx context.Context, org, member, vehicle string, abilities []string, at time.Time) (bool, error) {
	kind, err := e.Resolver.Kind(ctx, org)
	if err != nil || kind != KindOrg {
		return false, err
	}
	roles, err := e.Resolver.Roles(ctx, org, member)
	if err != nil {
		return false, err
	}
	for i := range roles {
		r := &roles[i]
		if !roleActive(r, org, member, at) {
			continue
		}
		c := r.Record.Covers
		if !c.Inherit && c.Vehicle != vehicle {
			continue
		}
		if containsAll(r.Record.Abilities, abilities) {
			return true, nil
		}
	}
	return false, nil
}

func roleActive(r *Stored, org, member string, at time.Time) bool {
	rec := &r.Record
	if rec.Type != TypeRole || rec.From != org || rec.To != member || rec.Validate() != nil {
		return false
	}
	if at.Before(r.CommittedAt) || !rec.Validity.Set().Contains(at) {
		return false
	}
	return !revokedAt(rec, r.Tombstone, at)
}

// roleScopeCovers reports whether a role's scope includes the target scope.
func roleScopeCovers(role, target Covers) bool {
	switch {
	case role.Inherit:
		return true
	case target.Inherit:
		return false
	case role.Tag != "":
		return role.Tag == target.Tag
	default:
		return role.Vehicle != "" && role.Vehicle == target.Vehicle
	}
}

// revokedAt reports whether an authorized tombstone is in effect at time at.
func revokedAt(rec *Record, t *Tombstone, at time.Time) bool {
	if t == nil || at.Before(t.At) {
		return false
	}
	switch rec.revocableBy() {
	case RevocableByTo:
		return t.By == rec.To
	case RevocableByEither:
		return t.By == rec.From || t.By == rec.To
	default:
		return t.By == rec.From
	}
}

func containsAll(have, need []string) bool {
	for _, n := range need {
		if !slices.Contains(have, n) {
			return false
		}
	}
	return true
}
