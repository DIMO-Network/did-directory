package delegation

import (
	"context"
	"errors"
	"fmt"
	"maps"
	"slices"
	"strings"
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
	ErrLienNotAllowed   = errors.New("only an attested operator may issue a delegation revocable only by its recipient")
	ErrSelfDealing      = errors.New("the author of a grant cannot be its recipient without a second approval")
	ErrExclusiveHold    = errors.New("another party holds these abilities exclusively")
	ErrExceedsRole      = errors.New("the grant exceeds the constraints of the role that authored it")
)

// ExclusiveHoldError is ErrExclusiveHold together with the abilities that are
// suspended, so an issuer can tell the caller which ones somebody else holds
// rather than parse them back out of the message. It matches ErrExclusiveHold
// under errors.Is.
type ExclusiveHoldError struct {
	Suspended []string
}

func (e *ExclusiveHoldError) Error() string {
	return ErrExclusiveHold.Error() + ": " + strings.Join(e.Suspended, ", ")
}

func (e *ExclusiveHoldError) Unwrap() error { return ErrExclusiveHold }

// Kind is the kind of principal behind a DID.
type Kind int

const (
	KindUnknown Kind = iota
	KindPerson
	KindOrg
)

// Party describes a principal for policy purposes.
//
// Entity type is a poor proxy for how someone is acting: a sole proprietor with
// six cars on a peer-to-peer platform is an operator, and a large company
// renting one car is a consumer in that transaction. People are routinely both,
// in different agreements, at the same time. Policy therefore keys off attested
// status, not off the shape of the DID.
type Party struct {
	Kind Kind
	// Operator reports attested commercial-operator status: may hold staff roles
	// and issue liens, and is governed by operator policy rather than consumer
	// protection.
	Operator bool
}

// CanHaveMembers reports whether principals may act as members of this party.
func (p Party) CanHaveMembers() bool { return p.Kind == KindOrg || p.Operator }

// ExclusiveHold is an active exclusive claim over a vehicle's live abilities.
type ExclusiveHold struct {
	URI       string
	Holder    string
	Abilities []string
	// Since is when the hold took effect: the claiming record's validity start,
	// or its commit time when the validity is open at the front. Two live holds
	// over the same ability is an issuing mistake the evaluator cannot referee,
	// and the newer one is the one in force — a returned booking whose device
	// never synced must not lock the next renter out of the car they are standing
	// next to (§12.5). A resolver that leaves it zero gets the tie rule below.
	Since time.Time
}

// Stored is a committed record plus repository metadata.
type Stored struct {
	URI         string
	Record      Record
	CommittedAt time.Time
	// CommittedBy is the principal the repository authenticated for this write,
	// which is the only trustworthy answer to "who authored this". Record.CreatedBy
	// sits inside the signed bytes, so a member who wants to escape the role that
	// bounds them need only leave it out; authority therefore comes from here and
	// CreatedBy stays the audit copy it claims to be.
	//
	// Empty means the repository recorded no separate author, which is honest only
	// for a record the issuing principal wrote itself. It is read that way, and a
	// record whose CreatedBy contradicts it — claiming an author the repository
	// never witnessed — is refused rather than believed. Hosts must populate it;
	// this is the fail-closed reading of a field that gates authority.
	CommittedBy string
	Tombstone   *Tombstone
	// ApprovedBy lists principals who approved this write, beyond its author.
	// Required for self-issued grants and for anything the policy gates.
	ApprovedBy []string
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

// CustodyPeriod is one period during which a holder physically had a vehicle:
// pickup to return, with a nil Until while the car is still out.
//
// It is written by the booking service at pickup and return, or signed by the
// car's own device and synced later. Grants never wait on it (§12.3): the renter
// opens the car by unlocking it, so requiring a custody record before access
// would leave someone standing next to a locked car in a garage with no signal.
// Custody narrows the data window afterwards instead.
type CustodyPeriod struct {
	Vehicle string     `json:"vehicle"`
	Holder  string     `json:"holder"`
	From    time.Time  `json:"from"`
	Until   *time.Time `json:"until,omitempty"`
}

// Resolver supplies repository and directory data to the evaluator.
type Resolver interface {
	// Record returns a delegation or role record by URI.
	Record(ctx context.Context, uri string) (*Stored, error)
	// Memberships returns every membership interval of vehicle in tag.
	Memberships(ctx context.Context, tag, vehicle string) ([]Membership, error)
	// TagSize returns how many vehicles the tag holds at time at.
	TagSize(ctx context.Context, tag string, at time.Time) (int, error)
	// Custody returns every period in which holder had the vehicle, oldest first.
	Custody(ctx context.Context, vehicle, holder string) ([]CustodyPeriod, error)
	// Roles returns role records issued by org to member, including tombstoned ones.
	Roles(ctx context.Context, org, member string) ([]Stored, error)
	// ControlState returns the vehicle's control eras from the DID directory.
	ControlState(ctx context.Context, vehicle string) (*control.State, error)
	// Opening returns controller's opening for the vehicle's era, or nil if the
	// controller holds none.
	Opening(ctx context.Context, vehicle string, era uint64, controller string) (*control.Opening, error)
	// Party returns the policy attributes of a DID.
	Party(ctx context.Context, did string) (Party, error)
	// Exclusives returns exclusive holds active over the vehicle at time at.
	Exclusives(ctx context.Context, vehicle string, at time.Time) ([]ExclusiveHold, error)
}

// Coverage is what a delegation grants over one vehicle at a point in time.
type Coverage struct {
	Vehicle string `json:"vehicle"`
	// Historical maps each historical ability to the data-timestamp windows it may read.
	Historical map[string]Set `json:"historical,omitempty"`
	// Live lists live and admin abilities usable at the evaluation time.
	Live []string `json:"live,omitempty"`
	// Suspended lists live abilities this record holds but cannot exercise now,
	// because another party holds them exclusively (custody).
	Suspended []string `json:"suspended,omitempty"`
	// RecoveryUsed reports that a recovery record overrode an exclusive hold.
	// The issuer logs this.
	RecoveryUsed bool `json:"recoveryUsed,omitempty"`
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
	// MaxDepth bounds chain length; zero means the policy's depth.
	MaxDepth int
	// Policy holds the thresholds and rules in force; zero means DefaultPolicy.
	Policy Policy
}

func (e *Evaluator) policy() Policy { return e.Policy.orDefault() }

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
		// A suspended grant answers "somebody else is driving" only to a caller
		// asking for something this grant actually carries. Asking for an ability
		// it never had is simply not covered.
		if errors.Is(err, ErrExclusiveHold) && !slices.ContainsFunc(abilities, func(a string) bool {
			return slices.Contains(s.Record.Abilities, a)
		}) {
			return nil, ErrNotCovered
		}
		return nil, err
	}

	// The filtered coverage narrows what was granted to what was asked for; it
	// does not drop the audit facts attached to the answer. RecoveryUsed in
	// particular is the record of the one operation that overrides a renter's
	// custody, and Authorize is the path an issuer actually calls.
	filtered := &Coverage{
		Vehicle: vehicle, Historical: map[string]Set{},
		RecoveryUsed: cov.RecoveryUsed, Chain: cov.Chain,
	}
	for _, a := range abilities {
		if w, ok := cov.Historical[a]; ok && !w.IsEmpty() {
			filtered.Historical[a] = w
		}
		if slices.Contains(cov.Live, a) {
			filtered.Live = append(filtered.Live, a)
		}
		if slices.Contains(cov.Suspended, a) {
			filtered.Suspended = append(filtered.Suspended, a)
		}
	}
	if filtered.Empty() {
		if len(filtered.Suspended) > 0 {
			return nil, &ExclusiveHoldError{Suspended: filtered.Suspended}
		}
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
	return e.policy().MaxChainDepth
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

	from, err := e.Resolver.Party(ctx, rec.From)
	if err != nil {
		return nil, err
	}
	if rec.revocableBy() == RevocableByTo && !from.Operator && !e.policy().AllowIrrevocableFromNonOperator {
		return nil, ErrLienNotAllowed
	}

	author, err := committedBy(s)
	if err != nil {
		return nil, err
	}
	// A member authoring on behalf of someone else needs delegation:create over
	// the scope, and may not write a grant to themselves without a second
	// approval — staff are customers too.
	if author != rec.From {
		if !from.CanHaveMembers() {
			return nil, fmt.Errorf("%s authored by %s, but %s cannot have members", s.URI, author, rec.From)
		}
		need := append([]string{"delegation:create"}, rec.Abilities...)
		ok, err := e.hasRole(ctx, rec.From, author, rec.Covers, need, s.CommittedAt, e.shapeCheck(ctx, s, at))
		if err != nil {
			return nil, fmt.Errorf("%s: %w", s.URI, err)
		}
		if !ok {
			return nil, fmt.Errorf("%s: author %s lacked authority when committed", s.URI, author)
		}
		if author == rec.To {
			ok, err := e.approvedByAnother(ctx, s, author, need)
			if err != nil {
				return nil, err
			}
			if !ok {
				return nil, fmt.Errorf("%w: %s", ErrSelfDealing, s.URI)
			}
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
	if rec.NarrowToCustody {
		held, err := e.custody(ctx, vehicle, rec.To)
		if err != nil {
			return nil, err
		}
		base = base.Intersect(held)
	}
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

	// Exclusivity applies to the record being authorized, not to links inside its
	// own chain: a custody hold must not suspend the grant it derives from.
	if depth == 1 && len(cov.Live) > 0 {
		if err := e.applyExclusives(ctx, s, vehicle, at, cov); err != nil {
			return nil, err
		}
	}

	if cov.Empty() {
		// Suspended is not the same answer as never granted: §12.2 wants the
		// operator to see that somebody is driving their car, and the issuer to
		// log it. Saying "not covered" here would hide a custody hold behind the
		// same error as a missing grant.
		if len(cov.Suspended) > 0 {
			return nil, &ExclusiveHoldError{Suspended: cov.Suspended}
		}
		return nil, ErrNotCovered
	}
	return cov, nil
}

// committedBy returns the principal whose authority this record was written
// under: what the repository witnessed, never what the record says about itself.
//
// Record.CreatedBy is inside the signed bytes, so gating the role, shape and
// self-dealing checks on it lets an author escape every one of them by leaving
// it out. It survives as the audit copy §5 describes it as, and the only thing
// it is consulted for here is honesty: a record claiming an author the
// repository never witnessed is refused, because believing it would hand
// authorship back to whoever wrote the record.
func committedBy(s *Stored) (string, error) {
	rec := &s.Record
	if s.CommittedBy == "" {
		if rec.CreatedBy != "" && rec.CreatedBy != rec.From {
			return "", fmt.Errorf("%s: createdBy claims %s but the repository witnessed no author", s.URI, rec.CreatedBy)
		}
		return rec.From, nil
	}
	if rec.CreatedBy != "" && rec.CreatedBy != s.CommittedBy {
		return "", fmt.Errorf("%s: createdBy says %s but the repository witnessed %s", s.URI, rec.CreatedBy, s.CommittedBy)
	}
	return s.CommittedBy, nil
}

// applyExclusives removes live abilities another party holds exclusively over
// this vehicle. A recovery record keeps them and is flagged instead.
func (e *Evaluator) applyExclusives(ctx context.Context, s *Stored, vehicle string, at time.Time, cov *Coverage) error {
	rec := &s.Record
	holds, err := e.Resolver.Exclusives(ctx, vehicle, at)
	if err != nil {
		return err
	}
	own := holdStart(s)

	blocked := map[string]bool{}
	for _, h := range holds {
		// A hold never blocks its own holder, nor anything derived from it: the
		// renter's booking inherits the platform's hold rather than fighting it.
		if h.Holder == rec.To || slices.Contains(cov.Chain, h.URI) {
			continue
		}
		for _, a := range h.Abilities {
			// Where this record claims the same ability exclusively, only a strictly
			// newer hold supersedes it. Suspending both sides of an overlap would
			// lock two parties out of a car one of them is driving, which is the
			// lockout §12.5 exists to prevent, and the operator — the party
			// exclusivity is actually aimed at — is still blocked by both.
			if slices.Contains(rec.Exclusive, a) && !h.Since.After(own) {
				continue
			}
			blocked[a] = true
		}
	}
	if len(blocked) == 0 {
		return nil
	}

	var live []string
	for _, a := range cov.Live {
		if !blocked[a] {
			live = append(live, a)
			continue
		}
		if rec.Recovery {
			live = append(live, a)
			cov.RecoveryUsed = true
			continue
		}
		cov.Suspended = append(cov.Suspended, a)
	}
	cov.Live = live
	return nil
}

// holdStart is when this record's own exclusive claim took effect, on the same
// footing a resolver reports ExclusiveHold.Since: the validity start, or the
// commit when the validity is open at the front.
func holdStart(s *Stored) time.Time {
	if s.Record.Validity.From != nil {
		return *s.Record.Validity.From
	}
	return s.CommittedAt
}

// custody returns the times the holder actually had the vehicle. An open period
// has no end, because the car is still out and the window follows the holder
// forward; closing it at return is what narrows the grant. A holder who never
// picked the car up has no periods, so the record covers no data at all.
func (e *Evaluator) custody(ctx context.Context, vehicle, holder string) (Set, error) {
	periods, err := e.Resolver.Custody(ctx, vehicle, holder)
	if err != nil {
		return nil, err
	}
	var set Set
	for _, p := range periods {
		set = set.Union(Span(&p.From, p.Until))
	}
	return set, nil
}

// shapeCheck returns a check of this record's shape against a role's issue
// constraints, for hasRole to apply to each candidate role. Counting the covered
// vehicles costs a resolver call, so it is taken only once and only when a
// constrained role is actually in play.
func (e *Evaluator) shapeCheck(ctx context.Context, s *Stored, at time.Time) func(*RoleConstraints) error {
	count, counted := 0, false
	return func(c *RoleConstraints) error {
		if c == nil {
			return nil
		}
		if !counted {
			n, err := e.coveredVehicles(ctx, &s.Record, at, 1)
			if err != nil {
				return err
			}
			count, counted = n, true
		}
		return c.check(&s.Record, count)
	}
}

// coveredVehicles counts the vehicles a record applies to, following
// covers.inherit up the basis chain to the selector that actually chooses them.
// Inheriting from several bases is bounded below by the largest of them, which
// is the best a count can do over a union of tags.
func (e *Evaluator) coveredVehicles(ctx context.Context, rec *Record, at time.Time, depth int) (int, error) {
	switch {
	case rec.Covers.Vehicle != "":
		return 1, nil
	case rec.Covers.Tag != "":
		return e.Resolver.TagSize(ctx, rec.Covers.Tag, at)
	case depth >= e.maxDepth():
		return 0, ErrChainTooDeep
	}

	most := 0
	for _, uri := range rec.Basis {
		p, err := e.Resolver.Record(ctx, uri)
		if err != nil {
			return 0, err
		}
		n, err := e.coveredVehicles(ctx, &p.Record, at, depth+1)
		if err != nil {
			return 0, err
		}
		most = max(most, n)
	}
	return most, nil
}

// approvedByAnother reports whether someone other than the author approved this
// write and held the same authority at commit time.
func (e *Evaluator) approvedByAnother(ctx context.Context, s *Stored, author string, need []string) (bool, error) {
	rec := &s.Record
	for _, approver := range s.ApprovedBy {
		if approver == author || approver == rec.To {
			continue
		}
		if approver == rec.From {
			return true, nil
		}
		ok, err := e.hasRole(ctx, rec.From, approver, rec.Covers, need, s.CommittedAt, nil)
		if err != nil {
			return false, err
		}
		if ok {
			return true, nil
		}
	}
	return false, nil
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
			ok, err := e.hasRole(ctx, org, m.CreatedBy, Covers{Tag: rec.Covers.Tag}, need, m.CommittedAt, nil)
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
		// drop keeps only the era in force. With no era in force — the car left
		// DIMO, or sits between eras — there is nothing to keep, and quietly
		// retaining the whole history is the opposite of what the record asked
		// for. Live abilities are unaffected: the parent already ended them.
		var current Set
		if cur := state.EraAt(at); cur != nil {
			current = Span(cur.Start, cur.End)
		}
		for a, w := range hist {
			hist[a] = w.Intersect(current)
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

	// The depth budget is checked the same way whatever mode spends it. An
	// allowlist bounds who, not how many, so one that names no depth is unbounded
	// and cannot narrow a basis that paid for a fixed number of hops: without
	// this, "attenuated, maxDepth 2" becomes an unbounded chain the moment a
	// child switches modes.
	if budget, bounded := depthBudget(parent); bounded && child.redelegateMode() != RedelegateNone {
		if budget < 2 {
			return fmt.Errorf("%w: redelegation depth exhausted", ErrNotNarrowing)
		}
		if cb, ok := depthBudget(child); !ok || cb > budget-1 {
			return fmt.Errorf("%w: maxDepth exceeds basis", ErrNotNarrowing)
		}
	}

	for _, a := range child.Abilities {
		if !slices.Contains(parent.Abilities, a) {
			return fmt.Errorf("%w: ability %s not in basis", ErrNotNarrowing, a)
		}
	}
	for _, a := range child.Exclusive {
		if !parent.Redelegate.Exclusive && !slices.Contains(parent.Exclusive, a) {
			return fmt.Errorf("%w: basis does not permit an exclusive claim over %s", ErrNotNarrowing, a)
		}
	}
	// Recovery is exclusivity's override: it acts through somebody else's hold,
	// so it cannot be cheaper to claim than the hold itself. A basis that never
	// permitted an exclusive claim must not be redelegable into a record that
	// beats one.
	if child.Recovery && !parent.Redelegate.Exclusive && !parent.Recovery {
		return fmt.Errorf("%w: basis does not permit recovery", ErrNotNarrowing)
	}
	if !windowWithin(child.DataWindow, parent.DataWindow) {
		return fmt.Errorf("%w: dataWindow exceeds basis", ErrNotNarrowing)
	}
	if !windowWithin(child.Validity, parent.Validity) {
		return fmt.Errorf("%w: validity exceeds basis", ErrNotNarrowing)
	}
	return nil
}

// depthBudget returns how many further hops a record pays for, and whether it
// bounds them at all. An allowlist carries a budget only when it names one,
// because naming who may receive says nothing about how many times.
func depthBudget(r *Record) (int, bool) {
	switch r.redelegateMode() {
	case RedelegateAttenuated:
		return r.Redelegate.MaxDepth, true
	case RedelegateAllowlist:
		if r.Redelegate.MaxDepth > 0 {
			return r.Redelegate.MaxDepth, true
		}
	}
	return 0, false
}

// hasRole reports whether member held, at time at, a role in org covering scope
// with every ability in need.
//
// shape, when non-nil, additionally checks the shape of what is being authored
// against each candidate role's issue constraints, so a constrained role cannot
// authorize a grant wider than it permits. A member holding several roles is
// authorized if any one of them allows both the abilities and the shape; when
// none does, the shape rejection is returned rather than swallowed, because
// "you may not issue this" and "you may not issue anything" are different
// answers to the writer.
func (e *Evaluator) hasRole(ctx context.Context, org, member string, scope Covers, need []string, at time.Time, shape func(*RoleConstraints) error) (bool, error) {
	roles, err := e.Resolver.Roles(ctx, org, member)
	if err != nil {
		return false, err
	}
	var shapeErr error
	for i := range roles {
		r := &roles[i]
		if !roleActive(r, org, member, at) {
			continue
		}
		ok, err := e.roleScopeCovers(ctx, r.Record.Covers, scope, at)
		if err != nil {
			return false, err
		}
		if !ok {
			continue
		}
		if !containsAll(r.Record.Abilities, need) {
			continue
		}
		if shape != nil {
			if err := shape(r.Record.Constraints); err != nil {
				shapeErr = err
				continue
			}
		}
		return true, nil
	}
	return false, shapeErr
}

// useRole reports whether member may use delegations addressed to org for
// vehicle with the given abilities.
func (e *Evaluator) useRole(ctx context.Context, org, member, vehicle string, abilities []string, at time.Time) (bool, error) {
	party, err := e.Resolver.Party(ctx, org)
	if err != nil || !party.CanHaveMembers() {
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
		// Scope is resolved the same way hasRole resolves it, or a tag-scoped
		// role could author a grant over a car (see roleScopeCovers) and then be
		// unable to exercise one addressed to its own org.
		ok, err := e.roleScopeCovers(ctx, r.Record.Covers, Covers{Vehicle: vehicle}, at)
		if err != nil {
			return false, err
		}
		if !ok {
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

// roleScopeCovers reports whether a role's scope includes the target scope at
// time at.
//
// A tag-scoped role covers a single vehicle that was in its tag at that time.
// Without this, a booking service scoped to the Florida fleet could not author
// the per-car custody grant a rental needs (§12.1) — the scope check would fail
// before constraints were consulted, and the only workable role would be an
// org-wide one. Membership is read raw here: whether the author of a membership
// held authority is a question for coverage, not for scope, and asking it here
// would recurse.
func (e *Evaluator) roleScopeCovers(ctx context.Context, role, target Covers, at time.Time) (bool, error) {
	switch {
	case role.Inherit:
		return true, nil
	case target.Inherit:
		return false, nil
	case role.Tag != "":
		if role.Tag == target.Tag {
			return true, nil
		}
		if target.Vehicle == "" {
			return false, nil
		}
		memberships, err := e.Resolver.Memberships(ctx, role.Tag, target.Vehicle)
		if err != nil {
			return false, err
		}
		for _, m := range memberships {
			if !at.Before(m.JoinedAt) && (m.LeftAt == nil || at.Before(*m.LeftAt)) {
				return true, nil
			}
		}
		return false, nil
	default:
		return role.Vehicle != "" && role.Vehicle == target.Vehicle, nil
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
