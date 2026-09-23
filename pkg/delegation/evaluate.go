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
	// ErrInvalidRecord is a record that does not hold up on its own terms: it
	// is malformed, is not a delegation, or was authored by somebody who could
	// not have written it.
	ErrInvalidRecord = errors.New("invalid record")
)

// refusals are the errors that mean an evaluation said no, as opposed to the
// resolver failing to answer.
var refusals = []error{
	ErrNotCovered, ErrRevoked, ErrNotValid, ErrNotNarrowing, ErrUnauthorized,
	ErrClientNotAllowed, ErrChainTooDeep, ErrLienNotAllowed, ErrSelfDealing,
	ErrExclusiveHold, ErrExceedsRole, ErrInvalidRecord,
}

// isRefusal reports whether err is an evaluation's answer rather than a
// failure to reach one.
func isRefusal(err error) bool {
	return slices.ContainsFunc(refusals, func(r error) bool { return errors.Is(err, r) })
}

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
	// Superseded is when a later version of the same record replaced this one.
	// Resolver.Roles returns every version of a role, so that a grant's author
	// is judged by the role as it stood when the grant was committed; a nil
	// Superseded is the current version.
	Superseded *time.Time
}

// Tombstone marks a revoked record. By is the principal whose repository write
// revoked it; tombstones by a principal not allowed by revocableBy are ignored.
type Tombstone struct {
	At time.Time
	By string
}

// Membership is one interval of a vehicle in a tag, as one version of its
// record states it.
type Membership struct {
	// URI is the membership record. A resolver may return several versions of
	// one record; the latest whose author could have written it is the one
	// that counts.
	URI         string
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
	// Memberships returns every membership interval of vehicle in tag: each
	// version of each live membership record since it was last created.
	Memberships(ctx context.Context, tag, vehicle string) ([]Membership, error)
	// TagSize returns how many vehicles the tag holds at time at.
	TagSize(ctx context.Context, tag string, at time.Time) (int, error)
	// Custody returns every period in which holder had the vehicle, as recorded
	// in org's repository, oldest first. Only the issuer of a grant can narrow it
	// by custody, so custody recorded anywhere else is not asked for.
	Custody(ctx context.Context, org, vehicle, holder string) ([]CustodyPeriod, error)
	// Roles returns role records issued by org to member, including tombstoned
	// ones, one Stored per version with Superseded set on all but the current.
	Roles(ctx context.Context, org, member string) ([]Stored, error)
	// ControlState returns the vehicle's control eras from the DID directory.
	ControlState(ctx context.Context, vehicle string) (*control.State, error)
	// Opening returns controller's opening for the vehicle's era, from any
	// version of its record, or nil if the controller holds none. An opening is
	// checked against the era's commitment, so an old version proves its era
	// as well as it ever did.
	Opening(ctx context.Context, vehicle string, era uint64, controller string) (*control.Opening, error)
	// Party returns the policy attributes of a DID.
	Party(ctx context.Context, did string) (Party, error)
	// Exclusives returns the exclusive holds claimed over the vehicle at time at.
	// They are claims: the evaluator checks each one's own chain before it
	// suspends anybody.
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
		return nil, fmt.Errorf("%w: %s is not a delegation", ErrInvalidRecord, uri)
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

	cov, err := e.evaluateTop(ctx, s, vehicle, clientID, at)
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
	return e.evaluateTop(ctx, s, vehicle, anyClient, at)
}

// evaluateTop evaluates the record being authorized and then applies the
// exclusive holds over the vehicle. Exclusivity applies to that record only, not
// to links inside its own chain: a custody hold must not suspend the grant it
// derives from.
func (e *Evaluator) evaluateTop(ctx context.Context, s *Stored, vehicle, clientID string, at time.Time) (*Coverage, error) {
	cov, err := e.evaluate(ctx, s, vehicle, clientID, at, 1, map[string]bool{})
	if err != nil {
		return nil, err
	}
	if len(cov.Live) == 0 {
		return cov, nil
	}
	if err := e.applyExclusives(ctx, s, vehicle, at, cov); err != nil {
		return nil, err
	}
	if cov.Empty() {
		// Suspended is not the same answer as never granted: §12.2 wants the
		// operator to see that somebody is driving their car, and the issuer to
		// log it. Saying "not covered" here would hide a custody hold behind the
		// same error as a missing grant.
		return nil, &ExclusiveHoldError{Suspended: cov.Suspended}
	}
	return cov, nil
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
		return nil, fmt.Errorf("%w: delegation cycle at %s", ErrInvalidRecord, s.URI)
	}
	seen[s.URI] = true
	defer delete(seen, s.URI)

	if rec.Type != TypeDelegation {
		return nil, fmt.Errorf("%w: %s is not a delegation", ErrInvalidRecord, s.URI)
	}
	if err := rec.Validate(); err != nil {
		return nil, fmt.Errorf("%w: %s: %w", ErrInvalidRecord, s.URI, err)
	}
	revoked, err := e.revokedAt(ctx, rec, s.Tombstone, at, walk{depth: depth})
	if err != nil {
		return nil, err
	}
	if revoked {
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
			return nil, fmt.Errorf("%w: %s authored by %s, but %s cannot have members", ErrInvalidRecord, s.URI, author, rec.From)
		}
		need := AuthoringNeed(rec)
		ok, err := e.hasRole(ctx, rec.From, author, rec.Covers, need, s.CommittedAt, e.shapeCheck(ctx, s, at), walk{depth: depth})
		if err != nil {
			return nil, fmt.Errorf("%s: %w", s.URI, err)
		}
		if !ok {
			return nil, fmt.Errorf("%w: %s: author %s lacked authority when committed", ErrInvalidRecord, s.URI, author)
		}
		if author == rec.To {
			ok, err := e.approvedByAnother(ctx, s, author, walk{depth: depth})
			if err != nil {
				return nil, err
			}
			if !ok {
				return nil, fmt.Errorf("%w: %s", ErrSelfDealing, s.URI)
			}
		}
	}

	member, liveMember, err := e.membership(ctx, rec, vehicle, at, depth)
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
		held, err := e.custody(ctx, rec.From, vehicle, rec.To)
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
	if cov.Empty() {
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
			return "", fmt.Errorf("%w: %s: createdBy claims %s but the repository witnessed no author", ErrInvalidRecord, s.URI, rec.CreatedBy)
		}
		return rec.From, nil
	}
	if rec.CreatedBy != "" && rec.CreatedBy != s.CommittedBy {
		return "", fmt.Errorf("%w: %s: createdBy says %s but the repository witnessed %s", ErrInvalidRecord, s.URI, rec.CreatedBy, s.CommittedBy)
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
		held, err := e.heldExclusively(ctx, h, vehicle, at)
		if err != nil {
			return err
		}
		for _, a := range held {
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

// heldExclusively returns the abilities hold actually suspends: those its record
// claims exclusively and can itself exercise over the vehicle at time at. A
// claim is only a claim; anybody can write one into their own repository, so a
// hold whose chain does not reach a controller suspends nothing. Holds are not
// applied to the hold's own evaluation, which is what keeps this from
// recursing, and a hold that evaluates to a refusal is ignored while a resolver
// failure is returned: when the host cannot tell, the car's driver stays
// protected.
func (e *Evaluator) heldExclusively(ctx context.Context, h ExclusiveHold, vehicle string, at time.Time) ([]string, error) {
	hs, err := e.Resolver.Record(ctx, h.URI)
	if err != nil {
		return nil, err
	}
	hc, err := e.evaluate(ctx, hs, vehicle, anyClient, at, 1, map[string]bool{})
	if isRefusal(err) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var held []string
	for _, a := range h.Abilities {
		if slices.Contains(hs.Record.Exclusive, a) && slices.Contains(hc.Live, a) {
			held = append(held, a)
		}
	}
	return held, nil
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
func (e *Evaluator) custody(ctx context.Context, org, vehicle, holder string) (Set, error) {
	periods, err := e.Resolver.Custody(ctx, org, vehicle, holder)
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

// CoveredVehicles counts the vehicles rec applies to at time at: one for a
// vehicle, the tag's size for a tag, and for covers.inherit the largest of its
// bases. It is the count CommitContext.CoveredVehicles wants.
func (e *Evaluator) CoveredVehicles(ctx context.Context, rec *Record, at time.Time) (int, error) {
	return e.coveredVehicles(ctx, rec, at, 1)
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

// approvedByAnother reports whether someone other than the author and the
// recipient approved this write: the issuer itself, or a member who held, at
// commit time, the ability that manages records of this kind over its scope.
// The approver need not hold what the record hands out; the author already
// does, or is the issuer. Asking more would make an org's first writes
// impossible to approve, since before the first role nobody holds anything.
func (e *Evaluator) approvedByAnother(ctx context.Context, s *Stored, author string, w walk) (bool, error) {
	rec := &s.Record
	for _, approver := range s.ApprovedBy {
		if approver == author || approver == rec.To {
			continue
		}
		if approver == rec.From {
			return true, nil
		}
		ok, err := e.hasRole(ctx, rec.From, approver, rec.Covers, []string{ManageAbility(rec)}, s.CommittedAt, nil, w)
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
func (e *Evaluator) membership(ctx context.Context, rec *Record, vehicle string, at time.Time, depth int) (Set, bool, error) {
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

	// Each record's interval is its latest version whose author could have
	// written it: tag edits widen every delegation over the tag, so they count
	// only when the author could have granted these abilities at commit time
	// (§9.2). An edit that does not count leaves the version before it standing,
	// rather than dropping the vehicle from the tag.
	byRecord := map[string][]Membership{}
	var order []string
	for i, m := range memberships {
		key := m.URI
		if key == "" {
			key = fmt.Sprintf("#%d", i)
		}
		if _, ok := byRecord[key]; !ok {
			order = append(order, key)
		}
		byRecord[key] = append(byRecord[key], m)
	}
	need := MembershipNeed(rec)
	var set Set
	live := false
	for _, key := range order {
		versions := byRecord[key]
		slices.SortStableFunc(versions, func(a, b Membership) int { return b.CommittedAt.Compare(a.CommittedAt) })
		var m *Membership
		for i := range versions {
			v := &versions[i]
			if v.CreatedBy != "" && v.CreatedBy != org {
				ok, err := e.hasRole(ctx, org, v.CreatedBy, Covers{Tag: rec.Covers.Tag}, need, v.CommittedAt, nil, walk{depth: depth})
				if err != nil {
					return nil, false, err
				}
				if !ok {
					continue
				}
			}
			m = v
			break
		}
		if m == nil {
			continue
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
		return fmt.Errorf("%w: basis must be a delegation", ErrInvalidRecord)
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
	// Permission to claim exclusivity passes down only from a basis that has it.
	// Without this a partner could switch it on for its own children, and a
	// grandchild's hold would suspend the controller's commands.
	if child.Redelegate.Exclusive && !parent.Redelegate.Exclusive {
		return fmt.Errorf("%w: basis does not permit exclusive redelegation", ErrNotNarrowing)
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

// HeldRoles returns the roles member holds in org at time at: issued to them,
// committed before at, inside their validity and not revoked. It is what an org
// host reads to decide whether a caller is a member at all.
func (e *Evaluator) HeldRoles(ctx context.Context, org, member string, at time.Time) ([]Stored, error) {
	roles, err := e.Resolver.Roles(ctx, org, member)
	if err != nil {
		return nil, err
	}
	var out []Stored
	for i := range roles {
		active, err := e.roleActive(ctx, &roles[i], org, member, at, walk{})
		if err != nil {
			return nil, err
		}
		if active {
			out = append(out, roles[i])
		}
	}
	return out, nil
}

// RolesCovering returns the roles member holds in org at time at that cover
// scope and carry every ability in need. It is the check an org host runs
// before committing a member's write (plan §3.2); the evaluator runs the same
// one when the record is later exercised, so what the host accepts is what
// evaluation will honour. Each returned role's constraints still bound the
// shape of what may be written under it: CheckCommit takes one at a time.
func (e *Evaluator) RolesCovering(ctx context.Context, org, member string, scope Covers, need []string, at time.Time) ([]Stored, error) {
	return e.rolesCovering(ctx, org, member, scope, need, at, walk{})
}

// walk bounds the recursion through roles and tombstones: how deep it has
// gone, so a knot of them is an error rather than a hang, and which roles are
// being checked on the way here, so a role cannot vouch for its own author.
type walk struct {
	depth int
	seen  []string
}

func (w walk) deeper() walk { return walk{depth: w.depth + 1, seen: w.seen} }

func (w walk) into(uri string) walk {
	return walk{depth: w.depth + 1, seen: append(slices.Clone(w.seen), uri)}
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
func (e *Evaluator) hasRole(ctx context.Context, org, member string, scope Covers, need []string, at time.Time, shape func(*RoleConstraints) error, w walk) (bool, error) {
	roles, err := e.rolesCovering(ctx, org, member, scope, need, at, w)
	if err != nil {
		return false, err
	}
	var shapeErr error
	for i := range roles {
		if shape != nil {
			if err := shape(roles[i].Record.Constraints); err != nil {
				shapeErr = err
				continue
			}
		}
		return true, nil
	}
	return false, shapeErr
}

func (e *Evaluator) rolesCovering(ctx context.Context, org, member string, scope Covers, need []string, at time.Time, w walk) ([]Stored, error) {
	roles, err := e.Resolver.Roles(ctx, org, member)
	if err != nil {
		return nil, err
	}
	var out []Stored
	for i := range roles {
		r := &roles[i]
		active, err := e.roleActive(ctx, r, org, member, at, w)
		if err != nil {
			return nil, err
		}
		if !active {
			continue
		}
		ok, err := e.roleScopeCovers(ctx, r.Record.Covers, scope, at)
		if err != nil {
			return nil, err
		}
		if !ok || !containsAll(r.Record.Abilities, need) {
			continue
		}
		out = append(out, *r)
	}
	return out, nil
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
		active, err := e.roleActive(ctx, r, org, member, at, walk{})
		if err != nil {
			return false, err
		}
		if !active {
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

// roleActive reports whether the role r, issued by org to member, is in force
// at time at.
//
// A role a member wrote is held to the same standard as a delegation a member
// wrote: the author must have held, when it was committed, org:members and
// every ability the role hands out over its scope, and a member may not write
// themselves a role without a second approval. An org host checks this before
// committing, but the evaluator is where it cannot be bypassed (spec §7). The
// org's own writes are trusted, since the org is the authority every role
// derives from.
//
// A role's author held their authority through other roles, and so on; the
// walk bounds that as chain depth is bounded, and a role already being checked
// cannot vouch for its own author, which is what a self-written role would
// otherwise do.
func (e *Evaluator) roleActive(ctx context.Context, r *Stored, org, member string, at time.Time, w walk) (bool, error) {
	rec := &r.Record
	if rec.Type != TypeRole || rec.From != org || rec.To != member || rec.Validate() != nil {
		return false, nil
	}
	if slices.Contains(w.seen, r.URI) {
		return false, nil
	}
	if at.Before(r.CommittedAt) || (r.Superseded != nil && !at.Before(*r.Superseded)) || !rec.Validity.Set().Contains(at) {
		return false, nil
	}
	revoked, err := e.revokedAt(ctx, rec, r.Tombstone, at, w.into(r.URI))
	if err != nil || revoked {
		return false, err
	}
	author, err := committedBy(r)
	if err != nil {
		return false, err
	}
	if author == org {
		return true, nil
	}
	if w.depth >= e.maxDepth() {
		return false, fmt.Errorf("%w: role authority at %s", ErrChainTooDeep, r.URI)
	}
	need := AuthoringNeed(rec)
	ok, err := e.hasRole(ctx, org, author, rec.Covers, need, r.CommittedAt, nil, w.into(r.URI))
	if err != nil || !ok {
		return false, err
	}
	if author == rec.To {
		return e.approvedByAnother(ctx, r, author, w.into(r.URI))
	}
	return true, nil
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
		for _, m := range latestVersions(memberships) {
			if !at.Before(m.JoinedAt) && (m.LeftAt == nil || at.Before(*m.LeftAt)) {
				return true, nil
			}
		}
		return false, nil
	default:
		return role.Vehicle != "" && role.Vehicle == target.Vehicle, nil
	}
}

// latestVersions keeps the current version of each membership record: what
// the tag says now, before anybody's authority is asked about.
func latestVersions(ms []Membership) []Membership {
	latest := map[string]int{}
	var out []Membership
	for i, m := range ms {
		if m.URI == "" {
			out = append(out, m)
			continue
		}
		j, ok := latest[m.URI]
		if !ok {
			latest[m.URI] = len(out)
			out = append(out, m)
			continue
		}
		if m.CommittedAt.After(out[j].CommittedAt) {
			out[j] = ms[i]
		}
	}
	return out
}

// revokedAt reports whether an authorized tombstone is in effect at time at.
//
// A tombstone is authorized when a principal revocableBy names wrote it, or a
// member acting for that principal did: somebody who held, when the tombstone
// was written, a role in the principal covering the record and carrying the
// ability that manages records of its kind (ManageAbility). Unlike authoring,
// revoking does not require the abilities the record hands out: taking access
// away is the safe direction, and a role that may issue grants over a scope may
// end them too. Writes are org acts (spec §6.3), and a member's revocation is
// one of them.
//
// Whether the member held that role can turn on another member's tombstone, so
// the walk bounds the recursion as chain depth is bounded; a knot of
// tombstones that never resolves is an error, which fails closed.
func (e *Evaluator) revokedAt(ctx context.Context, rec *Record, t *Tombstone, at time.Time, w walk) (bool, error) {
	if t == nil || at.Before(t.At) {
		return false, nil
	}
	principals := Revokers(rec)
	if slices.Contains(principals, t.By) {
		return true, nil
	}
	if t.By == "" {
		return false, nil
	}
	if w.depth >= e.maxDepth() {
		return false, fmt.Errorf("%w: tombstone authority", ErrChainTooDeep)
	}
	for _, p := range principals {
		party, err := e.Resolver.Party(ctx, p)
		if err != nil {
			return false, err
		}
		if !party.CanHaveMembers() {
			continue
		}
		ok, err := e.hasRole(ctx, p, t.By, rec.Covers, []string{ManageAbility(rec)}, t.At, nil, w.deeper())
		if err != nil {
			return false, err
		}
		if ok {
			return true, nil
		}
	}
	return false, nil
}

// Revokers returns the principals whose own tombstone revokes rec, from
// revocableBy. A member of one of them revokes it too, when they hold
// ManageAbility over its scope (see Evaluator's revocation rule).
func Revokers(rec *Record) []string {
	switch rec.revocableBy() {
	case RevocableByTo:
		return []string{rec.To}
	case RevocableByEither:
		return []string{rec.From, rec.To}
	default:
		return []string{rec.From}
	}
}

// revokedByPrincipal is revokedAt without the member rule: whether a principal
// revocableBy names has tombstoned rec by time at. It is what a resolver can
// answer on its own when it lists exclusive holds.
func revokedByPrincipal(rec *Record, t *Tombstone, at time.Time) bool {
	return t != nil && !at.Before(t.At) && slices.Contains(Revokers(rec), t.By)
}

func containsAll(have, need []string) bool {
	for _, n := range need {
		if !slices.Contains(have, n) {
			return false
		}
	}
	return true
}
