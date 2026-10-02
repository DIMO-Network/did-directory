package orghost

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"strings"
	"time"

	"github.com/DIMO-Network/did-directory/internal/orghost/store"
	"github.com/DIMO-Network/did-directory/pkg/delegation"
	"github.com/DIMO-Network/did-directory/pkg/odrl"
)

// ErrForbidden is a request the caller's roles do not allow.
var ErrForbidden = errors.New("forbidden")

// ApprovalRequiredError is a write that is well formed and inside its author's
// authority but needs a second approval before it is committed (plan §3.2 step
// 4). The host parks it as pending with these reasons.
type ApprovalRequiredError struct {
	Reasons []string
}

func (e *ApprovalRequiredError) Error() string {
	return delegation.ErrApprovalRequired.Error() + ": " + strings.Join(e.Reasons, "; ")
}

func (e *ApprovalRequiredError) Unwrap() error { return delegation.ErrApprovalRequired }

// Policies maps a profile name to the commit policy it stands for. A role names
// one in constraints.policy and records authored under that role are checked
// against it; the org's own writes, and roles naming none, use
// delegation.DefaultPolicy. The host does not know what any profile is for: a
// booking role commits under agreement.CommitPolicy because the org said so
// when it wrote the role, not because the host knows what a booking is
// (plan §1 decision F).
type Policies map[string]delegation.Policy

// DefaultPolicies is the registry with only the default profile.
func DefaultPolicies() Policies {
	d := delegation.DefaultPolicy()
	return Policies{d.Name: d}
}

// defaultPolicy is the profile in force when no role names one.
func (s *Server) defaultPolicy() delegation.Policy {
	if p, ok := s.policies[delegation.DefaultPolicy().Name]; ok {
		return p
	}
	return delegation.DefaultPolicy()
}

// policyFor returns the policy a role's constraints name. An unknown name is
// an error rather than the default: the role was accepted under a registry
// that knew it, and guessing now would be the wrong direction to fail.
func (s *Server) policyFor(c *delegation.RoleConstraints) (delegation.Policy, error) {
	if c == nil || c.Policy == "" {
		return s.defaultPolicy(), nil
	}
	p, ok := s.policies[c.Policy]
	if !ok {
		return delegation.Policy{}, fmt.Errorf("%w: role names policy %q, which this host does not know", ErrForbidden, c.Policy)
	}
	return p, nil
}

// write is a write the host is deciding on.
type write struct {
	org, collection, rkey string
	// record is canonical and structurally checked (checkRecord).
	record json.RawMessage
	// committedBy is the member writing, or "" for the org itself.
	committedBy string
	// approvedBy is the member approving a pending write, or "" for a fresh
	// write.
	approvedBy string
}

func (w *write) uri() string { return "at://" + w.org + "/" + w.collection + "/" + w.rkey }

func (s *Server) evaluator() *delegation.Evaluator {
	return &delegation.Evaluator{Resolver: s.resolver}
}

func forbidden(format string, args ...any) error {
	return fmt.Errorf("%w: %s", ErrForbidden, fmt.Sprintf(format, args...))
}

// checkWrite runs plan §3.2 steps 2 to 4 over a prepared write: the author
// holds a live role covering the write's scope with the ability the write
// needs, the record passes its policy check under that role, and an approval,
// when one is carried, comes from somebody else with the same authority. It
// returns nil to commit, an *ApprovalRequiredError to park the write, or
// ErrForbidden with the reason.
//
// The org's own writes park like anyone else's: the second signature is a
// record fact, not a signer feature (plan §1 decision D), so nothing here
// depends on who holds the org key. What an approver must hold is the ability
// that manages records of that kind over the scope, not everything the record
// hands out, which is what lets the first writes happen at all: the org's
// first admin role carries no live abilities and commits directly, and every
// later write the policy flags waits for that admin.
func (s *Server) checkWrite(ctx context.Context, w *write) error {
	if _, err := s.repo.Store.GetOrg(ctx, w.org); err != nil {
		return err
	}
	// An update takes the record at the key away as surely as a tombstone does,
	// so overwriting takes what revoking takes, on top of what writing the new
	// body takes. Otherwise a lien only the lender may release is released by
	// rewriting its revocableBy, and a record outside the writer's scope is
	// replaced by one inside it.
	cur, err := s.repo.Get(ctx, w.org, w.collection, w.rkey)
	switch {
	case err == nil && cur.Live():
		author := w.committedBy
		if author == "" {
			author = w.org
		}
		if err := s.checkTombstone(ctx, w.org, author, cur); err != nil {
			return fmt.Errorf("overwriting %s: %w", w.uri(), err)
		}
	case err != nil && !store.IsNotFound(err):
		return err
	}
	switch w.collection {
	case delegation.CollectionDelegation, delegation.CollectionRole:
		return s.checkRecordWrite(ctx, w)
	case delegation.CollectionTag:
		return s.requireRole(ctx, w.org, w.committedBy, delegation.Covers{Tag: w.uri()}, delegation.AbilityTagWrite)
	case delegation.CollectionTagMembership:
		return s.checkMembershipWrite(ctx, w)
	case delegation.CollectionVehicleControl:
		return s.requireRole(ctx, w.org, w.committedBy, delegation.Covers{Vehicle: w.rkey}, delegation.AbilityOrgAdmin)
	case delegation.CollectionCustody:
		var p delegation.CustodyPeriod
		if err := json.Unmarshal(w.record, &p); err != nil {
			return fmt.Errorf("%w: %v", ErrInvalid, err)
		}
		// Custody narrows the grants held by whoever had the car, and the
		// evaluator reads it host-wide (plan §7), so writing it takes the same
		// authority as writing a grant over the vehicle.
		return s.requireRole(ctx, w.org, w.committedBy, delegation.Covers{Vehicle: p.Vehicle}, delegation.AbilityDelegationCreate)
	default:
		return fmt.Errorf("%w: unknown collection %s", ErrInvalid, w.collection)
	}
}

// memberOf refuses a member's write to an org that cannot have members.
func (s *Server) memberOf(ctx context.Context, org, member string) (delegation.Party, error) {
	party, err := s.resolver.Party(ctx, org)
	if err != nil {
		return party, err
	}
	if member != "" && !party.CanHaveMembers() {
		return party, forbidden("%s cannot have members", org)
	}
	return party, nil
}

// requireRole checks that member holds a live role in org covering scope with
// ability, or is the org itself (member == "").
func (s *Server) requireRole(ctx context.Context, org, member string, scope delegation.Covers, ability string) error {
	if member == "" {
		return nil
	}
	if _, err := s.memberOf(ctx, org, member); err != nil {
		return err
	}
	roles, err := s.evaluator().RolesCovering(ctx, org, member, scope, []string{ability}, s.repo.now())
	if err != nil {
		return err
	}
	if len(roles) == 0 {
		return forbidden("%s holds no role in %s covering %s with %s", member, org, describe(scope), ability)
	}
	return nil
}

func describe(c delegation.Covers) string {
	switch {
	case c.Vehicle != "":
		return "vehicle " + c.Vehicle
	case c.Tag != "":
		return "tag " + c.Tag
	default:
		return "every vehicle"
	}
}

// checkRecordWrite is the delegation and role path: role resolution, then
// delegation.CheckCommit under each candidate role's policy, then the approver.
func (s *Server) checkRecordWrite(ctx context.Context, w *write) error {
	decoded, err := odrl.Decode(w.record)
	if err != nil {
		return fmt.Errorf("%w: %v", ErrInvalid, err)
	}
	rec := *decoded
	if rec.Type == delegation.TypeRole && rec.Constraints != nil && rec.Constraints.Policy != "" {
		if _, ok := s.policies[rec.Constraints.Policy]; !ok {
			return fmt.Errorf("%w: constraints.policy %q is not a policy this host knows", ErrInvalid, rec.Constraints.Policy)
		}
	}
	now := s.repo.now()
	party, err := s.memberOf(ctx, w.org, w.committedBy)
	if err != nil {
		return err
	}
	ev := s.evaluator()
	count, err := ev.CoveredVehicles(ctx, &rec, now)
	if store.IsNotFound(err) {
		return fmt.Errorf("%w: counting covered vehicles: %v", ErrInvalid, err)
	}
	if err != nil {
		return err
	}
	approved := w.approvedBy != ""
	need := delegation.AuthoringNeed(&rec)

	if w.committedBy == "" {
		cc := delegation.CommitContext{From: party, CoveredVehicles: count, Approved: approved, Policy: s.defaultPolicy()}
		if err := delegation.CheckCommit(&rec, cc); err != nil {
			if errors.Is(err, delegation.ErrApprovalRequired) {
				return &ApprovalRequiredError{Reasons: delegation.ApprovalReasons(&rec, cc)}
			}
			return forbidden("%v", err)
		}
	} else {
		roles, err := ev.RolesCovering(ctx, w.org, w.committedBy, rec.Covers, need, now)
		if err != nil {
			return err
		}
		if len(roles) == 0 {
			return forbidden("%s holds no role in %s covering %s with %s", w.committedBy, w.org, describe(rec.Covers), strings.Join(need, ", "))
		}
		// Any one role the member holds may carry the write. When none does, the
		// answer is the first role's, in the order the repository holds them:
		// an approval requirement if any role stopped there, else the refusal.
		var pending *ApprovalRequiredError
		var refused error
		ok := false
		for i := range roles {
			policy, err := s.policyFor(roles[i].Record.Constraints)
			if err != nil {
				return err
			}
			cc := delegation.CommitContext{
				From: party, CoveredVehicles: count, Role: &roles[i].Record,
				CommittedBy: w.committedBy, Approved: approved, Policy: policy,
			}
			err = delegation.CheckCommit(&rec, cc)
			switch {
			case err == nil:
				ok = true
			case errors.Is(err, delegation.ErrApprovalRequired) && pending == nil:
				pending = &ApprovalRequiredError{Reasons: delegation.ApprovalReasons(&rec, cc)}
			case refused == nil:
				refused = err
			}
			if ok {
				break
			}
		}
		if !ok {
			if pending != nil {
				return pending
			}
			return forbidden("%v", refused)
		}
	}

	if approved {
		return s.checkApprover(ctx, w, rec.To, func() error {
			return s.requireRole(ctx, w.org, w.approvedBy, rec.Covers, delegation.ManageAbility(&rec))
		})
	}
	return nil
}

// checkApprover applies the rules every approval shares: the author cannot
// approve their own write, nor can the recipient, and anyone else must hold the
// managing ability over the write's scope, which authority checks; it is the
// evaluator's own rule (approvedByAnother). The org itself is its own
// authority.
func (s *Server) checkApprover(ctx context.Context, w *write, recipient string, authority func() error) error {
	author := w.committedBy
	if author == "" {
		author = w.org
	}
	switch {
	case w.approvedBy == author:
		return forbidden("the author cannot approve their own write")
	case recipient != "" && w.approvedBy == recipient:
		return forbidden("the recipient cannot approve a write in their favour")
	case w.approvedBy == w.org:
		return nil
	}
	if _, err := s.memberOf(ctx, w.org, w.approvedBy); err != nil {
		return err
	}
	return authority()
}

// checkMembershipWrite is the tag membership path: tag:write over the tag, the
// §9.2 author-authority check against every delegation covering the tag, and
// CheckMembershipGrowth.
func (s *Server) checkMembershipWrite(ctx context.Context, w *write) error {
	var m delegation.MembershipRecord
	if err := json.Unmarshal(w.record, &m); err != nil {
		return fmt.Errorf("%w: %v", ErrInvalid, err)
	}
	covering, err := s.delegationsOverTag(ctx, w.org, m.Tag)
	if err != nil {
		return err
	}
	scope := delegation.Covers{Tag: m.Tag}

	if err := s.requireRole(ctx, w.org, w.committedBy, scope, delegation.AbilityTagWrite); err != nil {
		return err
	}
	if w.committedBy != "" {
		// A membership counts toward a delegation only if its author could have
		// granted that delegation's abilities (§9.2). One that would be ignored
		// is refused here, naming what blocks it, rather than committed to no
		// effect.
		var blocked []string
		for i := range covering {
			roles, err := s.evaluator().RolesCovering(ctx, w.org, w.committedBy, scope, delegation.MembershipNeed(&covering[i].Record), s.repo.now())
			if err != nil {
				return err
			}
			if len(roles) == 0 {
				blocked = append(blocked, covering[i].URI)
			}
		}
		if len(blocked) > 0 {
			return forbidden("%s lacks authority over the abilities granted by %s, so this membership would not count toward them", w.committedBy, strings.Join(blocked, ", "))
		}
	}

	count, err := s.membershipCount(ctx, w.org, &m)
	if err != nil {
		return err
	}
	records := make([]delegation.Record, len(covering))
	for i := range covering {
		records[i] = covering[i].Record
	}
	approved := w.approvedBy != ""
	if err := delegation.CheckMembershipGrowth(records, count, approved, s.defaultPolicy()); err != nil {
		return &ApprovalRequiredError{Reasons: []string{strings.TrimPrefix(err.Error(), delegation.ErrApprovalRequired.Error()+": ")}}
	}
	if approved {
		return s.checkApprover(ctx, w, "", func() error {
			return s.requireRole(ctx, w.org, w.approvedBy, scope, delegation.AbilityTagWrite)
		})
	}
	return nil
}

// delegationsOverTag returns the live delegations covering tag, parsed.
func (s *Server) delegationsOverTag(ctx context.Context, org, tag string) ([]delegation.Stored, error) {
	sts, err := s.repo.Store.DelegationsOverTag(ctx, org, tag)
	if err != nil {
		return nil, err
	}
	out := make([]delegation.Stored, 0, len(sts))
	for i := range sts {
		st, err := stored(org, &sts[i])
		if err != nil {
			return nil, err
		}
		out = append(out, *st)
	}
	return out, nil
}

// membershipCount is how many vehicles the tag would hold once m is committed,
// when m adds one: counted at the first moment the interval is in force, its
// joinedAt or now if it has already begun. It is zero when the write grows
// nothing, because the interval has already ended or the vehicle is in the
// tag already, since growth is what the threshold guards.
func (s *Server) membershipCount(ctx context.Context, org string, m *delegation.MembershipRecord) (int, error) {
	at := s.repo.now()
	if m.JoinedAt.After(at) {
		at = m.JoinedAt
	}
	if m.LeftAt != nil && !m.LeftAt.After(at) {
		return 0, nil
	}
	existing, err := s.resolver.Memberships(ctx, m.Tag, m.Vehicle)
	if err != nil {
		return 0, err
	}
	for _, e := range existing {
		if !at.Before(e.JoinedAt) && (e.LeftAt == nil || at.Before(*e.LeftAt)) {
			return 0, nil
		}
	}
	n, err := s.repo.Store.TagSize(ctx, org, m.Tag, at)
	if err != nil {
		return 0, err
	}
	return n + 1, nil
}

// checkTombstone decides whether caller may revoke the record cur (plan §3.5).
// For a delegation or role it is the evaluator's rule, so a tombstone the host
// accepts is one evaluation will honour: a principal revocableBy names, or a
// member of one holding the ability that manages records of that kind over its
// scope. Other collections take the same role their writes take.
func (s *Server) checkTombstone(ctx context.Context, org, caller string, cur *store.Stored) error {
	member := caller
	if caller == org {
		member = ""
	}
	switch cur.Collection {
	case delegation.CollectionDelegation, delegation.CollectionRole:
		st, err := stored(org, cur)
		if err != nil {
			return err
		}
		rec := &st.Record
		principals := delegation.Revokers(rec)
		if slices.Contains(principals, caller) {
			return nil
		}
		manage := delegation.ManageAbility(rec)
		for _, p := range principals {
			party, err := s.resolver.Party(ctx, p)
			if err != nil {
				return err
			}
			if !party.CanHaveMembers() {
				continue
			}
			roles, err := s.evaluator().RolesCovering(ctx, p, caller, rec.Covers, []string{manage}, s.repo.now())
			if err != nil {
				return err
			}
			if len(roles) > 0 {
				return nil
			}
		}
		return forbidden("only %s may revoke this record, or a member of them holding %s over %s", strings.Join(principals, " or "), manage, describe(rec.Covers))
	case delegation.CollectionTag:
		return s.requireRole(ctx, org, member, delegation.Covers{Tag: cur.URI}, delegation.AbilityTagWrite)
	case delegation.CollectionTagMembership:
		var m delegation.MembershipRecord
		if err := json.Unmarshal(cur.Record, &m); err != nil {
			return err
		}
		return s.requireRole(ctx, org, member, delegation.Covers{Tag: m.Tag}, delegation.AbilityTagWrite)
	case delegation.CollectionVehicleControl:
		return s.requireRole(ctx, org, member, delegation.Covers{Vehicle: cur.RKey}, delegation.AbilityOrgAdmin)
	case delegation.CollectionCustody:
		var p delegation.CustodyPeriod
		if err := json.Unmarshal(cur.Record, &p); err != nil {
			return err
		}
		return s.requireRole(ctx, org, member, delegation.Covers{Vehicle: p.Vehicle}, delegation.AbilityDelegationCreate)
	default:
		return fmt.Errorf("%w: unknown collection %s", ErrInvalid, cur.Collection)
	}
}

// reader is what one caller may read in one org's repository (spec §6.2).
// The org itself and holders of org:admin read everything. Any other member
// reads the records they wrote, and, through each org:read role they hold,
// the records inside that role's scope; no other ability implies reading.
// The control openings and the commit log that carries them are org:admin's
// alone.
type reader struct {
	s      *Server
	org    string
	caller string
	at     time.Time
	all    bool
	scopes []delegation.Covers
}

// reader resolves caller's read access to org. A caller holding no role there
// is refused outright; one whose roles grant no reads gets a reader that
// admits only their own records.
func (s *Server) reader(ctx context.Context, org, caller string) (*reader, error) {
	if _, err := s.repo.Store.GetOrg(ctx, org); err != nil {
		return nil, err
	}
	r := &reader{s: s, org: org, caller: caller, at: s.repo.now()}
	if caller == org {
		r.all = true
		return r, nil
	}
	if party, err := s.resolver.Party(ctx, org); err != nil {
		return nil, err
	} else if !party.CanHaveMembers() {
		return nil, forbidden("%s cannot have members", org)
	}
	roles, err := s.evaluator().HeldRoles(ctx, org, caller, r.at)
	if err != nil {
		return nil, err
	}
	if len(roles) == 0 {
		return nil, forbidden("%s holds no role in %s", caller, org)
	}
	for i := range roles {
		switch abilities := roles[i].Record.Abilities; {
		case slices.Contains(abilities, delegation.AbilityOrgAdmin):
			r.all = true
		case slices.Contains(abilities, delegation.AbilityOrgRead):
			r.scopes = append(r.scopes, roles[i].Record.Covers)
		}
	}
	return r, nil
}

// requireAdmin refuses a caller who does not read everything: the control
// openings and the log are not scoped.
func (r *reader) requireAdmin() error {
	if r.all {
		return nil
	}
	return forbidden("%s needs %s in %s to read this", r.caller, delegation.AbilityOrgAdmin, r.org)
}

// canRead reports whether the caller may read one record of the repository.
func (r *reader) canRead(ctx context.Context, uri, collection string, record json.RawMessage, committedBy string) (bool, error) {
	if r.all {
		return true, nil
	}
	if collection == delegation.CollectionVehicleControl {
		return false, nil
	}
	if committedBy == r.caller {
		return true, nil
	}
	if len(r.scopes) == 0 {
		return false, nil
	}
	targets, err := recordScope(uri, collection, record)
	if err != nil {
		return false, err
	}
	return r.covers(ctx, targets...)
}

// covers reports whether any of the caller's read scopes includes any target.
func (r *reader) covers(ctx context.Context, targets ...delegation.Covers) (bool, error) {
	ev := r.s.evaluator()
	for _, scope := range r.scopes {
		for _, target := range targets {
			ok, err := ev.RoleScopeCovers(ctx, scope, target, r.at)
			if err != nil || ok {
				return ok, err
			}
		}
	}
	return false, nil
}

// canReadStored is canRead for a committed record.
func (r *reader) canReadStored(ctx context.Context, st *store.Stored) (bool, error) {
	return r.canRead(ctx, st.URI, st.Collection, st.Record, st.CommittedBy)
}

// recordScope is what a record is about, as role scopes are written: a
// delegation or role by what it covers, a tag by itself, a membership by its
// tag and by its vehicle, custody by its vehicle. A record that covers by
// inheritance is in no scope narrower than the whole org.
func recordScope(uri, collection string, record json.RawMessage) ([]delegation.Covers, error) {
	switch collection {
	case delegation.CollectionDelegation, delegation.CollectionRole:
		rec, err := odrl.Decode(record)
		if err != nil {
			return nil, err
		}
		return []delegation.Covers{rec.Covers}, nil
	case delegation.CollectionTag:
		return []delegation.Covers{{Tag: uri}}, nil
	case delegation.CollectionTagMembership:
		var m delegation.MembershipRecord
		if err := json.Unmarshal(record, &m); err != nil {
			return nil, err
		}
		return []delegation.Covers{{Tag: m.Tag}, {Vehicle: m.Vehicle}}, nil
	case delegation.CollectionCustody:
		var p delegation.CustodyPeriod
		if err := json.Unmarshal(record, &p); err != nil {
			return nil, err
		}
		return []delegation.Covers{{Vehicle: p.Vehicle}}, nil
	default:
		return nil, nil
	}
}

// parseSince reads an RFC 3339 time.
func parseSince(s string) (time.Time, error) {
	t, err := time.Parse(time.RFC3339Nano, s)
	if err != nil {
		return time.Time{}, fmt.Errorf("since must be RFC 3339: %w", err)
	}
	return t, nil
}
