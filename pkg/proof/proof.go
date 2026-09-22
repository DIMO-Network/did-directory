// Package proof defines coverage proofs (spec §11.3) and verifies them offline.
//
// A proof is the transcript of one evaluation: every commit the org host read
// while deciding what a delegation covers over a vehicle, the vehicle's era log
// from the directory, the party attributes and tag sizes the host asserted, and
// the coverage the host arrived at. Anyone holding it can re-run the same
// evaluator over the same records without the host, checking every commit's
// signature against the org's #dimo_org key on the way, and confirm that the
// records really do give the coverage claimed. It settles "did you have access
// to this car on 3/14" from the bundle alone.
//
// What a proof does not show is what the host left out. A tombstone the host
// omitted, or a newer version of a record, would not be missed by a verifier
// who holds only a slice of the log; the hash chain proves order and integrity
// of what is present, not completeness. The host's signature on a coverage
// answer is therefore still the host's word at the time it was given; the
// proof makes that word checkable, not unnecessary.
//
// Design: docs/superpowers/specs/2026-09-16-dimo-orgs-fleets-delegation-design.md
// Plan:   docs/superpowers/plans/2026-09-22-org-host-plan.md
package proof

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"sort"
	"time"

	"github.com/DIMO-Network/did-directory/pkg/control"
	"github.com/DIMO-Network/did-directory/pkg/delegation"
	"github.com/DIMO-Network/did-directory/pkg/repo"
)

// Verification errors.
var (
	// ErrInvalid is a proof that is malformed or whose commits do not verify:
	// a bad signature, a CID that does not match its commit, a record that is
	// not canonical.
	ErrInvalid = errors.New("proof is invalid")
	// ErrIncomplete is a proof the evaluation could not be replayed from: it
	// needed a record, party, key or count the bundle does not carry.
	ErrIncomplete = errors.New("proof is incomplete")
	// ErrMismatch is a proof whose records, replayed, give a different coverage
	// from the one it claims.
	ErrMismatch = errors.New("proof claims coverage its records do not give")
)

// Proof is a coverage proof: the evaluation of Delegation over Vehicle at At,
// and everything that evaluation read.
type Proof struct {
	// Delegation is the URI of the record proven.
	Delegation string `json:"delegation"`
	Vehicle    string `json:"vehicle"`
	// At is the time the host evaluated at.
	At time.Time `json:"at"`
	// Coverage is what the host concluded.
	Coverage *delegation.Coverage `json:"coverage"`
	// Keys maps each org whose commits appear to its #dimo_org public key as a
	// did:key, as the host held it. A verifier who trusts the directory more
	// than the host resolves each org and supplies its own (Anchors).
	Keys map[string]string `json:"keys"`
	// Commits are every commit the evaluation read, in no particular order:
	// the chain records, the roles their authors held, the memberships, custody
	// periods, control openings and exclusive claims, and the tombstones of any
	// of them that were revoked. Each is signed by its org's key.
	Commits []repo.Committed `json:"commits"`
	// Control is the vehicle's era log as the directory served it.
	Control *control.State `json:"control"`
	// Parties are the policy attributes the host asserted for each principal
	// the evaluation asked about. They are DIMO's say-so (plan §1 decision E)
	// and are not verifiable from the bundle.
	Parties map[string]Party `json:"parties"`
	// TagSizes are the vehicle counts the host asserted for each tag the
	// evaluation measured, at At. A count is a property of a whole tag and the
	// bundle carries only this vehicle's memberships, so it is asserted rather
	// than derived.
	TagSizes map[string]int `json:"tagSizes,omitempty"`
}

// Party kinds as a proof carries them.
const (
	KindPerson = "person"
	KindOrg    = "org"
)

// Party is delegation.Party in its JSON form.
type Party struct {
	// Kind is KindPerson, KindOrg, or "" for a principal DIMO has not classified.
	Kind     string `json:"kind,omitempty"`
	Operator bool   `json:"operator,omitempty"`
}

// PartyOf converts a delegation.Party.
func PartyOf(p delegation.Party) Party {
	out := Party{Operator: p.Operator}
	switch p.Kind {
	case delegation.KindPerson:
		out.Kind = KindPerson
	case delegation.KindOrg:
		out.Kind = KindOrg
	}
	return out
}

// Delegation converts back to a delegation.Party.
func (p Party) Delegation() delegation.Party {
	out := delegation.Party{Operator: p.Operator}
	switch p.Kind {
	case KindPerson:
		out.Kind = delegation.KindPerson
	case KindOrg:
		out.Kind = delegation.KindOrg
	}
	return out
}

// Anchors are what a verifier trusts independently of the proof: the orgs'
// #dimo_org keys and the vehicle's era log, both public in the DID directory.
// A nil field is taken from the proof itself, which then shows only that the
// bundle is consistent with what the host said the directory held.
type Anchors struct {
	// Keys maps org DID to its #dimo_org did:key.
	Keys map[string]string
	// Control is the vehicle's era log.
	Control *control.State
}

// Verify checks a proof offline: every commit is signed by its org's key and
// hashes to its CID, every record is canonical, and replaying the evaluator
// over the bundle at the proof's time gives the coverage the proof claims. It
// returns that coverage. The evaluation runs under delegation.DefaultPolicy,
// as the host's does.
func Verify(ctx context.Context, p *Proof, anchors Anchors) (*delegation.Coverage, error) {
	if p.Coverage == nil {
		return nil, fmt.Errorf("%w: no coverage is claimed", ErrInvalid)
	}
	cov, err := Evaluate(ctx, p, anchors)
	if err != nil {
		return nil, err
	}
	same, err := sameCoverage(cov, p.Coverage)
	if err != nil {
		return nil, err
	}
	if !same {
		return nil, ErrMismatch
	}
	return cov, nil
}

// Evaluate checks the proof's commits and replays the evaluation, returning
// what the records give without comparing it to the claim. An evaluation that
// refuses returns the evaluator's error, so a proof of a revoked grant
// evaluates to delegation.ErrRevoked.
func Evaluate(ctx context.Context, p *Proof, anchors Anchors) (*delegation.Coverage, error) {
	if _, _, _, err := delegation.ParseURI(p.Delegation); err != nil {
		return nil, fmt.Errorf("%w: delegation: %v", ErrInvalid, err)
	}
	if !isDID(p.Vehicle) {
		return nil, fmt.Errorf("%w: vehicle must be a DID", ErrInvalid)
	}
	if p.At.IsZero() {
		return nil, fmt.Errorf("%w: at is required", ErrInvalid)
	}
	keys := anchors.Keys
	if keys == nil {
		keys = p.Keys
	}
	state := anchors.Control
	if state == nil {
		state = p.Control
	}
	if state == nil {
		return nil, fmt.Errorf("%w: no control state for %s", ErrIncomplete, p.Vehicle)
	}
	if state.DID != p.Vehicle {
		return nil, fmt.Errorf("%w: control state is for %s, not %s", ErrInvalid, state.DID, p.Vehicle)
	}

	b, err := newBundle(p, keys, state)
	if err != nil {
		return nil, err
	}
	ev := &delegation.Evaluator{Resolver: b}
	return ev.Coverage(ctx, p.Delegation, p.Vehicle, p.At)
}

// sameCoverage compares two coverages through their JSON form, which is how
// the claim travelled and what a reader of the proof sees.
func sameCoverage(a, b *delegation.Coverage) (bool, error) {
	ja, err := json.Marshal(a)
	if err != nil {
		return false, err
	}
	jb, err := json.Marshal(b)
	if err != nil {
		return false, err
	}
	return bytes.Equal(ja, jb), nil
}

// entry is the current state of one record key as the bundle's commits give
// it, in the form the evaluator reads.
type entry struct {
	org, collection, rkey string
	uri                   string
	seq                   int64
	record                json.RawMessage
	committedAt           time.Time
	committedBy           string
	approvedBy            []string
	tombstone             *delegation.Tombstone
}

func (e *entry) live() bool { return e.tombstone == nil }

// bundle implements delegation.Resolver over a proof's contents.
type bundle struct {
	p       *Proof
	control *control.State
	// entries are the current state of every record key touched, ordered by
	// org and seq, which is the order a host's store returns them in.
	entries []*entry
	byURI   map[string]*entry
}

// newBundle verifies every commit and replays them into record states.
func newBundle(p *Proof, keys map[string]string, state *control.State) (*bundle, error) {
	commits := slices.Clone(p.Commits)
	sort.SliceStable(commits, func(i, j int) bool {
		if commits[i].DID != commits[j].DID {
			return commits[i].DID < commits[j].DID
		}
		return commits[i].Seq < commits[j].Seq
	})

	b := &bundle{p: p, control: state, byURI: map[string]*entry{}}
	for i := range commits {
		c := &commits[i]
		if err := checkCommit(c, keys); err != nil {
			return nil, err
		}
		if i > 0 && commits[i-1].DID == c.DID && commits[i-1].Seq == c.Seq {
			return nil, fmt.Errorf("%w: %s seq %d appears twice", ErrInvalid, c.DID, c.Seq)
		}
		uri := c.URI()
		e, exists := b.byURI[uri]
		switch c.Op {
		case repo.OpCreate, repo.OpUpdate:
			if !exists {
				e = &entry{org: c.DID, collection: c.Collection, rkey: c.RKey, uri: uri}
				b.byURI[uri] = e
				b.entries = append(b.entries, e)
			}
			e.seq = c.Seq
			e.record = c.Record
			e.committedAt = c.CommittedAt
			e.committedBy = c.CommittedBy
			e.approvedBy = c.ApprovedBy
			e.tombstone = nil
		case repo.OpTombstone:
			if !exists {
				return nil, fmt.Errorf("%w: %s is tombstoned at seq %d but its record is not in the bundle", ErrIncomplete, uri, c.Seq)
			}
			// The org's own tombstone carries no author; the evaluator compares
			// the tombstone's author to the record's from, so it has to be named.
			by := c.CommittedBy
			if by == "" {
				by = c.DID
			}
			e.tombstone = &delegation.Tombstone{At: c.CommittedAt, By: by}
		}
	}
	return b, nil
}

// checkCommit verifies one commit against its org's key: signature, CID,
// record key, operation shape and canonical form.
func checkCommit(c *repo.Committed, keys map[string]string) error {
	key, ok := keys[c.DID]
	if !ok {
		return fmt.Errorf("%w: no #dimo_org key for %s", ErrIncomplete, c.DID)
	}
	where := fmt.Sprintf("%s seq %d", c.DID, c.Seq)
	if err := repo.Verify(&c.Commit, key); err != nil {
		return fmt.Errorf("%w: %s: %v", ErrInvalid, where, err)
	}
	cid, err := c.Commit.CID()
	if err != nil {
		return fmt.Errorf("%w: %s: %v", ErrInvalid, where, err)
	}
	if c.CID != "" && c.CID != cid {
		return fmt.Errorf("%w: %s: CID %s does not match content %s", ErrInvalid, where, c.CID, cid)
	}
	if err := repo.ValidateTID(c.Rev); err != nil {
		return fmt.Errorf("%w: %s: %v", ErrInvalid, where, err)
	}
	if c.Collection == "" {
		return fmt.Errorf("%w: %s: collection is empty", ErrInvalid, where)
	}
	if err := delegation.ValidateRKey(c.RKey); err != nil {
		return fmt.Errorf("%w: %s: %v", ErrInvalid, where, err)
	}
	switch c.Op {
	case repo.OpCreate, repo.OpUpdate:
		if len(c.Record) == 0 {
			return fmt.Errorf("%w: %s: %s without a record", ErrInvalid, where, c.Op)
		}
		canon, err := repo.Canonical(c.Record)
		if err != nil {
			return fmt.Errorf("%w: %s: record: %v", ErrInvalid, where, err)
		}
		if !bytes.Equal(canon, c.Record) {
			return fmt.Errorf("%w: %s: record is not in canonical form", ErrInvalid, where)
		}
	case repo.OpTombstone:
		if len(c.Record) != 0 {
			return fmt.Errorf("%w: %s: tombstone carries a record", ErrInvalid, where)
		}
	default:
		return fmt.Errorf("%w: %s: unknown op %q", ErrInvalid, where, c.Op)
	}
	return nil
}

func (e *entry) stored() (*delegation.Stored, error) {
	var rec delegation.Record
	if err := json.Unmarshal(e.record, &rec); err != nil {
		return nil, fmt.Errorf("%w: %s: %v", ErrInvalid, e.uri, err)
	}
	return &delegation.Stored{
		URI: e.uri, Record: rec, CommittedAt: e.committedAt, CommittedBy: e.committedBy,
		ApprovedBy: e.approvedBy, Tombstone: e.tombstone,
	}, nil
}

// Record implements delegation.Resolver.
func (b *bundle) Record(_ context.Context, uri string) (*delegation.Stored, error) {
	e, ok := b.byURI[uri]
	if !ok {
		return nil, fmt.Errorf("%w: %s is not in the bundle", ErrIncomplete, uri)
	}
	if e.collection != delegation.CollectionDelegation && e.collection != delegation.CollectionRole {
		return nil, fmt.Errorf("%w: %s is not a delegation or role", ErrInvalid, uri)
	}
	return e.stored()
}

// Memberships implements delegation.Resolver over the bundle's live
// membership records. CreatedBy is the commit's author, as on the host.
func (b *bundle) Memberships(_ context.Context, tag, vehicle string) ([]delegation.Membership, error) {
	org, err := delegation.TagAuthority(tag)
	if err != nil {
		return nil, err
	}
	var out []delegation.Membership
	for _, e := range b.entries {
		if e.org != org || e.collection != delegation.CollectionTagMembership || !e.live() {
			continue
		}
		var m delegation.MembershipRecord
		if err := json.Unmarshal(e.record, &m); err != nil {
			return nil, fmt.Errorf("%w: %s: %v", ErrInvalid, e.uri, err)
		}
		if m.Tag != tag || m.Vehicle != vehicle {
			continue
		}
		out = append(out, delegation.Membership{
			Tag: m.Tag, Vehicle: m.Vehicle, JoinedAt: m.JoinedAt, LeftAt: m.LeftAt,
			CreatedBy: e.committedBy, CommittedAt: e.committedAt,
		})
	}
	return out, nil
}

// TagSize implements delegation.Resolver from the host's asserted counts.
func (b *bundle) TagSize(_ context.Context, tag string, _ time.Time) (int, error) {
	n, ok := b.p.TagSizes[tag]
	if !ok {
		return 0, fmt.Errorf("%w: no size for tag %s", ErrIncomplete, tag)
	}
	return n, nil
}

// Custody implements delegation.Resolver over the bundle's live custody
// records, oldest first.
func (b *bundle) Custody(_ context.Context, vehicle, holder string) ([]delegation.CustodyPeriod, error) {
	var out []delegation.CustodyPeriod
	for _, e := range b.entries {
		if e.collection != delegation.CollectionCustody || !e.live() {
			continue
		}
		var p delegation.CustodyPeriod
		if err := json.Unmarshal(e.record, &p); err != nil {
			return nil, fmt.Errorf("%w: %s: %v", ErrInvalid, e.uri, err)
		}
		if p.Vehicle == vehicle && p.Holder == holder {
			out = append(out, p)
		}
	}
	sort.SliceStable(out, func(i, j int) bool { return out[i].From.Before(out[j].From) })
	return out, nil
}

// Roles implements delegation.Resolver, tombstoned roles included.
func (b *bundle) Roles(_ context.Context, org, member string) ([]delegation.Stored, error) {
	var out []delegation.Stored
	for _, e := range b.entries {
		if e.org != org || e.collection != delegation.CollectionRole {
			continue
		}
		s, err := e.stored()
		if err != nil {
			return nil, err
		}
		if s.Record.To == member {
			out = append(out, *s)
		}
	}
	return out, nil
}

// ControlState implements delegation.Resolver from the anchored era log.
func (b *bundle) ControlState(_ context.Context, vehicle string) (*control.State, error) {
	if vehicle != b.control.DID {
		return nil, fmt.Errorf("%w: no control state for %s", ErrIncomplete, vehicle)
	}
	return b.control, nil
}

// Opening implements delegation.Resolver from the controller's live
// vehicleControl record for the vehicle.
func (b *bundle) Opening(_ context.Context, vehicle string, era uint64, controller string) (*control.Opening, error) {
	e, ok := b.byURI["at://"+controller+"/"+delegation.CollectionVehicleControl+"/"+vehicle]
	if !ok || !e.live() {
		return nil, nil
	}
	var o control.Opening
	if err := json.Unmarshal(e.record, &o); err != nil {
		return nil, fmt.Errorf("%w: %s: %v", ErrInvalid, e.uri, err)
	}
	if o.Era != era {
		return nil, nil
	}
	return &o, nil
}

// Party implements delegation.Resolver from the host's asserted attributes.
func (b *bundle) Party(_ context.Context, did string) (delegation.Party, error) {
	p, ok := b.p.Parties[did]
	if !ok {
		return delegation.Party{}, fmt.Errorf("%w: no party attributes for %s", ErrIncomplete, did)
	}
	return p.Delegation(), nil
}

// Exclusives implements delegation.Resolver as the host's store does: live
// delegations claiming exclusive abilities over the vehicle, directly or
// through a tag the vehicle has a membership in at time at, whose validity
// contains at.
func (b *bundle) Exclusives(_ context.Context, vehicle string, at time.Time) ([]delegation.ExclusiveHold, error) {
	tags := map[string]bool{}
	for _, e := range b.entries {
		if e.collection != delegation.CollectionTagMembership || !e.live() {
			continue
		}
		var m delegation.MembershipRecord
		if err := json.Unmarshal(e.record, &m); err != nil {
			return nil, fmt.Errorf("%w: %s: %v", ErrInvalid, e.uri, err)
		}
		if m.Vehicle == vehicle && !at.Before(m.JoinedAt) && (m.LeftAt == nil || at.Before(*m.LeftAt)) {
			tags[m.Tag] = true
		}
	}
	var holds []delegation.ExclusiveHold
	for _, e := range b.entries {
		if e.collection != delegation.CollectionDelegation || !e.live() {
			continue
		}
		s, err := e.stored()
		if err != nil {
			return nil, err
		}
		rec := &s.Record
		if len(rec.Exclusive) == 0 || !rec.Validity.Set().Contains(at) {
			continue
		}
		if rec.Covers.Vehicle != vehicle && !tags[rec.Covers.Tag] {
			continue
		}
		since := s.CommittedAt
		if rec.Validity.From != nil {
			since = *rec.Validity.From
		}
		holds = append(holds, delegation.ExclusiveHold{URI: s.URI, Holder: rec.To, Abilities: rec.Exclusive, Since: since})
	}
	return holds, nil
}

var _ delegation.Resolver = (*bundle)(nil)

func isDID(s string) bool {
	return len(s) > len("did:") && s[:len("did:")] == "did:"
}
