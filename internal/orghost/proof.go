package orghost

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/DIMO-Network/did-directory/internal/orghost/store"
	"github.com/DIMO-Network/did-directory/pkg/control"
	"github.com/DIMO-Network/did-directory/pkg/delegation"
	"github.com/DIMO-Network/did-directory/pkg/proof"
	"github.com/DIMO-Network/did-directory/pkg/repo"
	"github.com/gofiber/fiber/v2"
)

// recorder is the host's resolver with a transcript: every record, party,
// count and era log an evaluation reads is kept, so that once the evaluation
// is done the transcript can be bundled as a coverage proof (spec §11.3) and
// replayed offline by pkg/proof over exactly what the host consulted.
//
// The record-backed methods go to the store themselves rather than through
// the embedded Resolver, because the proof needs the commits behind each
// record and the evaluator's view has already shed them. The conversions are
// the Resolver's own, so what the transcript holds is what the evaluation saw.
type recorder struct {
	*Resolver
	at time.Time

	records  map[string]store.Stored // by URI, current state
	parties  map[string]proof.Party
	tagSizes map[string]int
	control  *control.State
}

func (s *Server) recorder(at time.Time) *recorder {
	return &recorder{
		Resolver: s.resolver, at: at,
		records: map[string]store.Stored{}, parties: map[string]proof.Party{}, tagSizes: map[string]int{},
	}
}

func (r *recorder) keep(sts ...store.Stored) {
	for i := range sts {
		r.records[sts[i].URI] = sts[i]
	}
}

func (r *recorder) Record(ctx context.Context, uri string) (*delegation.Stored, error) {
	org, collection, rkey, err := delegation.ParseURI(uri)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", store.ErrNotFound, err)
	}
	if collection != delegation.CollectionDelegation && collection != delegation.CollectionRole {
		return nil, fmt.Errorf("%w: %s is not a delegation or role", store.ErrNotFound, uri)
	}
	st, err := r.Store.Current(ctx, org, collection, rkey)
	if store.IsNotFound(err) {
		return nil, fmt.Errorf("%w: %s", store.ErrNotFound, uri)
	}
	if err != nil {
		return nil, resolveErr(err)
	}
	r.keep(*st)
	return stored(org, st)
}

func (r *recorder) Memberships(ctx context.Context, tag, vehicle string) ([]delegation.Membership, error) {
	org, err := delegation.TagAuthority(tag)
	if err != nil {
		return nil, err
	}
	sts, err := r.Store.Memberships(ctx, org, tag, vehicle)
	if store.IsNotFound(err) {
		return nil, nil
	}
	if err != nil {
		return nil, resolveErr(err)
	}
	r.keep(sts...)
	return membershipsOf(sts)
}

func (r *recorder) TagSize(ctx context.Context, tag string, at time.Time) (int, error) {
	n, err := r.Resolver.TagSize(ctx, tag, at)
	if err == nil {
		r.tagSizes[tag] = n
	}
	return n, err
}

func (r *recorder) Custody(ctx context.Context, vehicle, holder string) ([]delegation.CustodyPeriod, error) {
	sts, err := r.Store.Custody(ctx, vehicle, holder)
	if err != nil {
		return nil, resolveErr(err)
	}
	r.keep(sts...)
	return custodyOf(sts)
}

func (r *recorder) Roles(ctx context.Context, org, member string) ([]delegation.Stored, error) {
	sts, err := r.Store.Roles(ctx, org, member)
	if store.IsNotFound(err) {
		return nil, nil
	}
	if err != nil {
		return nil, resolveErr(err)
	}
	r.keep(sts...)
	return storedAll(org, sts)
}

func (r *recorder) ControlState(ctx context.Context, vehicle string) (*control.State, error) {
	state, err := r.Resolver.ControlState(ctx, vehicle)
	if err == nil {
		r.control = state
	}
	return state, err
}

func (r *recorder) Opening(ctx context.Context, vehicle string, era uint64, controller string) (*control.Opening, error) {
	st, err := r.Store.Current(ctx, controller, delegation.CollectionVehicleControl, vehicle)
	if store.IsNotFound(err) {
		return nil, nil
	}
	if err != nil {
		return nil, resolveErr(err)
	}
	r.keep(*st)
	return openingOf(st, era)
}

func (r *recorder) Party(ctx context.Context, did string) (delegation.Party, error) {
	p, err := r.Resolver.Party(ctx, did)
	if err == nil {
		r.parties[did] = proof.PartyOf(p)
	}
	return p, err
}

func (r *recorder) Exclusives(ctx context.Context, vehicle string, at time.Time) ([]delegation.ExclusiveHold, error) {
	sts, err := r.Store.Exclusives(ctx, vehicle, at)
	if err != nil {
		return nil, resolveErr(err)
	}
	r.keep(sts...)
	return holdsOf(sts, at)
}

var _ delegation.Resolver = (*recorder)(nil)

// proof bundles the transcript: the commit behind every record read, the
// tombstone commit of each one that was revoked, the key of every org those
// commits came from, and what the evaluation asserted and concluded.
func (r *recorder) proof(ctx context.Context, signer repo.Signer, uri, vehicle string, cov *delegation.Coverage) (*proof.Proof, error) {
	p := &proof.Proof{
		Delegation: uri, Vehicle: vehicle, At: r.at, Coverage: cov,
		Keys: map[string]string{}, Commits: []repo.Committed{}, Control: r.control,
		Parties: r.parties, TagSizes: r.tagSizes,
	}
	if p.Control == nil {
		// A chain that failed before reaching its root never asked; the proof
		// still names the vehicle's era log so the verifier has one to anchor.
		state, err := r.Resolver.ControlState(ctx, vehicle)
		if err != nil {
			return nil, err
		}
		p.Control = state
	}
	seen := map[string]bool{}
	for _, st := range r.records {
		org, _, _, err := delegation.ParseURI(st.URI)
		if err != nil {
			return nil, err
		}
		if _, ok := p.Keys[org]; !ok {
			key, err := signer.PublicKey(ctx, org)
			if err != nil {
				return nil, resolveErr(err)
			}
			p.Keys[org] = key
		}
		seqs := []int64{st.Seq}
		if st.Tombstone != nil {
			seqs = append(seqs, st.Tombstone.Seq)
		}
		for _, seq := range seqs {
			key := fmt.Sprintf("%s/%d", org, seq)
			if seen[key] {
				continue
			}
			seen[key] = true
			c, err := r.commitAt(ctx, org, seq)
			if err != nil {
				return nil, err
			}
			p.Commits = append(p.Commits, *c)
		}
	}
	sort.Slice(p.Commits, func(i, j int) bool {
		if p.Commits[i].DID != p.Commits[j].DID {
			return p.Commits[i].DID < p.Commits[j].DID
		}
		return p.Commits[i].Seq < p.Commits[j].Seq
	})
	return p, nil
}

// commitAt reads one commit of org's log.
func (r *recorder) commitAt(ctx context.Context, org string, seq int64) (*repo.Committed, error) {
	commits, err := r.Store.Commits(ctx, org, seq-1, 1)
	if err != nil {
		return nil, resolveErr(err)
	}
	if len(commits) != 1 || commits[0].Seq != seq {
		return nil, resolveErr(fmt.Errorf("%s has no commit at seq %d", org, seq))
	}
	return &commits[0], nil
}

// proof serves GET /orgs/:org/delegations/:rkey/proof?vehicle= (plan §3.4):
// the coverage proof for one delegation over one vehicle, evaluated now. The
// delegation's recipient may fetch it, since it is their access being proven,
// and so may the org. An evaluation that refuses answers as /authorize would,
// with the code; there is no proof of what was not granted.
func (s *Server) proof(c *fiber.Ctx) error {
	org, _, rkey := params(c)
	vehicle := strings.Clone(c.Query("vehicle"))
	if !isDID(vehicle) {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "vehicle must be a DID"})
	}
	cur, err := s.repo.Get(c.Context(), org, delegation.CollectionDelegation, rkey)
	if err != nil {
		return s.fail(c, err)
	}
	st, err := stored(org, cur)
	if err != nil {
		return s.fail(c, err)
	}
	if by := caller(c); by != org && by != st.Record.To {
		return s.fail(c, forbidden("only %s or %s may fetch a proof of this delegation", st.Record.To, org))
	}

	rec := s.recorder(s.repo.now())
	ev := &delegation.Evaluator{Resolver: rec}
	cov, err := ev.Coverage(c.Context(), st.URI, vehicle, rec.at)
	if err != nil {
		return s.refuse(c, st.URI, err)
	}
	p, err := rec.proof(c.Context(), s.repo.Signer, st.URI, vehicle, cov)
	if err != nil {
		return s.fail(c, err)
	}
	s.log.Info().Str("uri", st.URI).Str("vehicle", vehicle).Str("by", caller(c)).Int("commits", len(p.Commits)).Msg("coverage proof served")
	return c.JSON(p)
}

// Descendant is one entry of the consent transparency view (spec §9.3): a
// delegation that chains, directly or through others, from the root asked
// about, and what it gives over the vehicle now.
type Descendant struct {
	URI   string `json:"uri"`
	From  string `json:"from"`
	To    string `json:"to"`
	Depth int    `json:"depth"`
	// Basis is the record's own basis, which names the descendant it chains
	// through, or the root.
	Basis     []string          `json:"basis"`
	Covers    delegation.Covers `json:"covers"`
	Abilities []string          `json:"abilities"`
	Purpose   string            `json:"purpose,omitempty"`
	// Coverage is what the record gives over the vehicle now, or nil when it
	// gives nothing, with Refused saying why in the codes /authorize uses.
	Coverage *delegation.Coverage `json:"coverage,omitempty"`
	Refused  string               `json:"refused,omitempty"`
}

// descendants serves GET /orgs/:org/delegations/:rkey/descendants?vehicle=
// (plan §3.4): every delegation on this host that chains from the given one,
// breadth first to the chain depth limit, each resolved over the vehicle. It
// is for the delegation's from, the owner who consented, so they can see
// every party with access to their car through it. A descendant that no
// longer evaluates is still listed, with the reason, since a record that
// names the consent is part of what the owner is entitled to see.
func (s *Server) descendants(c *fiber.Ctx) error {
	org, _, rkey := params(c)
	vehicle := strings.Clone(c.Query("vehicle"))
	if !isDID(vehicle) {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "vehicle must be a DID"})
	}
	if caller(c) != org {
		return s.fail(c, forbidden("only %s may list the descendants of its delegations", org))
	}
	cur, err := s.repo.Get(c.Context(), org, delegation.CollectionDelegation, rkey)
	if err != nil {
		return s.fail(c, err)
	}

	at := s.repo.now()
	ev := s.evaluator()
	maxDepth := delegation.DefaultPolicy().MaxChainDepth
	out := []Descendant{}
	seen := map[string]bool{cur.URI: true}
	frontier := []string{cur.URI}
	for depth := 2; depth <= maxDepth && len(frontier) > 0; depth++ {
		var next []string
		for _, uri := range frontier {
			sts, err := s.repo.Store.DelegationsWithBasis(c.Context(), uri)
			if err != nil {
				return s.fail(c, err)
			}
			for i := range sts {
				if seen[sts[i].URI] {
					continue
				}
				seen[sts[i].URI] = true
				descOrg, _, _, err := delegation.ParseURI(sts[i].URI)
				if err != nil {
					return s.fail(c, err)
				}
				st, err := stored(descOrg, &sts[i])
				if err != nil {
					return s.fail(c, err)
				}
				d := Descendant{
					URI: st.URI, From: st.Record.From, To: st.Record.To, Depth: depth,
					Basis: st.Record.Basis, Covers: st.Record.Covers, Abilities: st.Record.Abilities, Purpose: st.Record.Purpose,
				}
				cov, err := ev.Coverage(c.Context(), st.URI, vehicle, at)
				switch {
				case err == nil:
					d.Coverage = cov
				case errors.Is(err, ErrResolve):
					return s.fail(c, err)
				default:
					d.Refused = codeOf(err)
				}
				out = append(out, d)
				next = append(next, st.URI)
			}
		}
		frontier = next
	}
	return c.JSON(fiber.Map{"root": cur.URI, "vehicle": vehicle, "at": at, "descendants": out})
}
