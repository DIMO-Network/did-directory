package orghost

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"sync"
	"time"

	"github.com/DIMO-Network/did-directory/internal/orghost/store"
	"github.com/DIMO-Network/did-directory/pkg/client"
	"github.com/DIMO-Network/did-directory/pkg/control"
	"github.com/DIMO-Network/did-directory/pkg/delegation"
)

// ErrResolve marks a failure to read something an evaluation needed: the store
// or the directory did not answer. It is distinct from an evaluation that read
// everything and refused, which is the caller's problem and not the host's.
var ErrResolve = errors.New("resolver")

// ControlSource answers control-state lookups. The DID directory is the one
// that counts (pkg/client.Client); tests supply their own.
type ControlSource interface {
	Control(ctx context.Context, did string) (*control.State, error)
}

// DefaultControlCacheTTL bounds how stale a cached control state may be. A
// transfer or revocation in the directory takes effect on the host within this
// long, which is well inside the token lifetimes spec §11.1 sets.
const DefaultControlCacheTTL = 30 * time.Second

// Resolver implements delegation.Resolver over this host's store and the DID
// directory (plan §3.3). Records are read from any repository on the host, so
// a chain from one org through another resolves as long as both live here;
// cross-host chains are the open question in plan §7.
type Resolver struct {
	Store   store.Store
	Control ControlSource
	// Now is the clock the cache ages by; nil means time.Now.
	Now func() time.Time
	// ControlCacheTTL is how long a fetched control state is served before the
	// directory is asked again; zero means DefaultControlCacheTTL.
	ControlCacheTTL time.Duration

	mu    sync.Mutex
	cache map[string]cachedControl
}

type cachedControl struct {
	state   *control.State
	fetched time.Time
}

func (r *Resolver) now() time.Time {
	if r.Now != nil {
		return r.Now()
	}
	return time.Now()
}

func (r *Resolver) controlTTL() time.Duration {
	if r.ControlCacheTTL > 0 {
		return r.ControlCacheTTL
	}
	return DefaultControlCacheTTL
}

func resolveErr(err error) error {
	return fmt.Errorf("%w: %v", ErrResolve, err)
}

// stored converts a store record to what the evaluator reads. org is the
// repository it came from, which is what an empty committedBy or tombstone-by
// means: the org itself. The evaluator already reads an empty CommittedBy as
// the issuer; a tombstone's By is compared to the record's from directly, so
// the org's own tombstone has to name it.
func stored(org string, st *store.Stored) (*delegation.Stored, error) {
	var rec delegation.Record
	if err := json.Unmarshal(st.Record, &rec); err != nil {
		return nil, fmt.Errorf("%s: %w", st.URI, err)
	}
	out := &delegation.Stored{
		URI: st.URI, Record: rec, CommittedAt: st.CommittedAt, CommittedBy: st.CommittedBy, ApprovedBy: st.ApprovedBy,
	}
	if st.Tombstone != nil {
		by := st.Tombstone.By
		if by == "" {
			by = org
		}
		out.Tombstone = &delegation.Tombstone{At: st.Tombstone.At, By: by}
	}
	return out, nil
}

// Record implements delegation.Resolver. A URI nothing was ever committed
// under, or in a repository this host does not serve, is store.ErrNotFound.
func (r *Resolver) Record(ctx context.Context, uri string) (*delegation.Stored, error) {
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
	return stored(org, st)
}

// Memberships implements delegation.Resolver: every version of each live
// membership record, CreatedBy the commit's witnessed author (plan §7).
func (r *Resolver) Memberships(ctx context.Context, tag, vehicle string) ([]delegation.Membership, error) {
	org, err := delegation.TagAuthority(tag)
	if err != nil {
		return nil, err
	}
	out, _, err := membershipVersions(ctx, r.Store, org, tag, vehicle)
	if store.IsNotFound(err) {
		return nil, nil
	}
	if err != nil {
		return nil, resolveErr(err)
	}
	return out, nil
}

// TagSize implements delegation.Resolver.
func (r *Resolver) TagSize(ctx context.Context, tag string, at time.Time) (int, error) {
	org, err := delegation.TagAuthority(tag)
	if err != nil {
		return 0, err
	}
	n, err := r.Store.TagSize(ctx, org, tag, at)
	if store.IsNotFound(err) {
		return 0, nil
	}
	if err != nil {
		return 0, resolveErr(err)
	}
	return n, nil
}

// Custody implements delegation.Resolver. Periods are read from org's
// repository, oldest first.
func (r *Resolver) Custody(ctx context.Context, org, vehicle, holder string) ([]delegation.CustodyPeriod, error) {
	sts, err := r.Store.Custody(ctx, org, vehicle, holder)
	if err != nil {
		return nil, resolveErr(err)
	}
	return custodyOf(sts)
}

// custodyOf converts custody records to periods, oldest first.
func custodyOf(sts []store.Stored) ([]delegation.CustodyPeriod, error) {
	out := make([]delegation.CustodyPeriod, 0, len(sts))
	for i := range sts {
		var p delegation.CustodyPeriod
		if err := json.Unmarshal(sts[i].Record, &p); err != nil {
			return nil, fmt.Errorf("%s: %w", sts[i].URI, err)
		}
		out = append(out, p)
	}
	sort.SliceStable(out, func(i, j int) bool { return out[i].From.Before(out[j].From) })
	return out, nil
}

// Roles implements delegation.Resolver: every version of every role org
// issued to member.
func (r *Resolver) Roles(ctx context.Context, org, member string) ([]delegation.Stored, error) {
	out, _, err := roleVersions(ctx, r.Store, org, member)
	if store.IsNotFound(err) {
		return nil, nil
	}
	if err != nil {
		return nil, resolveErr(err)
	}
	return out, nil
}

// ControlState implements delegation.Resolver over the directory, cached for
// ControlCacheTTL. A DID the directory does not hold has no eras, which the
// evaluator turns into "not the controller of record".
func (r *Resolver) ControlState(ctx context.Context, vehicle string) (*control.State, error) {
	now := r.now()
	r.mu.Lock()
	if c, ok := r.cache[vehicle]; ok && now.Sub(c.fetched) < r.controlTTL() {
		r.mu.Unlock()
		return c.state, nil
	}
	r.mu.Unlock()

	state, err := r.Control.Control(ctx, vehicle)
	if errors.Is(err, client.ErrNotFound) {
		state = &control.State{DID: vehicle}
	} else if err != nil {
		return nil, resolveErr(err)
	}

	r.mu.Lock()
	if r.cache == nil {
		r.cache = map[string]cachedControl{}
	}
	r.cache[vehicle] = cachedControl{state: state, fetched: now}
	r.mu.Unlock()
	return state, nil
}

// Opening implements delegation.Resolver from any version of the
// controller's vehicleControl record for the vehicle.
func (r *Resolver) Opening(ctx context.Context, vehicle string, era uint64, controller string) (*control.Opening, error) {
	o, _, err := openingVersion(ctx, r.Store, vehicle, era, controller)
	if store.IsNotFound(err) {
		return nil, nil
	}
	if err != nil {
		return nil, resolveErr(err)
	}
	return o, nil
}

// Party implements delegation.Resolver from the party table (plan §1 decision
// E). A DID the table does not name is an org if it has a repository here and
// otherwise unknown; neither is an attested operator.
func (r *Resolver) Party(ctx context.Context, did string) (delegation.Party, error) {
	p, err := r.Store.GetParty(ctx, did)
	if err == nil {
		return partyOf(p), nil
	}
	if !store.IsNotFound(err) {
		return delegation.Party{}, resolveErr(err)
	}
	if _, err := r.Store.GetOrg(ctx, did); err == nil {
		return delegation.Party{Kind: delegation.KindOrg}, nil
	} else if !store.IsNotFound(err) {
		return delegation.Party{}, resolveErr(err)
	}
	return delegation.Party{}, nil
}

func partyOf(p *store.Party) delegation.Party {
	out := delegation.Party{Operator: p.Operator}
	switch p.Kind {
	case store.KindPerson:
		out.Kind = delegation.KindPerson
	case store.KindOrg:
		out.Kind = delegation.KindOrg
	}
	return out
}

// Exclusives implements delegation.Resolver: the live exclusive claims over the
// vehicle whose validity contains at. Since is the validity start, or the commit
// time when the validity is open at the front, as the evaluator's tie rule
// expects.
func (r *Resolver) Exclusives(ctx context.Context, vehicle string, at time.Time) ([]delegation.ExclusiveHold, error) {
	sts, err := r.Store.Exclusives(ctx, vehicle, at)
	if err != nil {
		return nil, resolveErr(err)
	}
	return holdsOf(sts, at)
}

// holdsOf converts the delegations the store found to the holds in force at
// time at.
func holdsOf(sts []store.Stored, at time.Time) ([]delegation.ExclusiveHold, error) {
	var holds []delegation.ExclusiveHold
	for i := range sts {
		var rec delegation.Record
		if err := json.Unmarshal(sts[i].Record, &rec); err != nil {
			return nil, fmt.Errorf("%s: %w", sts[i].URI, err)
		}
		if len(rec.Exclusive) == 0 || !rec.Validity.Set().Contains(at) {
			continue
		}
		since := sts[i].CommittedAt
		if rec.Validity.From != nil {
			since = *rec.Validity.From
		}
		holds = append(holds, delegation.ExclusiveHold{URI: sts[i].URI, Holder: rec.To, Abilities: rec.Exclusive, Since: since})
	}
	return holds, nil
}

var _ delegation.Resolver = (*Resolver)(nil)
