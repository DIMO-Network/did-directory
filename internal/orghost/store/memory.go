package store

import (
	"context"
	"encoding/json"
	"slices"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/DIMO-Network/did-directory/pkg/repo"
)

// MemoryStore implements Store in memory. It is the default when DATABASE_URL
// is unset, so it is a production code path: Fiber serves every request in its
// own goroutine, and mu is what keeps concurrent appends from losing a sequence
// number.
type MemoryStore struct {
	mu      sync.RWMutex
	orgs    map[string]*memOrg
	parties map[string]Party
	pending map[string]Pending // org + "/" + id
}

type memOrg struct {
	org     Org
	commits []repo.Committed
	// heads maps collection/rkey to the index in commits of the last create or
	// update, and of the tombstone if any.
	heads map[string]memHead
}

type memHead struct {
	record    int
	tombstone int // -1 when live
}

// NewMemoryStore creates an empty in-memory store.
func NewMemoryStore() *MemoryStore {
	return &MemoryStore{orgs: map[string]*memOrg{}, parties: map[string]Party{}, pending: map[string]Pending{}}
}

func (s *MemoryStore) CreateOrg(_ context.Context, org Org) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	did := strings.Clone(org.DID)
	if _, ok := s.orgs[did]; ok {
		return ErrOrgExists
	}
	org.DID = did
	org.KeyEnc = slices.Clone(org.KeyEnc)
	if org.CreatedAt.IsZero() {
		org.CreatedAt = time.Now().UTC()
	}
	s.orgs[did] = &memOrg{org: org, heads: map[string]memHead{}}
	return nil
}

func (s *MemoryStore) GetOrg(_ context.Context, did string) (*Org, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	o, ok := s.orgs[did]
	if !ok {
		return nil, ErrNotFound
	}
	org := o.org
	org.KeyEnc = slices.Clone(org.KeyEnc)
	return &org, nil
}

func (s *MemoryStore) Head(_ context.Context, org string) (Head, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	o, ok := s.orgs[org]
	if !ok {
		return Head{}, ErrNotFound
	}
	return o.head(), nil
}

func (o *memOrg) head() Head {
	if len(o.commits) == 0 {
		return Head{}
	}
	last := o.commits[len(o.commits)-1]
	return Head{Seq: last.Seq, CID: last.CID, Rev: last.Rev}
}

func (s *MemoryStore) AppendAfter(_ context.Context, expectedHead Head, c repo.Committed) error {
	// Handlers pass Fiber params, which alias a reused request buffer; the store
	// must own its copies.
	c = cloneCommitted(c)

	s.mu.Lock()
	defer s.mu.Unlock()
	o, ok := s.orgs[c.DID]
	if !ok {
		return ErrNotFound
	}
	if o.head() != expectedHead {
		return ErrHeadChanged
	}
	idx := len(o.commits)
	o.commits = append(o.commits, c)
	key := c.Collection + "/" + c.RKey
	switch c.Op {
	case repo.OpTombstone:
		h := o.heads[key]
		h.tombstone = idx
		o.heads[key] = h
	default:
		o.heads[key] = memHead{record: idx, tombstone: -1}
	}
	return nil
}

func (s *MemoryStore) Current(_ context.Context, org, collection, rkey string) (*Stored, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	o, ok := s.orgs[org]
	if !ok {
		return nil, ErrNotFound
	}
	h, ok := o.heads[collection+"/"+rkey]
	if !ok {
		return nil, ErrNotFound
	}
	st := o.stored(h)
	return &st, nil
}

func (o *memOrg) stored(h memHead) Stored {
	c := o.commits[h.record]
	st := Stored{
		URI:         c.URI(),
		Collection:  c.Collection,
		RKey:        c.RKey,
		Record:      slices.Clone(c.Record),
		Seq:         c.Seq,
		CID:         c.CID,
		Rev:         c.Rev,
		CommittedBy: c.CommittedBy,
		ApprovedBy:  slices.Clone(c.ApprovedBy),
		CommittedAt: c.CommittedAt,
	}
	if h.tombstone >= 0 {
		t := o.commits[h.tombstone]
		st.Tombstone = &Tombstone{At: t.CommittedAt, By: t.CommittedBy, Seq: t.Seq, CID: t.CID}
	}
	return st
}

func (s *MemoryStore) List(_ context.Context, org, collection, afterRKey string, limit int) ([]Stored, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	o, ok := s.orgs[org]
	if !ok {
		return nil, ErrNotFound
	}
	prefix := collection + "/"
	var keys []string
	for k, h := range o.heads {
		if h.tombstone >= 0 || !strings.HasPrefix(k, prefix) {
			continue
		}
		if rkey := strings.TrimPrefix(k, prefix); rkey > afterRKey {
			keys = append(keys, rkey)
		}
	}
	sort.Strings(keys)
	if limit > 0 && len(keys) > limit {
		keys = keys[:limit]
	}
	out := make([]Stored, 0, len(keys))
	for _, k := range keys {
		out = append(out, o.stored(o.heads[prefix+k]))
	}
	return out, nil
}

func (s *MemoryStore) Commits(_ context.Context, org string, afterSeq int64, limit int) ([]repo.Committed, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	o, ok := s.orgs[org]
	if !ok {
		return nil, ErrNotFound
	}
	out := []repo.Committed{}
	for _, c := range o.commits {
		if c.Seq <= afterSeq {
			continue
		}
		out = append(out, cloneCommitted(c))
		if limit > 0 && len(out) >= limit {
			break
		}
	}
	return out, nil
}

// each calls fn with the current state of every live record in collection
// whose parsed body is wanted, in seq order, across the given orgs.
func (o *memOrg) each(collection string, fn func(st Stored, rec map[string]any)) {
	prefix := collection + "/"
	var heads []memHead
	for k, h := range o.heads {
		if h.tombstone >= 0 || !strings.HasPrefix(k, prefix) {
			continue
		}
		heads = append(heads, h)
	}
	sort.Slice(heads, func(i, j int) bool { return heads[i].record < heads[j].record })
	for _, h := range heads {
		st := o.stored(h)
		var rec map[string]any
		if json.Unmarshal(st.Record, &rec) != nil {
			continue
		}
		fn(st, rec)
	}
}

func field(rec map[string]any, path ...string) string {
	var cur any = rec
	for _, p := range path {
		m, ok := cur.(map[string]any)
		if !ok {
			return ""
		}
		cur = m[p]
	}
	s, _ := cur.(string)
	return s
}

func parseTime(s string) (time.Time, bool) {
	t, err := time.Parse(time.RFC3339Nano, s)
	return t, err == nil
}

// memberAt reports whether a membership record's interval contains at.
func memberAt(rec map[string]any, at time.Time) bool {
	joined, ok := parseTime(field(rec, "joinedAt"))
	if !ok || at.Before(joined) {
		return false
	}
	if left, ok := parseTime(field(rec, "leftAt")); ok && !at.Before(left) {
		return false
	}
	return true
}

func (s *MemoryStore) Memberships(_ context.Context, org, tag, vehicle string) ([]Stored, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	o, ok := s.orgs[org]
	if !ok {
		return nil, ErrNotFound
	}
	out := []Stored{}
	o.each("network.dimo.org.tagMembership", func(st Stored, rec map[string]any) {
		if field(rec, "tag") == tag && field(rec, "vehicle") == vehicle {
			out = append(out, st)
		}
	})
	return out, nil
}

func (s *MemoryStore) TagSize(_ context.Context, org, tag string, at time.Time) (int, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	o, ok := s.orgs[org]
	if !ok {
		return 0, ErrNotFound
	}
	vehicles := map[string]bool{}
	o.each("network.dimo.org.tagMembership", func(_ Stored, rec map[string]any) {
		if field(rec, "tag") == tag && memberAt(rec, at) {
			vehicles[field(rec, "vehicle")] = true
		}
	})
	return len(vehicles), nil
}

func (s *MemoryStore) Custody(_ context.Context, org, vehicle, holder string) ([]Stored, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := []Stored{}
	o, ok := s.orgs[org]
	if !ok {
		return out, nil
	}
	o.each("network.dimo.org.custody", func(st Stored, rec map[string]any) {
		if field(rec, "vehicle") == vehicle && field(rec, "holder") == holder {
			out = append(out, st)
		}
	})
	return out, nil
}

func (s *MemoryStore) Roles(_ context.Context, org, member string) ([]Stored, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	o, ok := s.orgs[org]
	if !ok {
		return nil, ErrNotFound
	}
	prefix := "network.dimo.org.role/"
	var heads []memHead
	for k, h := range o.heads {
		if strings.HasPrefix(k, prefix) {
			heads = append(heads, h)
		}
	}
	sort.Slice(heads, func(i, j int) bool { return heads[i].record < heads[j].record })
	out := []Stored{}
	for _, h := range heads {
		st := o.stored(h)
		var rec map[string]any
		if json.Unmarshal(st.Record, &rec) == nil && field(rec, "to") == member {
			out = append(out, st)
		}
	}
	return out, nil
}

func (s *MemoryStore) Exclusives(_ context.Context, vehicle string, at time.Time) ([]Stored, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	tags := map[string]bool{}
	for _, o := range s.orgs {
		o.each("network.dimo.org.tagMembership", func(_ Stored, rec map[string]any) {
			if field(rec, "vehicle") == vehicle && memberAt(rec, at) {
				tags[field(rec, "tag")] = true
			}
		})
	}
	out := []Stored{}
	for _, o := range s.orgs {
		o.each("network.dimo.delegation", func(st Stored, rec map[string]any) {
			if ex, _ := rec["exclusive"].([]any); len(ex) == 0 {
				return
			}
			if field(rec, "covers", "vehicle") == vehicle || tags[field(rec, "covers", "tag")] {
				out = append(out, st)
			}
		})
	}
	return out, nil
}

func (s *MemoryStore) DelegationsOverTag(_ context.Context, org, tag string) ([]Stored, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	o, ok := s.orgs[org]
	if !ok {
		return nil, ErrNotFound
	}
	out := []Stored{}
	o.each("network.dimo.delegation", func(st Stored, rec map[string]any) {
		if field(rec, "covers", "tag") == tag {
			out = append(out, st)
		}
	})
	return out, nil
}

func (s *MemoryStore) DelegationsWithBasis(_ context.Context, uri string) ([]Stored, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	orgs := make([]string, 0, len(s.orgs))
	for did := range s.orgs {
		orgs = append(orgs, did)
	}
	sort.Strings(orgs)
	out := []Stored{}
	for _, did := range orgs {
		s.orgs[did].each("network.dimo.delegation", func(st Stored, rec map[string]any) {
			basis, _ := rec["basis"].([]any)
			if slices.Contains(basis, any(uri)) {
				out = append(out, st)
			}
		})
	}
	return out, nil
}

func (s *MemoryStore) Authored(_ context.Context, org, member string, since time.Time) ([]Stored, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	o, ok := s.orgs[org]
	if !ok {
		return nil, ErrNotFound
	}
	var heads []memHead
	for _, h := range o.heads {
		if h.tombstone < 0 {
			heads = append(heads, h)
		}
	}
	sort.Slice(heads, func(i, j int) bool { return heads[i].record < heads[j].record })
	out := []Stored{}
	for _, h := range heads {
		if st := o.stored(h); st.CommittedBy == member && st.CommittedAt.After(since) {
			out = append(out, st)
		}
	}
	return out, nil
}

func (s *MemoryStore) AddPending(_ context.Context, p Pending) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.orgs[p.Org]; !ok {
		return ErrNotFound
	}
	p.ID, p.Org = strings.Clone(p.ID), strings.Clone(p.Org)
	p.Collection, p.RKey = strings.Clone(p.Collection), strings.Clone(p.RKey)
	p.Record = slices.Clone(p.Record)
	p.CommittedBy = strings.Clone(p.CommittedBy)
	p.Reasons = slices.Clone(p.Reasons)
	if p.CreatedAt.IsZero() {
		p.CreatedAt = time.Now().UTC()
	}
	s.pending[p.Org+"/"+p.ID] = p
	return nil
}

func (s *MemoryStore) GetPending(_ context.Context, org, id string) (*Pending, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	p, ok := s.pending[org+"/"+id]
	if !ok {
		return nil, ErrNotFound
	}
	p.Record = slices.Clone(p.Record)
	p.Reasons = slices.Clone(p.Reasons)
	return &p, nil
}

func (s *MemoryStore) ListPending(_ context.Context, org string) ([]Pending, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if _, ok := s.orgs[org]; !ok {
		return nil, ErrNotFound
	}
	out := []Pending{}
	for _, p := range s.pending {
		if p.Org == org {
			p.Record = slices.Clone(p.Record)
			p.Reasons = slices.Clone(p.Reasons)
			out = append(out, p)
		}
	}
	sort.Slice(out, func(i, j int) bool {
		if !out[i].CreatedAt.Equal(out[j].CreatedAt) {
			return out[i].CreatedAt.Before(out[j].CreatedAt)
		}
		return out[i].ID < out[j].ID
	})
	return out, nil
}

func (s *MemoryStore) DeletePending(_ context.Context, org, id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.pending[org+"/"+id]; !ok {
		return ErrNotFound
	}
	delete(s.pending, org+"/"+id)
	return nil
}

func (s *MemoryStore) SetParty(_ context.Context, p Party) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	p.DID = strings.Clone(p.DID)
	p.Kind = strings.Clone(p.Kind)
	if p.SetAt.IsZero() {
		p.SetAt = time.Now().UTC()
	}
	s.parties[p.DID] = p
	return nil
}

func (s *MemoryStore) GetParty(_ context.Context, did string) (*Party, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	p, ok := s.parties[did]
	if !ok {
		return nil, ErrNotFound
	}
	return &p, nil
}

func (s *MemoryStore) Close() error { return nil }

func cloneCommitted(c repo.Committed) repo.Committed {
	c.DID = strings.Clone(c.DID)
	c.Prev = strings.Clone(c.Prev)
	c.Rev = strings.Clone(c.Rev)
	c.Op = strings.Clone(c.Op)
	c.Collection = strings.Clone(c.Collection)
	c.RKey = strings.Clone(c.RKey)
	c.Record = slices.Clone(c.Record)
	c.CommittedBy = strings.Clone(c.CommittedBy)
	c.ApprovedBy = slices.Clone(c.ApprovedBy)
	c.Sig = strings.Clone(c.Sig)
	c.CID = strings.Clone(c.CID)
	return c
}
