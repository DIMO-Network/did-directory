package store

import (
	"context"
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
	mu   sync.RWMutex
	orgs map[string]*memOrg
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
	return &MemoryStore{orgs: map[string]*memOrg{}}
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
