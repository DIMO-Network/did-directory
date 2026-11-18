package orghost

import (
	"context"
	"crypto/ecdsa"
	"encoding/json"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/DIMO-Network/did-directory/internal/orghost/store"
	"github.com/DIMO-Network/did-directory/pkg/delegation"
	"github.com/DIMO-Network/did-directory/pkg/repo"
)

// Write errors, distinguished so the HTTP layer can pick a status.
var (
	// ErrInvalid is a structural problem with the write.
	ErrInvalid = errors.New("invalid write")
	// ErrNotLive is a tombstone of something that is not live.
	ErrNotLive = errors.New("record is not live")
	// ErrContended is an append that lost the head race too many times.
	ErrContended = errors.New("repository is contended, retry")
)

// appendAttempts is how many times a write re-reads the head after losing the
// race for it. Writers in this process queue on a per-org lock, so a loss
// means another host instance committed; each loss is that instance's success.
const appendAttempts = 8

// Repository is the write and read path over one host's org repositories.
// Every write becomes a commit signed by the org's key and appended after the
// head the write was decided against.
type Repository struct {
	Store  store.Store
	Signer repo.Signer
	// Now is the host clock; nil means time.Now.
	Now func() time.Time

	// locks serialises writers to one org within this process. The store's head
	// check is what keeps the chain correct; the lock is what keeps it fair, since
	// a signature and a round trip per attempt is enough for optimistic retries
	// to starve under a burst.
	locks sync.Map // org DID -> *sync.Mutex
}

func (r *Repository) lock(org string) *sync.Mutex {
	mu, _ := r.locks.LoadOrStore(org, &sync.Mutex{})
	return mu.(*sync.Mutex)
}

// Register puts org on this host. When key is nil the signer generates one.
// It returns the did:key to publish as the org's #dimo_org.
func (r *Repository) Register(ctx context.Context, org string, key *ecdsa.PrivateKey) (string, error) {
	local, ok := r.Signer.(*LocalSigner)
	if !ok {
		return "", errors.New("this signer does not register orgs")
	}
	return local.Register(ctx, org, key)
}

// Result is what a write returns.
type Result struct {
	URI string `json:"uri"`
	CID string `json:"cid"`
	Rev string `json:"rev"`
	Seq int64  `json:"seq"`
	Op  string `json:"op"`
}

// Prepare canonicalises body and checks it structurally as a write of
// collection/rkey to org's repository by committedBy ("" for the org itself).
// What it returns is what Put commits, once the role checks have passed.
func (r *Repository) Prepare(org, collection, rkey string, body []byte, committedBy string) (json.RawMessage, error) {
	record, err := repo.CanonicalRecord(body)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrInvalid, err)
	}
	if err := checkRecord(org, collection, rkey, record, committedBy); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrInvalid, err)
	}
	return record, nil
}

// Check is a write's authority check, run under the org's write lock against
// the record's current state (nil when nothing was ever committed under the
// key), after the head the commit will follow was read. A check that passes is
// therefore about the repository the commit lands in: if another writer moves
// the head before the append, the append fails, and the write reads and checks
// again. Without this a check and its commit could straddle another write, so
// two memberships could each see a tag under its approval threshold, or a
// role tombstoned in between could still authorize a write.
type Check func(ctx context.Context, cur *store.Stored) error

// Put creates or updates the record at collection/rkey in org's repository,
// as a write by committedBy ("" for the org itself), approved by approvedBy.
// record is Prepare's output; check, when not nil, must pass first.
func (r *Repository) Put(ctx context.Context, org, collection, rkey string, record json.RawMessage, committedBy string, approvedBy []string, check Check) (*Result, error) {
	return r.append(ctx, org, collection, rkey, check, func(cur *store.Stored) (string, json.RawMessage, error) {
		if cur != nil && cur.Live() {
			return repo.OpUpdate, record, nil
		}
		return repo.OpCreate, record, nil
	}, committedBy, approvedBy)
}

// Delete tombstones the record at collection/rkey as a write by committedBy,
// once check, when not nil, passes.
func (r *Repository) Delete(ctx context.Context, org, collection, rkey, committedBy string, approvedBy []string, check Check) (*Result, error) {
	if err := delegation.ValidateRKey(rkey); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrInvalid, err)
	}
	return r.append(ctx, org, collection, rkey, check, tombstoneOp, committedBy, approvedBy)
}

func tombstoneOp(cur *store.Stored) (string, json.RawMessage, error) {
	if cur == nil {
		return "", nil, store.ErrNotFound
	}
	if !cur.Live() {
		return "", nil, ErrNotLive
	}
	return repo.OpTombstone, nil, nil
}

// Key names one record in a repository.
type Key struct{ Collection, RKey string }

// DeleteAll tombstones every key that is still live, as one append: every
// tombstone commits or none does. check sees the current state of each key,
// in order, under the org's write lock; keys already tombstoned are skipped,
// since the outcome is the one asked for.
func (r *Repository) DeleteAll(ctx context.Context, org string, keys []Key, committedBy string, check func(ctx context.Context, curs []*store.Stored) error) ([]*Result, error) {
	for _, k := range keys {
		if err := delegation.ValidateRKey(k.RKey); err != nil {
			return nil, fmt.Errorf("%w: %v", ErrInvalid, err)
		}
	}
	mu := r.lock(org)
	mu.Lock()
	defer mu.Unlock()
	for range appendAttempts {
		head, err := r.Store.Head(ctx, org)
		if err != nil {
			return nil, err
		}
		var live []Key
		var curs []*store.Stored
		for _, k := range keys {
			cur, err := r.Store.Current(ctx, org, k.Collection, k.RKey)
			if err != nil {
				return nil, err
			}
			if cur.Live() {
				live = append(live, k)
				curs = append(curs, cur)
			}
		}
		if check != nil {
			if err := check(ctx, curs); err != nil {
				return nil, err
			}
		}
		prev := head
		commits := make([]repo.Committed, 0, len(live))
		for _, k := range live {
			c, err := r.commit(ctx, org, prev, repo.OpTombstone, k.Collection, k.RKey, nil, committedBy, nil)
			if err != nil {
				return nil, err
			}
			commits = append(commits, *c)
			prev = store.Head{Seq: c.Seq, CID: c.CID, Rev: c.Rev}
		}
		if len(commits) == 0 {
			return []*Result{}, nil
		}
		err = r.Store.AppendAfter(ctx, head, commits...)
		if store.IsHeadChanged(err) {
			continue
		}
		if err != nil {
			return nil, err
		}
		out := make([]*Result, len(commits))
		for i := range commits {
			c := &commits[i]
			out[i] = &Result{URI: c.URI(), CID: c.CID, Rev: c.Rev, Seq: c.Seq, Op: c.Op}
		}
		return out, nil
	}
	return nil, ErrContended
}

// append builds a commit against the current head and record state, checks
// it, signs it and appends it; if the head moves underneath it, it reads,
// checks and decides again.
func (r *Repository) append(ctx context.Context, org, collection, rkey string, check Check,
	decide func(cur *store.Stored) (string, json.RawMessage, error), committedBy string, approvedBy []string) (*Result, error) {
	mu := r.lock(org)
	mu.Lock()
	defer mu.Unlock()
	for range appendAttempts {
		head, err := r.Store.Head(ctx, org)
		if err != nil {
			return nil, err
		}
		cur, err := r.Store.Current(ctx, org, collection, rkey)
		if store.IsNotFound(err) {
			cur, err = nil, nil
		}
		if err != nil {
			return nil, err
		}
		if check != nil {
			if err := check(ctx, cur); err != nil {
				return nil, err
			}
		}
		op, record, err := decide(cur)
		if err != nil {
			return nil, err
		}
		c, err := r.commit(ctx, org, head, op, collection, rkey, record, committedBy, approvedBy)
		if err != nil {
			return nil, err
		}
		err = r.Store.AppendAfter(ctx, head, *c)
		if store.IsHeadChanged(err) {
			continue
		}
		if err != nil {
			return nil, err
		}
		return &Result{URI: c.URI(), CID: c.CID, Rev: c.Rev, Seq: c.Seq, Op: c.Op}, nil
	}
	return nil, ErrContended
}

// commit builds and signs the commit that follows head.
func (r *Repository) commit(ctx context.Context, org string, head store.Head, op, collection, rkey string, record json.RawMessage, committedBy string, approvedBy []string) (*repo.Committed, error) {
	c := repo.Committed{Commit: repo.Commit{
		DID:         org,
		Seq:         head.Seq + 1,
		Prev:        head.CID,
		Rev:         repo.NewTID(),
		Op:          op,
		Collection:  collection,
		RKey:        rkey,
		Record:      record,
		CommittedBy: committedBy,
		ApprovedBy:  approvedBy,
		CommittedAt: r.now(),
	}}
	if err := repo.Sign(ctx, r.Signer, &c.Commit); err != nil {
		return nil, fmt.Errorf("sign commit: %w", err)
	}
	cid, err := c.Commit.CID()
	if err != nil {
		return nil, err
	}
	c.CID = cid
	return &c, nil
}

// now returns the host clock at the precision a commit carries: UTC, whole
// microseconds, so the signed timestamp is the one a timestamptz gives back.
func (r *Repository) now() time.Time {
	now := time.Now
	if r.Now != nil {
		now = r.Now
	}
	return now().UTC().Truncate(time.Microsecond)
}

// Get returns the current state of a record, tombstoned or not.
func (r *Repository) Get(ctx context.Context, org, collection, rkey string) (*store.Stored, error) {
	return r.Store.Current(ctx, org, collection, rkey)
}

// List returns live records in a collection after afterRKey.
func (r *Repository) List(ctx context.Context, org, collection, afterRKey string, limit int) ([]store.Stored, error) {
	return r.Store.List(ctx, org, collection, afterRKey, limit)
}

// Log returns commits after afterSeq.
func (r *Repository) Log(ctx context.Context, org string, afterSeq int64, limit int) ([]repo.Committed, error) {
	return r.Store.Commits(ctx, org, afterSeq, limit)
}
