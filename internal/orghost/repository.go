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

// Put creates or updates the record at collection/rkey in org's repository,
// as a write by committedBy ("" for the org itself), approved by approvedBy.
// record is Prepare's output.
func (r *Repository) Put(ctx context.Context, org, collection, rkey string, record json.RawMessage, committedBy string, approvedBy []string) (*Result, error) {
	return r.append(ctx, org, collection, rkey, func(cur *store.Stored) (string, json.RawMessage, error) {
		if cur != nil && cur.Live() {
			return repo.OpUpdate, record, nil
		}
		return repo.OpCreate, record, nil
	}, committedBy, approvedBy)
}

// Delete tombstones the record at collection/rkey as a write by committedBy.
func (r *Repository) Delete(ctx context.Context, org, collection, rkey, committedBy string, approvedBy []string) (*Result, error) {
	if err := delegation.ValidateRKey(rkey); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrInvalid, err)
	}
	return r.append(ctx, org, collection, rkey, func(cur *store.Stored) (string, json.RawMessage, error) {
		if cur == nil {
			return "", nil, store.ErrNotFound
		}
		if !cur.Live() {
			return "", nil, ErrNotLive
		}
		return repo.OpTombstone, nil, nil
	}, committedBy, approvedBy)
}

// append builds a commit against the current head and record state, signs it
// and appends it; if the head moves underneath it, it decides again.
func (r *Repository) append(ctx context.Context, org, collection, rkey string,
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
		if err != nil && !store.IsNotFound(err) {
			return nil, err
		}
		op, record, err := decide(cur)
		if err != nil {
			return nil, err
		}
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
		if c.CID, err = c.Commit.CID(); err != nil {
			return nil, err
		}
		err = r.Store.AppendAfter(ctx, head, c)
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
