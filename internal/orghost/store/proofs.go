package store

import (
	"context"
	"errors"
	"sync"
	"time"
)

// Proof is one accepted DPoP proof: the key that signed it, its id, the
// subject of the token it was presented with, and when it can no longer be
// presented. A proof is accepted once; the host remembers it until Expires.
type Proof struct {
	JKT     string
	JTI     string
	Subject string
	Expires time.Time
}

var (
	// ErrProofReplayed is a proof already accepted and not yet expired.
	ErrProofReplayed = errors.New("DPoP proof already used")
	// ErrProofLimit is a subject already holding as many live proofs as it may.
	ErrProofLimit = errors.New("too many live DPoP proofs for this caller")
	// ErrProofsFull is a bounded store holding as many live proofs as it may.
	ErrProofsFull = errors.New("DPoP proof store is full")
)

// ProofStore remembers accepted DPoP proofs, so a captured request cannot be
// replayed inside its proof's window. The Postgres store shares them across
// every replica on the database; the memory one is one process's.
type ProofStore interface {
	// RecordProof records p, accepted at now. It returns ErrProofReplayed if
	// the same key's proof with the same id is recorded and unexpired, and,
	// when perSubject is above zero, ErrProofLimit if p's subject already holds
	// perSubject unexpired proofs: one caller cannot crowd out the others.
	RecordProof(ctx context.Context, p Proof, now time.Time, perSubject int) error
	// DeleteExpiredProofs drops the proofs expired at now and says how many.
	DeleteExpiredProofs(ctx context.Context, now time.Time) (int64, error)
}

// DefaultMaxProofs bounds a MemoryProofs: about 157 MiB at a million entries.
const DefaultMaxProofs = 1_000_000

// MemoryProofs is a ProofStore for one process, bounded at max live proofs.
type MemoryProofs struct {
	max int

	mu        sync.Mutex
	seen      map[proofKey]memProof
	bySubject map[string]int
	// sweepAt is when expired entries are next dropped; swept when they last were.
	sweepAt, swept time.Time
}

type proofKey struct{ jkt, jti string }

type memProof struct {
	subject string
	expires time.Time
}

// NewMemoryProofs returns an empty store holding at most max live proofs; zero
// or less means DefaultMaxProofs.
func NewMemoryProofs(max int) *MemoryProofs {
	if max <= 0 {
		max = DefaultMaxProofs
	}
	return &MemoryProofs{max: max, seen: map[proofKey]memProof{}, bySubject: map[string]int{}}
}

func (m *MemoryProofs) RecordProof(_ context.Context, p Proof, now time.Time, perSubject int) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if !now.Before(m.sweepAt) {
		m.sweep(now)
	}
	k := proofKey{p.JKT, p.JTI}
	if e, ok := m.seen[k]; ok {
		if now.Before(e.expires) {
			return ErrProofReplayed
		}
		m.drop(k, e)
	}
	// The periodic sweep may be a minute stale, so sweep before refusing, but
	// at most once a second: a store walked on every request would hand a
	// flood a CPU lever.
	if perSubject > 0 && m.bySubject[p.Subject] >= perSubject {
		m.sweepSoon(now)
		if m.bySubject[p.Subject] >= perSubject {
			return ErrProofLimit
		}
	}
	if len(m.seen) >= m.max {
		m.sweepSoon(now)
		if len(m.seen) >= m.max {
			return ErrProofsFull
		}
	}
	m.seen[k] = memProof{subject: p.Subject, expires: p.Expires}
	m.bySubject[p.Subject]++
	return nil
}

func (m *MemoryProofs) DeleteExpiredProofs(_ context.Context, now time.Time) (int64, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.sweep(now), nil
}

func (m *MemoryProofs) sweepSoon(now time.Time) {
	if now.Sub(m.swept) >= time.Second {
		m.sweep(now)
	}
}

func (m *MemoryProofs) sweep(now time.Time) int64 {
	var n int64
	for k, e := range m.seen {
		if !now.Before(e.expires) {
			m.drop(k, e)
			n++
		}
	}
	m.sweepAt, m.swept = now.Add(time.Minute), now
	return n
}

func (m *MemoryProofs) drop(k proofKey, e memProof) {
	delete(m.seen, k)
	if m.bySubject[e.subject]--; m.bySubject[e.subject] <= 0 {
		delete(m.bySubject, e.subject)
	}
}
