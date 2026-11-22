package store

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func proofStores(t *testing.T) map[string]ProofStore {
	t.Helper()
	out := map[string]ProofStore{"memory": NewMemoryProofs(DefaultMaxProofs)}
	if pg, ok := stores(t)["postgres"]; ok {
		out["postgres"] = pg.(*PostgresStore)
	}
	return out
}

// R5-F6: a DPoP proof is accepted once by every replica sharing the store, and
// R4-F10: one subject can hold only so many live proofs.
func TestProofStore(t *testing.T) {
	for name, ps := range proofStores(t) {
		t.Run(name, func(t *testing.T) {
			ctx := context.Background()
			run := fmt.Sprintf("%d-%d", time.Now().UnixNano(), orgCounter.Add(1))
			now := time.Now().UTC().Truncate(time.Microsecond)
			exp := now.Add(6 * time.Minute)
			p := Proof{JKT: "jkt-" + run, JTI: "jti-1", Subject: "did:dimo:a" + run, Expires: exp}

			require.NoError(t, ps.RecordProof(ctx, p, now, 0))
			assert.ErrorIs(t, ps.RecordProof(ctx, p, now.Add(time.Minute), 0), ErrProofReplayed)
			other := p
			other.JKT = "other-" + run
			assert.NoError(t, ps.RecordProof(ctx, other, now, 0), "the same jti from another key is another proof")

			// Per subject: two live proofs, the third is refused, another subject is not.
			sub := "did:dimo:capped" + run
			for i := range 2 {
				require.NoError(t, ps.RecordProof(ctx, Proof{JKT: "k" + run, JTI: fmt.Sprintf("c%d", i), Subject: sub, Expires: exp}, now, 2))
			}
			assert.ErrorIs(t, ps.RecordProof(ctx, Proof{JKT: "k" + run, JTI: "c2", Subject: sub, Expires: exp}, now, 2), ErrProofLimit)
			assert.NoError(t, ps.RecordProof(ctx, Proof{JKT: "k" + run, JTI: "c2", Subject: sub, Expires: exp}, now, 0), "no limit for an exempt caller")
			assert.NoError(t, ps.RecordProof(ctx, Proof{JKT: "k" + run, JTI: "d0", Subject: "did:dimo:free" + run, Expires: exp}, now, 2))
			assert.NoError(t, ps.RecordProof(ctx, p, exp.Add(time.Second), 0), "once expired, the id may come back")
			// Once its proofs expire the subject has room again.
			assert.NoError(t, ps.RecordProof(ctx, Proof{JKT: "k" + run, JTI: "c3", Subject: sub, Expires: exp.Add(time.Hour)}, exp.Add(time.Second), 2))

			n, err := ps.DeleteExpiredProofs(ctx, exp.Add(time.Second))
			require.NoError(t, err)
			if name == "postgres" {
				// The memory store sweeps itself as it goes; Postgres relies on this.
				assert.GreaterOrEqual(t, n, int64(4))
			}
			assert.NoError(t, ps.RecordProof(ctx, Proof{JKT: "k" + run, JTI: "c0", Subject: sub, Expires: exp.Add(2 * time.Hour)}, exp.Add(2*time.Second), 0), "swept")
		})
	}
}

// The memory store, one process's, is bounded: past its size it refuses new
// proofs with ErrProofsFull until old ones expire.
func TestMemoryProofs_Full(t *testing.T) {
	ctx := context.Background()
	ps := NewMemoryProofs(2)
	now := time.Now()
	exp := now.Add(time.Minute)
	require.NoError(t, ps.RecordProof(ctx, Proof{JKT: "k", JTI: "1", Subject: "a", Expires: exp}, now, 0))
	require.NoError(t, ps.RecordProof(ctx, Proof{JKT: "k", JTI: "2", Subject: "b", Expires: exp}, now, 0))
	assert.ErrorIs(t, ps.RecordProof(ctx, Proof{JKT: "k", JTI: "3", Subject: "c", Expires: exp}, now, 0), ErrProofsFull)
	assert.NoError(t, ps.RecordProof(ctx, Proof{JKT: "k", JTI: "3", Subject: "c", Expires: exp.Add(time.Minute)}, exp.Add(2*time.Second), 0))
}
