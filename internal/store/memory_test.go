package store

import (
	"context"
	"fmt"
	"sync"
	"sync/atomic"
	"testing"
	"unsafe"

	"github.com/DIMO-Network/did-directory/internal/did"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Fiber route params alias a request buffer that is reused after the handler
// returns. The memory store must not retain those bytes.
func TestMemoryStore_AppendCopiesAliasedStrings(t *testing.T) {
	buf := []byte("did:dimo:aaaaaaaaaaaaaaaaaaaaaaaa")
	aliased := unsafe.String(&buf[0], len(buf))

	s := NewMemoryStore()
	require.NoError(t, s.AppendAfter(context.Background(), aliased, "", "cid", &did.Operation{Type: did.OpTypeCreate}))

	copy(buf, "export?after=0&limit=100xxxxxxxxx")

	ok, err := s.Exists(context.Background(), "did:dimo:aaaaaaaaaaaaaaaaaaaaaaaa")
	require.NoError(t, err)
	assert.True(t, ok)
	recs, err := s.Export(context.Background(), 0, 10)
	require.NoError(t, err)
	assert.Equal(t, "did:dimo:aaaaaaaaaaaaaaaaaaaaaaaa", recs[0].DID)
}

// MemoryStore backs local runs (DATABASE_URL unset, ALLOW_MEMORY_STORE=true), and Fiber
// serves every request in its own goroutine. Without a lock `s.seq++` loses
// updates and the concurrent `s.byDID[...] = append(...)` trips Go's
// unrecoverable "fatal error: concurrent map writes", which -race cannot even
// report because it kills the process first.
func TestMemoryStore_ConcurrentAppendsAreSafe(t *testing.T) {
	const writers = 32
	const perWriter = 25

	s := NewMemoryStore()
	ctx := context.Background()
	op := &did.Operation{Type: did.OpTypeCreate}

	var wg sync.WaitGroup
	var appended atomic.Int64
	for w := range writers {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := range perWriter {
				// Every writer owns its own DID, so no append can lose the head race:
				// what is under test here is the shared slice, map and counter.
				didStr := fmt.Sprintf("did:dimo:writer%02d", w)
				head := ""
				if i > 0 {
					head = fmt.Sprintf("cid-%02d-%03d", w, i-1)
				}
				cid := fmt.Sprintf("cid-%02d-%03d", w, i)
				if err := s.AppendAfter(ctx, didStr, head, cid, op); err == nil {
					appended.Add(1)
				}
			}
		}()
	}

	// Readers run alongside, since GetLog and Export walk the same slice.
	var readers sync.WaitGroup
	done := make(chan struct{})
	for range 4 {
		readers.Add(1)
		go func() {
			defer readers.Done()
			for {
				select {
				case <-done:
					return
				default:
					_, _ = s.Export(ctx, 0, 100)
					_, _ = s.GetLog(ctx, "did:dimo:writer00")
					_, _ = s.Exists(ctx, "did:dimo:writer01")
				}
			}
		}()
	}

	wg.Wait()
	close(done)
	readers.Wait()

	total := int64(writers * perWriter)
	assert.Equal(t, total, appended.Load(), "every append should have succeeded")

	all, err := s.Export(ctx, 0, int(total)+1)
	require.NoError(t, err)
	require.Len(t, all, int(total), "a lost update would drop records")

	seen := make(map[int64]bool, len(all))
	for _, rec := range all {
		assert.False(t, seen[rec.Seq], "sequence %d was handed out twice", rec.Seq)
		seen[rec.Seq] = true
	}
}

// handleUpdate reads the head, validates against it, then appends. Two
// concurrent dimo_transfer posts both pass `prev == head` and both append
// distinct CIDs, which UNIQUE(did,cid) does not catch: the DID then resolves to
// two rival eras and the legitimate controller can never grant again.
func TestMemoryStore_AppendAfterIsCompareAndSwap(t *testing.T) {
	ctx := context.Background()
	s := NewMemoryStore()
	op := &did.Operation{Type: did.OpTypeCreate}

	require.NoError(t, s.AppendAfter(ctx, "did:dimo:veh", "", "genesis", op))
	assert.ErrorIs(t, s.AppendAfter(ctx, "did:dimo:veh", "", "genesis-again", op), ErrHeadChanged,
		"a second genesis must not land on a non-empty log")

	require.NoError(t, s.AppendAfter(ctx, "did:dimo:veh", "genesis", "transfer-a", op))
	err := s.AppendAfter(ctx, "did:dimo:veh", "genesis", "transfer-b", op)
	assert.ErrorIs(t, err, ErrHeadChanged, "the second writer read a head that has moved")
	assert.True(t, IsHeadChanged(err))

	log, err := s.GetLog(ctx, "did:dimo:veh")
	require.NoError(t, err)
	require.Len(t, log, 2, "only one of the rival transfers may be stored")
}

// Only one of many racing writers may extend the same head.
func TestMemoryStore_ConcurrentAppendAfterElectsOneWinner(t *testing.T) {
	ctx := context.Background()
	s := NewMemoryStore()
	op := &did.Operation{Type: did.OpTypeCreate}
	require.NoError(t, s.AppendAfter(ctx, "did:dimo:veh", "", "genesis", op))

	var wg sync.WaitGroup
	var won atomic.Int64
	for i := range 16 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if err := s.AppendAfter(ctx, "did:dimo:veh", "genesis", fmt.Sprintf("rival-%02d", i), op); err == nil {
				won.Add(1)
			}
		}()
	}
	wg.Wait()

	assert.Equal(t, int64(1), won.Load(), "exactly one writer may extend the head")
	log, err := s.GetLog(ctx, "did:dimo:veh")
	require.NoError(t, err)
	assert.Len(t, log, 2)
}
