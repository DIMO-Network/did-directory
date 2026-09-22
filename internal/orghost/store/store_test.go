package store

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/DIMO-Network/did-directory/pkg/repo"
	"github.com/rs/zerolog"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func stores(t *testing.T) map[string]Store {
	t.Helper()
	out := map[string]Store{"memory": NewMemoryStore()}
	if url := os.Getenv(TestDatabaseURLEnv); url != "" {
		pg, err := NewPostgresStore(context.Background(), url, zerolog.Nop())
		require.NoError(t, err)
		t.Cleanup(func() { _ = pg.Close() })
		out["postgres"] = pg
	}
	return out
}

var orgCounter atomic.Int64

// newOrg registers a fresh org so cases never see each other's rows, even on
// a Postgres database that keeps them between runs.
func newOrg(t *testing.T, s Store) string {
	t.Helper()
	did := fmt.Sprintf("did:dimo:test%d-%d", time.Now().UnixNano(), orgCounter.Add(1))
	require.NoError(t, s.CreateOrg(context.Background(), Org{DID: did, KeyEnc: []byte("sealed")}))
	return did
}

// commit builds an unsigned commit after head. The store does not check
// signatures, so none is needed here; the repository layer signs.
func commit(org string, head Head, op, coll, rkey, record, by string) repo.Committed {
	c := repo.Committed{Commit: repo.Commit{
		DID: org, Seq: head.Seq + 1, Prev: head.CID, Rev: repo.NewTID(), Op: op,
		Collection: coll, RKey: rkey, CommittedBy: by,
		CommittedAt: time.Now().UTC().Truncate(time.Microsecond),
		Sig:         "sig",
	}}
	if record != "" {
		c.Record = json.RawMessage(record)
	}
	c.CID, _ = c.Commit.CID()
	return c
}

func TestStore_Orgs(t *testing.T) {
	for name, s := range stores(t) {
		t.Run(name, func(t *testing.T) {
			ctx := context.Background()
			did := newOrg(t, s)

			org, err := s.GetOrg(ctx, did)
			require.NoError(t, err)
			assert.Equal(t, did, org.DID)
			assert.Equal(t, []byte("sealed"), org.KeyEnc)
			assert.False(t, org.CreatedAt.IsZero())

			assert.ErrorIs(t, s.CreateOrg(ctx, Org{DID: did, KeyEnc: []byte("other")}), ErrOrgExists)
			_, err = s.GetOrg(ctx, "did:dimo:nobody")
			assert.True(t, IsNotFound(err))
			_, err = s.Head(ctx, "did:dimo:nobody")
			assert.True(t, IsNotFound(err))
			_, err = s.Commits(ctx, "did:dimo:nobody", 0, 10)
			assert.True(t, IsNotFound(err))
			_, err = s.List(ctx, "did:dimo:nobody", "c", "", 10)
			assert.True(t, IsNotFound(err))

			head, err := s.Head(ctx, did)
			require.NoError(t, err)
			assert.Equal(t, Head{}, head)
		})
	}
}

func TestStore_Log(t *testing.T) {
	for name, s := range stores(t) {
		t.Run(name, func(t *testing.T) {
			ctx := context.Background()
			did := newOrg(t, s)
			const coll = "network.dimo.org.tag"

			head, _ := s.Head(ctx, did)
			c1 := commit(did, head, repo.OpCreate, coll, "fleet", `{"name":"Fleet"}`, "did:dimo:alice")
			require.NoError(t, s.AppendAfter(ctx, head, c1))

			// The head moved; the same expected head is refused.
			c1b := commit(did, head, repo.OpCreate, coll, "other", `{"name":"Other"}`, "")
			assert.True(t, IsHeadChanged(s.AppendAfter(ctx, head, c1b)))

			head, err := s.Head(ctx, did)
			require.NoError(t, err)
			assert.Equal(t, Head{Seq: 1, CID: c1.CID, Rev: c1.Rev}, head)

			cur, err := s.Current(ctx, did, coll, "fleet")
			require.NoError(t, err)
			assert.Equal(t, "at://"+did+"/"+coll+"/fleet", cur.URI)
			assert.JSONEq(t, `{"name":"Fleet"}`, string(cur.Record))
			assert.Equal(t, int64(1), cur.Seq)
			assert.Equal(t, c1.CID, cur.CID)
			assert.Equal(t, "did:dimo:alice", cur.CommittedBy)
			assert.Equal(t, c1.CommittedAt, cur.CommittedAt)
			assert.Nil(t, cur.ApprovedBy)
			assert.True(t, cur.Live())

			// Update replaces the body and moves the record's seq.
			c2 := commit(did, head, repo.OpUpdate, coll, "fleet", `{"description":"All","name":"Fleet"}`, "did:dimo:alice")
			c2.ApprovedBy = []string{"did:dimo:bob"}
			c2.CID, _ = c2.Commit.CID()
			require.NoError(t, s.AppendAfter(ctx, head, c2))
			head, _ = s.Head(ctx, did)
			cur, err = s.Current(ctx, did, coll, "fleet")
			require.NoError(t, err)
			assert.Equal(t, int64(2), cur.Seq)
			assert.JSONEq(t, `{"description":"All","name":"Fleet"}`, string(cur.Record))
			assert.Equal(t, []string{"did:dimo:bob"}, cur.ApprovedBy)

			// A second record, then list.
			c3 := commit(did, head, repo.OpCreate, coll, "airport", `{"name":"Airport"}`, "")
			require.NoError(t, s.AppendAfter(ctx, head, c3))
			head, _ = s.Head(ctx, did)
			list, err := s.List(ctx, did, coll, "", 10)
			require.NoError(t, err)
			require.Len(t, list, 2)
			assert.Equal(t, "airport", list[0].RKey)
			assert.Equal(t, "fleet", list[1].RKey)
			list, err = s.List(ctx, did, coll, "airport", 10)
			require.NoError(t, err)
			require.Len(t, list, 1)
			assert.Equal(t, "fleet", list[0].RKey)
			list, err = s.List(ctx, did, coll, "", 1)
			require.NoError(t, err)
			require.Len(t, list, 1)
			list, err = s.List(ctx, did, "network.dimo.delegation", "", 10)
			require.NoError(t, err)
			assert.Empty(t, list)

			// Tombstone: the record keeps its body but leaves the listing.
			c4 := commit(did, head, repo.OpTombstone, coll, "fleet", "", "did:dimo:bob")
			require.NoError(t, s.AppendAfter(ctx, head, c4))
			head, _ = s.Head(ctx, did)
			cur, err = s.Current(ctx, did, coll, "fleet")
			require.NoError(t, err)
			assert.False(t, cur.Live())
			assert.Equal(t, int64(2), cur.Seq)
			assert.JSONEq(t, `{"description":"All","name":"Fleet"}`, string(cur.Record))
			require.NotNil(t, cur.Tombstone)
			assert.Equal(t, Tombstone{At: c4.CommittedAt, By: "did:dimo:bob", Seq: 4, CID: c4.CID}, *cur.Tombstone)
			list, err = s.List(ctx, did, coll, "", 10)
			require.NoError(t, err)
			require.Len(t, list, 1)
			assert.Equal(t, "airport", list[0].RKey)

			// Re-create after a tombstone clears it.
			c5 := commit(did, head, repo.OpCreate, coll, "fleet", `{"name":"Fleet again"}`, "")
			require.NoError(t, s.AppendAfter(ctx, head, c5))
			cur, err = s.Current(ctx, did, coll, "fleet")
			require.NoError(t, err)
			assert.True(t, cur.Live())
			assert.Equal(t, int64(5), cur.Seq)

			_, err = s.Current(ctx, did, coll, "missing")
			assert.True(t, IsNotFound(err))

			// The log comes back whole, in order, byte for byte.
			log, err := s.Commits(ctx, did, 0, 100)
			require.NoError(t, err)
			require.Len(t, log, 5)
			for i, want := range []repo.Committed{c1, c2, c3, c4, c5} {
				assert.Equal(t, want, log[i], "seq %d", i+1)
			}
			log, err = s.Commits(ctx, did, 3, 1)
			require.NoError(t, err)
			require.Len(t, log, 1)
			assert.Equal(t, int64(4), log[0].Seq)

			// Appending to an org that does not exist is refused.
			ghost := commit("did:dimo:ghost", Head{}, repo.OpCreate, coll, "x", `{}`, "")
			assert.True(t, IsNotFound(s.AppendAfter(ctx, Head{}, ghost)))
		})
	}
}

// Concurrent writers to one org must each end up with a distinct seq and an
// unbroken prev chain, whichever store is underneath.
func TestStore_ConcurrentAppendsKeepOneChain(t *testing.T) {
	for name, s := range stores(t) {
		t.Run(name, func(t *testing.T) {
			ctx := context.Background()
			did := newOrg(t, s)
			const writers, perWriter = 8, 20

			var wg sync.WaitGroup
			for w := range writers {
				wg.Add(1)
				go func() {
					defer wg.Done()
					for i := range perWriter {
						rkey := fmt.Sprintf("w%d-%d", w, i)
						for {
							head, err := s.Head(ctx, did)
							require.NoError(t, err)
							c := commit(did, head, repo.OpCreate, "network.dimo.org.tag", rkey, `{"name":"x"}`, "")
							err = s.AppendAfter(ctx, head, c)
							if IsHeadChanged(err) {
								continue
							}
							require.NoError(t, err)
							break
						}
					}
				}()
			}
			wg.Wait()

			log, err := s.Commits(ctx, did, 0, 0)
			require.NoError(t, err)
			require.Len(t, log, writers*perWriter)
			prev := ""
			for i, c := range log {
				assert.Equal(t, int64(i+1), c.Seq)
				assert.Equal(t, prev, c.Prev)
				prev = c.CID
			}
			list, err := s.List(ctx, did, "network.dimo.org.tag", "", 0)
			require.NoError(t, err)
			assert.Len(t, list, writers*perWriter)
		})
	}
}
