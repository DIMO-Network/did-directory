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

// append commits a record after the org's current head.
func appendRecord(t *testing.T, s Store, org, op, coll, rkey, record, by string) repo.Committed {
	t.Helper()
	ctx := context.Background()
	head, err := s.Head(ctx, org)
	require.NoError(t, err)
	c := commit(org, head, op, coll, rkey, record, by)
	require.NoError(t, s.AppendAfter(ctx, head, c))
	return c
}

// The resolver queries read the current view: live records only, except roles,
// found by the fields the evaluator asks by, across repositories where the
// evaluator does not say which one.
func TestStore_ResolverQueries(t *testing.T) {
	for name, s := range stores(t) {
		t.Run(name, func(t *testing.T) {
			ctx := context.Background()
			org, other := newOrg(t, s), newOrg(t, s)
			tag := "at://" + org + "/network.dimo.org.tag/fleet"
			// Custody and exclusives are read across repositories, so the vehicles
			// and holder are minted per run or a persistent database would answer
			// with an earlier run's rows.
			car, van, renter := org+"-car", org+"-van", org+"-renter"
			const alice = "did:dimo:alice"
			const memberships, custody, roles, delegations = "network.dimo.org.tagMembership", "network.dimo.org.custody", "network.dimo.org.role", "network.dimo.delegation"
			day := func(d int) string { return fmt.Sprintf("2026-01-%02dT00:00:00Z", d) }

			// Two intervals for the car, one for the van that ended, and one for
			// the car that was tombstoned.
			appendRecord(t, s, org, repo.OpCreate, memberships, "m1", `{"tag":"`+tag+`","vehicle":"`+car+`","joinedAt":"`+day(1)+`","leftAt":"`+day(5)+`"}`, alice)
			appendRecord(t, s, org, repo.OpCreate, memberships, "m2", `{"tag":"`+tag+`","vehicle":"`+car+`","joinedAt":"`+day(10)+`"}`, "")
			appendRecord(t, s, org, repo.OpCreate, memberships, "m3", `{"tag":"`+tag+`","vehicle":"`+van+`","joinedAt":"`+day(1)+`","leftAt":"`+day(3)+`"}`, "")
			appendRecord(t, s, org, repo.OpCreate, memberships, "m4", `{"tag":"`+tag+`","vehicle":"`+car+`","joinedAt":"`+day(6)+`","leftAt":"`+day(7)+`"}`, "")
			appendRecord(t, s, org, repo.OpTombstone, memberships, "m4", "", "")

			ms, err := s.Memberships(ctx, org, tag, car)
			require.NoError(t, err)
			require.Len(t, ms, 2)
			assert.Equal(t, "m1", ms[0].RKey)
			assert.Equal(t, alice, ms[0].CommittedBy)
			assert.Equal(t, "m2", ms[1].RKey)
			ms, err = s.Memberships(ctx, org, tag, "did:dimo:nobody")
			require.NoError(t, err)
			assert.Empty(t, ms)
			_, err = s.Memberships(ctx, "did:dimo:nowhere", tag, car)
			assert.True(t, IsNotFound(err))

			at := func(d int) time.Time { return time.Date(2026, 1, d, 0, 0, 0, 0, time.UTC) }
			for d, want := range map[int]int{1: 2, 3: 1, 5: 0, 6: 0, 12: 1} {
				n, err := s.TagSize(ctx, org, tag, at(d))
				require.NoError(t, err)
				assert.Equal(t, want, n, "day %d", d)
			}

			// Custody is found by vehicle and holder within one repository.
			appendRecord(t, s, org, repo.OpCreate, custody, "c1", `{"vehicle":"`+car+`","holder":"`+renter+`","from":"`+day(10)+`","until":"`+day(12)+`"}`, alice)
			appendRecord(t, s, other, repo.OpCreate, custody, "c2", `{"vehicle":"`+car+`","holder":"`+renter+`","from":"`+day(20)+`"}`, "")
			appendRecord(t, s, org, repo.OpCreate, custody, "c3", `{"vehicle":"`+van+`","holder":"`+renter+`","from":"`+day(10)+`"}`, "")
			appendRecord(t, s, org, repo.OpCreate, custody, "c4", `{"vehicle":"`+car+`","holder":"`+renter+`","from":"`+day(1)+`","until":"`+day(2)+`"}`, "")
			appendRecord(t, s, org, repo.OpTombstone, custody, "c4", "", "")
			cs, err := s.Custody(ctx, org, car, renter)
			require.NoError(t, err)
			require.Len(t, cs, 1)
			assert.Equal(t, "c1", cs[0].RKey)
			cs, err = s.Custody(ctx, other, car, renter)
			require.NoError(t, err)
			require.Len(t, cs, 1)
			assert.Equal(t, "c2", cs[0].RKey)

			// Roles come back tombstoned or not; the evaluator reads the tombstone.
			role := func(to string) string {
				return `{"@type":"Set","assigner":"` + org + `","assignee":"` + to + `","permission":[{"target":"` + tag + `","@type":"AssetCollection","action":["dimo:tag.write"]}],"dcterms:issued":"` + day(1) + `"}`
			}
			appendRecord(t, s, org, repo.OpCreate, roles, "r1", role(alice), "")
			appendRecord(t, s, org, repo.OpCreate, roles, "r2", role(alice), "")
			appendRecord(t, s, org, repo.OpTombstone, roles, "r2", "", "")
			appendRecord(t, s, org, repo.OpCreate, roles, "r3", role("did:dimo:bob"), "")
			rs, err := s.Roles(ctx, org, alice)
			require.NoError(t, err)
			require.Len(t, rs, 2)
			assert.True(t, rs[0].Live())
			assert.False(t, rs[1].Live())
			rs, err = s.Roles(ctx, other, alice)
			require.NoError(t, err)
			assert.Empty(t, rs)

			// Exclusives: over the car directly, over a tag the car is in at the
			// time, from any repository; not a record without an exclusive claim,
			// not a tombstoned one, not one over a tag the car has left.
			grant := func(target, exclusive string) string {
				return `{"@type":"Agreement","assigner":"` + org + `","assignee":"` + renter + `","permission":[{"target":"` + target + `","action":["dimo:command.unlock"]}]` + exclusive + `,"dcterms:issued":"` + day(1) + `"}`
			}
			appendRecord(t, s, org, repo.OpCreate, delegations, "g1", grant(car, `,"dimo:exclusive":["dimo:command.unlock"]`), "")
			appendRecord(t, s, org, repo.OpCreate, delegations, "g2", grant(car, ``), "")
			appendRecord(t, s, org, repo.OpCreate, delegations, "g3", grant(car, `,"dimo:exclusive":["dimo:command.unlock"]`), "")
			appendRecord(t, s, org, repo.OpTombstone, delegations, "g3", "", "")
			appendRecord(t, s, org, repo.OpCreate, delegations, "g4", grant(tag, `,"dimo:exclusive":["dimo:command.unlock"]`), "")
			appendRecord(t, s, other, repo.OpCreate, delegations, "g5", grant(car, `,"dimo:exclusive":["dimo:command.unlock"]`), "")
			appendRecord(t, s, org, repo.OpCreate, delegations, "g6", grant(van, `,"dimo:exclusive":["dimo:command.unlock"]`), "")
			keys := func(sts []Stored) []string {
				out := []string{}
				for _, st := range sts {
					out = append(out, st.RKey)
				}
				return out
			}
			ex, err := s.Exclusives(ctx, car, at(12))
			require.NoError(t, err)
			assert.ElementsMatch(t, []string{"g1", "g4", "g5"}, keys(ex))
			ex, err = s.Exclusives(ctx, car, at(8))
			require.NoError(t, err)
			assert.ElementsMatch(t, []string{"g1", "g5"}, keys(ex), "the car was out of the tag on day 8")

			// Parties.
			_, err = s.GetParty(ctx, org)
			assert.True(t, IsNotFound(err))
			require.NoError(t, s.SetParty(ctx, Party{DID: org, Kind: KindOrg}))
			require.NoError(t, s.SetParty(ctx, Party{DID: org, Kind: KindOrg, Operator: true}))
			p, err := s.GetParty(ctx, org)
			require.NoError(t, err)
			assert.Equal(t, KindOrg, p.Kind)
			assert.True(t, p.Operator)
			assert.False(t, p.SetAt.IsZero())
		})
	}
}

func TestStore_AuthoredAndDelegationsOver(t *testing.T) {
	for name, s := range stores(t) {
		t.Run(name, func(t *testing.T) {
			ctx := context.Background()
			did := newOrg(t, s)
			tag := "at://" + did + "/network.dimo.org.tag/fleet"
			before := time.Now().UTC().Add(-time.Second)

			head, _ := s.Head(ctx, did)
			c1 := commit(did, head, repo.OpCreate, "network.dimo.delegation", "a", `{"permission":[{"target":"`+tag+`"}],"assignee":"did:dimo:x"}`, "did:dimo:alice")
			require.NoError(t, s.AppendAfter(ctx, head, c1))
			head, _ = s.Head(ctx, did)
			c2 := commit(did, head, repo.OpCreate, "network.dimo.delegation", "b", `{"permission":[{"target":"did:dimo:v"}],"assignee":"did:dimo:y"}`, "did:dimo:alice")
			require.NoError(t, s.AppendAfter(ctx, head, c2))
			head, _ = s.Head(ctx, did)
			c3 := commit(did, head, repo.OpCreate, "network.dimo.org.tag", "fleet", `{"name":"Fleet"}`, "did:dimo:bob")
			require.NoError(t, s.AppendAfter(ctx, head, c3))
			// Bob updates a, so its current version is his.
			head, _ = s.Head(ctx, did)
			c4 := commit(did, head, repo.OpUpdate, "network.dimo.delegation", "a", `{"permission":[{"target":"`+tag+`"}],"assignee":"did:dimo:z"}`, "did:dimo:bob")
			require.NoError(t, s.AppendAfter(ctx, head, c4))

			over, err := s.DelegationsOver(ctx, did, tag)
			require.NoError(t, err)
			require.Len(t, over, 1)
			assert.Equal(t, "a", over[0].RKey)
			assert.Equal(t, "did:dimo:bob", over[0].CommittedBy)
			over, err = s.DelegationsOver(ctx, did, "at://"+did+"/network.dimo.org.tag/other")
			require.NoError(t, err)
			assert.Empty(t, over)
			_, err = s.DelegationsOver(ctx, "did:dimo:nobody", tag)
			assert.True(t, IsNotFound(err))

			byAlice, err := s.Authored(ctx, did, "did:dimo:alice", before)
			require.NoError(t, err)
			require.Len(t, byAlice, 1, "a is now bob's version")
			assert.Equal(t, "b", byAlice[0].RKey)
			byBob, err := s.Authored(ctx, did, "did:dimo:bob", before)
			require.NoError(t, err)
			assert.Len(t, byBob, 2)
			byBob, err = s.Authored(ctx, did, "did:dimo:bob", time.Now().UTC().Add(time.Hour))
			require.NoError(t, err)
			assert.Empty(t, byBob)

			// Tombstoned records are not authored anything any more.
			head, _ = s.Head(ctx, did)
			c5 := commit(did, head, repo.OpTombstone, "network.dimo.delegation", "b", "", "")
			require.NoError(t, s.AppendAfter(ctx, head, c5))
			byAlice, err = s.Authored(ctx, did, "did:dimo:alice", before)
			require.NoError(t, err)
			assert.Empty(t, byAlice)
		})
	}
}

func TestStore_Pending(t *testing.T) {
	for name, s := range stores(t) {
		t.Run(name, func(t *testing.T) {
			ctx := context.Background()
			did := newOrg(t, s)

			assert.True(t, IsNotFound(s.AddPending(ctx, Pending{ID: "p0", Org: "did:dimo:nobody", Record: []byte(`{}`)})))
			_, err := s.ListPending(ctx, "did:dimo:nobody")
			assert.True(t, IsNotFound(err))

			at := time.Now().UTC().Truncate(time.Microsecond)
			p1 := Pending{ID: "p1", Org: did, Collection: "network.dimo.delegation", RKey: "a", Record: []byte(`{"x":1}`),
				CommittedBy: "did:dimo:alice", Reasons: []string{"grants live ability command:unlock"}, CreatedAt: at}
			p2 := Pending{ID: "p2", Org: did, Collection: "network.dimo.org.tagMembership", RKey: "b", Record: []byte(`{"y":2}`),
				CommittedBy: "", Reasons: []string{"tag would cover 501 vehicles"}, CreatedAt: at.Add(time.Second)}
			require.NoError(t, s.AddPending(ctx, p2))
			require.NoError(t, s.AddPending(ctx, p1))

			got, err := s.GetPending(ctx, did, "p1")
			require.NoError(t, err)
			assert.Equal(t, p1, *got)
			_, err = s.GetPending(ctx, did, "p3")
			assert.True(t, IsNotFound(err))

			list, err := s.ListPending(ctx, did)
			require.NoError(t, err)
			require.Len(t, list, 2)
			assert.Equal(t, "p1", list[0].ID, "oldest first")
			assert.Equal(t, "p2", list[1].ID)

			require.NoError(t, s.DeletePending(ctx, did, "p1"))
			assert.True(t, IsNotFound(s.DeletePending(ctx, did, "p1")))
			list, err = s.ListPending(ctx, did)
			require.NoError(t, err)
			require.Len(t, list, 1)
			assert.Equal(t, "p2", list[0].ID)
		})
	}
}

func TestStore_DelegationsWithBasis(t *testing.T) {
	for name, s := range stores(t) {
		t.Run(name, func(t *testing.T) {
			ctx := context.Background()
			owner := newOrg(t, s)
			dealer := newOrg(t, s)
			root := "at://" + owner + "/network.dimo.delegation/consent"
			delegations := "network.dimo.delegation"

			head, _ := s.Head(ctx, owner)
			require.NoError(t, s.AppendAfter(ctx, head, commit(owner, head, repo.OpCreate, delegations, "consent", `{"dimo:basis":[],"assignee":"`+dealer+`"}`, "")))
			// Two descendants in the dealer's repository, one of them later
			// tombstoned; a record with another basis; a role naming the root.
			head, _ = s.Head(ctx, dealer)
			require.NoError(t, s.AppendAfter(ctx, head, commit(dealer, head, repo.OpCreate, delegations, "a", `{"dimo:basis":["`+root+`"],"assignee":"did:dimo:x"}`, "")))
			head, _ = s.Head(ctx, dealer)
			require.NoError(t, s.AppendAfter(ctx, head, commit(dealer, head, repo.OpCreate, delegations, "b", `{"dimo:basis":["at://did:dimo:other/network.dimo.delegation/k","`+root+`"],"assignee":"did:dimo:y"}`, "")))
			head, _ = s.Head(ctx, dealer)
			require.NoError(t, s.AppendAfter(ctx, head, commit(dealer, head, repo.OpCreate, delegations, "c", `{"dimo:basis":["`+root+`"],"assignee":"did:dimo:z"}`, "")))
			head, _ = s.Head(ctx, dealer)
			require.NoError(t, s.AppendAfter(ctx, head, commit(dealer, head, repo.OpTombstone, delegations, "c", "", "")))
			head, _ = s.Head(ctx, dealer)
			require.NoError(t, s.AppendAfter(ctx, head, commit(dealer, head, repo.OpCreate, delegations, "d", `{"dimo:basis":["at://did:dimo:other/network.dimo.delegation/k"],"assignee":"did:dimo:w"}`, "")))
			head, _ = s.Head(ctx, dealer)
			require.NoError(t, s.AppendAfter(ctx, head, commit(dealer, head, repo.OpCreate, "network.dimo.org.role", "r", `{"dimo:basis":["`+root+`"],"assignee":"did:dimo:v"}`, "")))

			got, err := s.DelegationsWithBasis(ctx, root)
			require.NoError(t, err)
			keys := []string{}
			for _, st := range got {
				keys = append(keys, st.RKey)
			}
			assert.ElementsMatch(t, []string{"a", "b"}, keys)
			for _, st := range got {
				assert.Equal(t, "at://"+dealer+"/"+delegations+"/"+st.RKey, st.URI)
			}
			got, err = s.DelegationsWithBasis(ctx, "at://"+owner+"/network.dimo.delegation/nothing")
			require.NoError(t, err)
			assert.Empty(t, got)
		})
	}
}

func TestStore_Assigned(t *testing.T) {
	for name, s := range stores(t) {
		t.Run(name, func(t *testing.T) {
			ctx := context.Background()
			a, b := newOrg(t, s), newOrg(t, s)
			member := a + "-member"
			roles, delegations := "network.dimo.org.role", "network.dimo.delegation"
			add := func(org, op, coll, rkey, record string) {
				t.Helper()
				head, err := s.Head(ctx, org)
				require.NoError(t, err)
				require.NoError(t, s.AppendAfter(ctx, head, commit(org, head, op, coll, rkey, record, "")))
			}
			add(a, repo.OpCreate, roles, "r1", `{"assignee":"`+member+`"}`)
			add(a, repo.OpCreate, roles, "r2", `{"assignee":"did:dimo:someone"}`)
			add(b, repo.OpCreate, roles, "r3", `{"assignee":"`+member+`"}`)
			add(b, repo.OpTombstone, roles, "r3", "")
			add(b, repo.OpCreate, delegations, "d1", `{"assignee":"`+member+`"}`)

			got, err := s.Assigned(ctx, roles, member)
			require.NoError(t, err)
			uris := []string{}
			for _, st := range got {
				uris = append(uris, st.URI)
			}
			assert.ElementsMatch(t, []string{"at://" + a + "/" + roles + "/r1", "at://" + b + "/" + roles + "/r3"}, uris,
				"both repositories, tombstones included")
			for _, st := range got {
				assert.Equal(t, st.RKey == "r3", !st.Live())
			}

			got, err = s.Assigned(ctx, delegations, member)
			require.NoError(t, err)
			require.Len(t, got, 1)
			assert.Equal(t, "d1", got[0].RKey)

			got, err = s.Assigned(ctx, roles, "did:dimo:nobody")
			require.NoError(t, err)
			assert.Empty(t, got)
		})
	}
}

func TestStore_VehicleTags(t *testing.T) {
	for name, s := range stores(t) {
		t.Run(name, func(t *testing.T) {
			ctx := context.Background()
			org := newOrg(t, s)
			car := org + "-car"
			tag := func(slug string) string { return "at://" + org + "/network.dimo.org.tag/" + slug }
			memberships := "network.dimo.org.tagMembership"
			add := func(op, rkey, record string) {
				t.Helper()
				head, err := s.Head(ctx, org)
				require.NoError(t, err)
				require.NoError(t, s.AppendAfter(ctx, head, commit(org, head, op, memberships, rkey, record, "")))
			}
			add(repo.OpCreate, "m1", `{"tag":"`+tag("fleet")+`","vehicle":"`+car+`","joinedAt":"2026-01-01T00:00:00Z"}`)
			// Ended, but still a membership the car had.
			add(repo.OpCreate, "m2", `{"tag":"`+tag("alpha")+`","vehicle":"`+car+`","joinedAt":"2026-01-01T00:00:00Z","leftAt":"2026-01-02T00:00:00Z"}`)
			add(repo.OpCreate, "m3", `{"tag":"`+tag("fleet")+`","vehicle":"`+car+`","joinedAt":"2026-02-01T00:00:00Z"}`)
			add(repo.OpCreate, "m4", `{"tag":"`+tag("gone")+`","vehicle":"`+car+`","joinedAt":"2026-01-01T00:00:00Z"}`)
			add(repo.OpTombstone, "m4", "")
			add(repo.OpCreate, "m5", `{"tag":"`+tag("other")+`","vehicle":"`+org+`-other-car","joinedAt":"2026-01-01T00:00:00Z"}`)

			got, err := s.VehicleTags(ctx, org, car)
			require.NoError(t, err)
			assert.Equal(t, []string{tag("alpha"), tag("fleet")}, got)
			got, err = s.VehicleTags(ctx, org, org+"-no-car")
			require.NoError(t, err)
			assert.Empty(t, got)
			_, err = s.VehicleTags(ctx, "did:dimo:nobody", car)
			assert.True(t, IsNotFound(err))

			got, err = s.TagVehicles(ctx, org, tag("fleet"))
			require.NoError(t, err)
			assert.Equal(t, []string{car}, got, "two memberships, one car")
			got, err = s.TagVehicles(ctx, org, tag("alpha"))
			require.NoError(t, err)
			assert.Equal(t, []string{car}, got, "an ended membership still counts")
			got, err = s.TagVehicles(ctx, org, tag("gone"))
			require.NoError(t, err)
			assert.Empty(t, got, "a tombstoned membership does not")
			_, err = s.TagVehicles(ctx, "did:dimo:nobody", tag("fleet"))
			assert.True(t, IsNotFound(err))
		})
	}
}
