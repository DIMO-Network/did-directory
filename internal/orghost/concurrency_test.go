package orghost

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"

	"github.com/DIMO-Network/did-directory/internal/orghost/store"
	"github.com/DIMO-Network/did-directory/pkg/delegation"
	"github.com/DIMO-Network/did-directory/pkg/repo"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// A write's checks and its commit happen under the org's write lock, against
// the head the commit follows, so concurrent writes are judged one after the
// other rather than all against the state before any of them.

// send is do for goroutines: no require, and a token minted beforehand.
func (h *host) send(method, path, token string, body any) (int, map[string]any, error) {
	data, err := json.Marshal(body)
	if err != nil {
		return 0, nil, err
	}
	req := httptest.NewRequest(method, path, bytes.NewReader(data))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+token)
	resp, err := h.app.Test(req, -1)
	if err != nil {
		return 0, nil, err
	}
	defer func() { _ = resp.Body.Close() }()
	raw, err := io.ReadAll(resp.Body)
	if err != nil {
		return 0, nil, err
	}
	var out map[string]any
	_ = json.Unmarshal(raw, &out)
	return resp.StatusCode, out, nil
}

// race runs n requests at once and returns their statuses.
func race(t *testing.T, n int, do func(i int) (int, map[string]any, error)) []int {
	t.Helper()
	statuses := make([]int, n)
	var wg sync.WaitGroup
	start := make(chan struct{})
	for i := range n {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			status, _, err := do(i)
			if err != nil {
				t.Error(err)
			}
			statuses[i] = status
		}()
	}
	close(start)
	wg.Wait()
	return statuses
}

func count(statuses []int, want int) int {
	n := 0
	for _, s := range statuses {
		if s == want {
			n++
		}
	}
	return n
}

// Approving is claiming: of many approvers at once, one commits the write and
// the rest find nothing left to approve.
func TestConcurrentApprovalsCommitOnce(t *testing.T) {
	for name, st := range stores(t) {
		t.Run(name, func(t *testing.T) {
			a := newAvis(t, st)
			lien := a.grant(fordCredit, delegation.Covers{Tag: a.tag["financed-fc"]}, "location:precise")
			lien.RevocableBy = delegation.RevocableByTo
			status, body := a.do(http.MethodPut, a.path(delegation.CollectionDelegation, "lien"), bob, lien)
			require.Equal(t, http.StatusAccepted, status, body)
			path := "/orgs/" + a.org + "/pending/" + body["pending"].(string) + "/approve"
			token := a.issuer.identity(t, carol)

			statuses := race(t, 20, func(int) (int, map[string]any, error) { return a.send(http.MethodPost, path, token, nil) })
			assert.Equal(t, 1, count(statuses, http.StatusCreated), "%v", statuses)
			assert.Equal(t, 19, count(statuses, http.StatusNotFound), "%v", statuses)

			status, body = a.do(http.MethodGet, "/orgs/"+a.org+"/commits", a.org, nil)
			require.Equal(t, http.StatusOK, status, body)
			lienCommits := 0
			for _, c := range body["commits"].([]any) {
				if c.(map[string]any)["rkey"] == "lien" {
					lienCommits++
				}
			}
			assert.Equal(t, 1, lienCommits)
		})
	}
}

// The approval threshold counts the tag as it stands when each membership
// commits. Judged against the state before any of them, every one of several
// concurrent additions saw room under the threshold and committed.
func TestConcurrentMembershipsRespectTheThreshold(t *testing.T) {
	for name, st := range stores(t) {
		t.Run(name, func(t *testing.T) {
			a := newAvis(t, st)
			a.clock = day(1)
			fl := delegation.Covers{Tag: a.tag["fl-fleet"]}
			status, body := a.do(http.MethodPut, a.path(delegation.CollectionDelegation, "insurer"), alice, a.grant(insurer, fl, "telemetry:read"))
			require.Equal(t, http.StatusCreated, status, body)
			status, body = a.do(http.MethodPost, a.path(delegation.CollectionTagMembership, ""), alice, a.join("fl-fleet", a.cars[0], day(1)))
			require.Equal(t, http.StatusCreated, status, body)

			// The threshold is two vehicles: one more fits, the rest need approval.
			var cars []string
			for i := range 7 {
				car := a.org + "-extra" + string(rune('a'+i))
				a.control(car, a.org)
				cars = append(cars, car)
			}
			token := a.issuer.identity(t, alice)
			path := a.path(delegation.CollectionTagMembership, "")
			statuses := race(t, len(cars), func(i int) (int, map[string]any, error) {
				return a.send(http.MethodPost, path, token, a.join("fl-fleet", cars[i], day(1)))
			})
			assert.Equal(t, 1, count(statuses, http.StatusCreated), "%v", statuses)
			assert.Equal(t, len(cars)-1, count(statuses, http.StatusAccepted), "%v", statuses)
		})
	}
}

// revoke-authored-by is one reviewed batch: DeleteAll appends every tombstone
// together, and a check that fails for any of them writes none.
func TestDeleteAllIsOneAppend(t *testing.T) {
	for name, st := range stores(t) {
		t.Run(name, func(t *testing.T) {
			a := newAvis(t, st)
			var keys []Key
			for _, rkey := range []string{"t1", "t2", "t3"} {
				status, body := a.do(http.MethodPut, a.path(delegation.CollectionTag, rkey), a.org, map[string]any{"name": rkey})
				require.Equal(t, http.StatusCreated, status, body)
				keys = append(keys, Key{Collection: delegation.CollectionTag, RKey: rkey})
			}
			before, err := st.Head(t.Context(), a.org)
			require.NoError(t, err)

			_, err = a.repo.DeleteAll(t.Context(), a.org, keys, "", func(_ context.Context, curs []*store.Stored) error {
				require.Len(t, curs, 3)
				return ErrForbidden
			})
			require.ErrorIs(t, err, ErrForbidden)
			after, err := st.Head(t.Context(), a.org)
			require.NoError(t, err)
			assert.Equal(t, before, after, "nothing was written")

			res, err := a.repo.DeleteAll(t.Context(), a.org, keys, "", nil)
			require.NoError(t, err)
			require.Len(t, res, 3)
			for i, r := range res {
				assert.Equal(t, before.Seq+int64(i)+1, r.Seq)
				assert.Equal(t, "tombstone", r.Op)
			}
			commits, err := st.Commits(t.Context(), a.org, 0, 0)
			require.NoError(t, err)
			key, err := a.repo.Signer.PublicKey(t.Context(), a.org)
			require.NoError(t, err)
			_, err = repo.VerifyLog(a.org, commits, key)
			require.NoError(t, err, "the batch chains like any other commits")
		})
	}
}
