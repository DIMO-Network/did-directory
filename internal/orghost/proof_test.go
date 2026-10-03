package orghost

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"slices"
	"testing"

	"github.com/DIMO-Network/did-directory/internal/orghost/store"
	"github.com/DIMO-Network/did-directory/pkg/agreement"
	"github.com/DIMO-Network/did-directory/pkg/delegation"
	"github.com/DIMO-Network/did-directory/pkg/odrl"
	"github.com/DIMO-Network/did-directory/pkg/proof"
	"github.com/DIMO-Network/did-directory/pkg/repo"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// get sends a GET as the given DID and returns the raw body, for responses
// that are decoded into a type rather than read as a map.
func (h *host) get(path, as string) (int, []byte) {
	h.t.Helper()
	req := httptest.NewRequest(http.MethodGet, path, nil)
	if as != "" {
		req.Header.Set("Authorization", "Bearer "+h.issuer.identity(h.t, as))
	}
	resp, err := h.app.Test(req, -1)
	require.NoError(h.t, err)
	defer func() { _ = resp.Body.Close() }()
	raw, err := io.ReadAll(resp.Body)
	require.NoError(h.t, err)
	return resp.StatusCode, raw
}

func (h *host) proof(uri, vehicle, as string) (int, *proof.Proof, map[string]any) {
	h.t.Helper()
	org, _, rkey, err := delegation.ParseURI(uri)
	require.NoError(h.t, err)
	status, raw := h.get("/orgs/"+org+"/delegations/"+rkey+"/proof?vehicle="+vehicle, as)
	if status != http.StatusOK {
		var body map[string]any
		_ = json.Unmarshal(raw, &body)
		return status, nil, body
	}
	var p proof.Proof
	require.NoError(h.t, json.Unmarshal(raw, &p))
	return status, &p, nil
}

func rkeys(commits []repo.Committed) []string {
	out := []string{}
	for _, c := range commits {
		out = append(out, c.Op+" "+c.Collection+"/"+c.RKey)
	}
	return out
}

// TestCoverageProofVerifiesWithTheHostDown is plan §6 step 6's test: the
// renter fetches a proof of their history grant, the host goes away, and the
// proof still verifies, against the bundle alone and against the directory's
// key and era log. The chain runs through a member-authored grant, a custody
// period and a control opening, so the bundle carries the booking service's
// role, the custody record and the opening beside the grant itself.
func TestCoverageProofVerifiesWithTheHostDown(t *testing.T) {
	for name, st := range stores(t) {
		t.Run(name, func(t *testing.T) {
			h := newHost(t, st)
			org := newOrgDID()
			car := carOf(org)
			h.fleet(org)

			h.clock = day(9)
			driving := rental(org)
			h.commitGrants(org, h.compile(&driving, day(11)))
			h.clock = day(13)
			status, body := h.do(http.MethodPost, "/orgs/"+org+"/"+delegation.CollectionCustody, backend,
				delegation.CustodyPeriod{Vehicle: car, Holder: renter, From: day(10), Until: tp(day(12))})
			require.Equal(t, http.StatusCreated, status, body)
			returned := rental(org)
			returned.Custody = []agreement.Custody{{Start: day(10), End: tp(day(12))}}
			returned.State = agreement.StateReturned
			h.commitGrants(org, h.compile(&returned, day(13)))
			historyURI := "at://" + org + "/" + delegation.TypeDelegation + "/bk-1:rental:history"

			status, body = h.do(http.MethodGet, "/orgs/"+org, org, nil)
			require.Equal(t, http.StatusOK, status, body)
			orgKey := body["key"].(string)

			h.clock = day(20)
			status, p, body := h.proof(historyURI, car, renter)
			require.Equal(t, http.StatusOK, status, body)
			assert.Equal(t, historyURI, p.Delegation)
			assert.Equal(t, car, p.Vehicle)
			assert.True(t, p.At.Equal(day(20)))
			assert.Equal(t, map[string]string{org: orgKey}, p.Keys)
			assert.Equal(t, car, p.Control.DID)
			assert.Equal(t, proof.Party{Kind: proof.KindOrg, Operator: true}, p.Parties[org])
			got := rkeys(p.Commits)
			assert.Contains(t, got, "update "+delegation.CollectionDelegation+"/bk-1:rental:history", "the grant, as recompiled after return")
			assert.Contains(t, got, "create "+delegation.CollectionVehicleControl+"/"+car, "the opening, so the root can be checked")
			assert.Contains(t, got, "create "+delegation.CollectionRole+"/"+roleKey(t, p.Commits, backend), "the booking service's role, which authored the grant")
			assert.True(t, slices.ContainsFunc(p.Commits, func(c repo.Committed) bool {
				return c.Collection == delegation.CollectionCustody
			}), "the custody period the grant is narrowed to")
			assert.False(t, slices.ContainsFunc(p.Commits, func(c repo.Committed) bool {
				return c.RKey == "valet" || c.Collection == delegation.CollectionTag
			}), "nothing the evaluation did not read")

			// The host goes away.
			require.NoError(t, h.app.Shutdown())

			cov, err := proof.Verify(t.Context(), p, proof.Anchors{})
			require.NoError(t, err)
			w := cov.Historical["telemetry:read"]
			assert.True(t, w.Contains(day(11)), "the day they drove")
			assert.False(t, w.Contains(day(14)), "after they handed the car back")
			assert.Equal(t, []string{historyURI}, cov.Chain)

			// Against what the directory publishes, not what the host said.
			anchors := proof.Anchors{Keys: map[string]string{org: orgKey}, Control: h.directory.states[car]}
			_, err = proof.Verify(t.Context(), p, anchors)
			require.NoError(t, err)

			// Without the custody record the renter never had the car, and the
			// grant covers nothing: the claim no longer follows from the records.
			p.Commits = slices.DeleteFunc(p.Commits, func(c repo.Committed) bool {
				return c.Collection == delegation.CollectionCustody
			})
			_, err = proof.Verify(t.Context(), p, anchors)
			assert.ErrorIs(t, err, delegation.ErrNotCovered)
		})
	}
}

// roleKey finds the rkey of the role issued to member among the commits.
func roleKey(t *testing.T, commits []repo.Committed, member string) string {
	t.Helper()
	for _, c := range commits {
		if c.Collection != delegation.CollectionRole {
			continue
		}
		rec, err := odrl.Decode(c.Record)
		require.NoError(t, err)
		if rec.To == member {
			return c.RKey
		}
	}
	t.Fatalf("no role for %s in the proof", member)
	return ""
}

// A proof of a live grant carries the exclusive claims in force too, since
// the evaluation read them, and a proof is only served for what the grant
// actually gives; a refusal answers as /authorize does.
func TestCoverageProofOfLiveGrant(t *testing.T) {
	h := newHost(t, store.NewMemoryStore())
	org := newOrgDID()
	car := carOf(org)
	h.fleet(org)
	h.clock = day(9)
	driving := rental(org)
	h.commitGrants(org, h.compile(&driving, day(11)))
	custodyURI := "at://" + org + "/" + delegation.TypeDelegation + "/bk-1:rental:custody"

	h.clock = day(11)
	status, p, body := h.proof(custodyURI, car, renter)
	require.Equal(t, http.StatusOK, status, body)
	assert.Contains(t, p.Coverage.Live, "command:unlock")
	assert.True(t, slices.ContainsFunc(p.Commits, func(c repo.Committed) bool {
		return c.RKey == "bk-1:rental:custody"
	}), "the exclusive claim the evaluation read is the grant itself")
	cov, err := proof.Verify(t.Context(), p, proof.Anchors{})
	require.NoError(t, err)
	assert.Equal(t, p.Coverage.Live, cov.Live)

	status, _, body = h.proof(custodyURI, "did:dimo:car2", renter)
	require.Equal(t, http.StatusForbidden, status, body)
	assert.Equal(t, CodeNotCovered, body["code"])
	h.clock = day(16)
	status, _, body = h.proof(custodyURI, car, renter)
	require.Equal(t, http.StatusForbidden, status, body)
	assert.Equal(t, CodeNotValid, body["code"])
}

// The recipient and the org may fetch a proof; nobody else may, and the route
// takes a vehicle and a delegation that exists.
func TestCoverageProofAccess(t *testing.T) {
	h := newHost(t, store.NewMemoryStore())
	org := newOrgDID()
	car := carOf(org)
	h.fleet(org)
	h.clock = day(9)
	driving := rental(org)
	h.commitGrants(org, h.compile(&driving, day(11)))
	custodyURI := "at://" + org + "/" + delegation.TypeDelegation + "/bk-1:rental:custody"
	path := "/orgs/" + org + "/delegations/bk-1:rental:custody/proof"

	h.clock = day(11)
	status, _, body := h.proof(custodyURI, car, org)
	assert.Equal(t, http.StatusOK, status, body)
	status, _, body = h.proof(custodyURI, car, valet)
	assert.Equal(t, http.StatusNotFound, status, body, "as if there were no such grant")
	status, _, body = h.proof(custodyURI, car, backend)
	assert.Equal(t, http.StatusNotFound, status, body, "authoring a grant is not holding it")
	status, _ = h.get(path+"?vehicle="+car, "")
	assert.Equal(t, http.StatusUnauthorized, status)
	status, _ = h.get(path, renter)
	assert.Equal(t, http.StatusBadRequest, status)
	status, _ = h.get("/orgs/"+org+"/delegations/nothing/proof?vehicle="+car, renter)
	assert.Equal(t, http.StatusNotFound, status)
}

// TestDescendants is the consent transparency view (spec §9.3, §13.2): an
// owner consents to a dealer with an allowlist, the dealer shares onward, and
// the owner sees every party with access to their car through the consent,
// with the chain resolved per vehicle, including the record the dealer wrote
// to somebody the allowlist does not name. Revoking the consent cuts them all.
func TestDescendants(t *testing.T) {
	for name, st := range stores(t) {
		t.Run(name, func(t *testing.T) {
			h := newHost(t, st)
			base := newOrgDID()
			owner, dealer, lender, analytics, integrator := base+"-owner", base+"-dealer", base+"-lender", base+"-analytics", base+"-integrator"
			car := base + "-car"
			h.clock = day(1)

			for _, did := range []string{owner, dealer, lender} {
				status, body := h.do(http.MethodPost, "/orgs/"+did, did, nil)
				require.Equal(t, http.StatusCreated, status, body)
			}
			status, body := h.do(http.MethodPut, "/parties/"+owner, dimoDID, map[string]any{"kind": "person"})
			require.Equal(t, http.StatusOK, status, body)
			status, body = h.do(http.MethodPut, "/parties/"+dealer, dimoDID, map[string]any{"kind": "org", "operator": true})
			require.Equal(t, http.StatusOK, status, body)
			h.control(car, owner)

			grant := func(from, to string, basis []string, covers delegation.Covers, redelegate delegation.Redelegate, abilities ...string) delegation.Record {
				return delegation.Record{
					Type: delegation.TypeDelegation, From: from, To: to, Basis: basis, Covers: covers, Abilities: abilities,
					DataWindow: delegation.Window{From: tp(day(1))}, Validity: delegation.Window{From: tp(day(1))},
					Redelegate: redelegate, CreatedAt: day(1),
				}
			}
			put := func(org, rkey string, rec delegation.Record) string {
				t.Helper()
				status, body := h.do(http.MethodPut, "/orgs/"+org+"/"+delegation.CollectionDelegation+"/"+rkey, org, rec)
				require.Equal(t, http.StatusCreated, status, body)
				return body["uri"].(string)
			}
			consent := put(owner, "consent", grant(owner, dealer, nil, delegation.Covers{Vehicle: car},
				delegation.Redelegate{Mode: delegation.RedelegateAllowlist, Grantees: []string{lender, analytics}},
				"telemetry:read", "health:read"))
			toLender := put(dealer, "lender", grant(dealer, lender, []string{consent}, delegation.Covers{Inherit: true},
				delegation.Redelegate{Mode: delegation.RedelegateAllowlist, Grantees: []string{analytics}}, "health:read"))
			toIntegrator := put(dealer, "integrator", grant(dealer, integrator, []string{consent}, delegation.Covers{Inherit: true},
				delegation.Redelegate{Mode: delegation.RedelegateNone}, "telemetry:read"))
			toAnalytics := put(lender, "analytics", grant(lender, analytics, []string{toLender}, delegation.Covers{Inherit: true},
				delegation.Redelegate{Mode: delegation.RedelegateNone}, "health:read"))

			path := "/orgs/" + owner + "/delegations/consent/descendants"
			h.clock = day(2)
			status, body = h.do(http.MethodGet, path+"?vehicle="+car, owner, nil)
			require.Equal(t, http.StatusOK, status, body)
			assert.Equal(t, consent, body["root"])
			list := body["descendants"].([]any)
			require.Len(t, list, 3)
			byURI := map[string]map[string]any{}
			for _, d := range list {
				d := d.(map[string]any)
				byURI[d["uri"].(string)] = d
			}

			d := byURI[toLender]
			require.NotNil(t, d)
			assert.Equal(t, float64(2), d["depth"])
			assert.Equal(t, lender, d["to"])
			assert.Nil(t, d["refused"])
			assert.True(t, window(t, d["coverage"].(map[string]any), "health:read").Contains(day(2)))
			assert.Equal(t, []any{toLender, consent}, d["coverage"].(map[string]any)["chain"])

			d = byURI[toAnalytics]
			require.NotNil(t, d)
			assert.Equal(t, float64(3), d["depth"], "the lender's onward share, one hop further")
			assert.Equal(t, []any{toAnalytics, toLender, consent}, d["coverage"].(map[string]any)["chain"])

			d = byURI[toIntegrator]
			require.NotNil(t, d)
			assert.Equal(t, CodeNotNarrowing, d["refused"], "the integrator is not on the owner's allowlist")
			assert.Nil(t, d["coverage"])

			// Another car of the owner's is not in any of these. The integrator's
			// record fails to narrow before any car is looked at.
			refusals := func(body map[string]any) map[string]any {
				out := map[string]any{}
				for _, d := range body["descendants"].([]any) {
					d := d.(map[string]any)
					out[d["uri"].(string)] = d["refused"]
				}
				return out
			}
			status, body = h.do(http.MethodGet, path+"?vehicle="+car+"2", owner, nil)
			require.Equal(t, http.StatusOK, status, body)
			assert.Equal(t, map[string]any{toLender: CodeNotCovered, toAnalytics: CodeNotCovered, toIntegrator: CodeNotNarrowing}, refusals(body))

			// The recipient sees the same list: what it passed on, and what
			// others wrote naming its grant. Nobody further down sees the root's.
			status, body = h.do(http.MethodGet, path+"?vehicle="+car, dealer, nil)
			require.Equal(t, http.StatusOK, status, body)
			assert.Len(t, body["descendants"], 3)
			status, body = h.do(http.MethodGet, path+"?vehicle="+car, lender, nil)
			assert.Equal(t, http.StatusNotFound, status, body)
			// The lender, recipient of the dealer's grant, sees below that one.
			status, body = h.do(http.MethodGet, "/orgs/"+dealer+"/delegations/lender/descendants?vehicle="+car, lender, nil)
			require.Equal(t, http.StatusOK, status, body)
			assert.Equal(t, map[string]any{toAnalytics: nil}, refusals(body))
			status, body = h.do(http.MethodGet, "/orgs/"+dealer+"/delegations/lender/descendants?vehicle="+car, analytics, nil)
			assert.Equal(t, http.StatusNotFound, status, body)

			// It takes a vehicle and a real record.
			status, body = h.do(http.MethodGet, path, owner, nil)
			assert.Equal(t, http.StatusBadRequest, status, body)
			status, body = h.do(http.MethodGet, "/orgs/"+owner+"/delegations/nothing/descendants?vehicle="+car, owner, nil)
			assert.Equal(t, http.StatusNotFound, status, body)

			// Owner revocation cuts the dealer and every descendant in one step.
			h.clock = day(3)
			status, body = h.do(http.MethodDelete, "/orgs/"+owner+"/"+delegation.CollectionDelegation+"/consent", owner, nil)
			require.Equal(t, http.StatusOK, status, body)
			status, body = h.do(http.MethodGet, path+"?vehicle="+car, owner, nil)
			require.Equal(t, http.StatusOK, status, body)
			require.Len(t, body["descendants"].([]any), 3, "the records still exist, and the owner still sees them")
			assert.Equal(t, map[string]any{toLender: CodeRevoked, toAnalytics: CodeRevoked, toIntegrator: CodeNotNarrowing}, refusals(body))
		})
	}
}
