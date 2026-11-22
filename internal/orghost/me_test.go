package orghost

import (
	"net/http"
	"strings"
	"testing"

	"github.com/DIMO-Network/did-directory/pkg/delegation"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestMyRoles(t *testing.T) {
	for name, st := range stores(t) {
		t.Run(name, func(t *testing.T) {
			h := newHost(t, st)
			base := newOrgDID()
			kept, dropped, demoted := base+"-kept", base+"-dropped", base+"-demoted"
			member, other := base+"-member", base+"-other"
			for _, did := range []string{kept, dropped, demoted} {
				h.publish(did)
				status, body := h.do(http.MethodPost, "/orgs/"+did, did, nil)
				require.Equal(t, http.StatusCreated, status, body)
			}

			held := h.grantRole(kept, roleRecord(kept, member, delegation.Covers{Inherit: true}, delegation.AbilityOrgAdmin))
			h.grantRole(kept, roleRecord(kept, other, delegation.Covers{Inherit: true}, delegation.AbilityOrgAdmin))
			// A role the org has since revoked.
			gone := h.grantRole(dropped, roleRecord(dropped, member, delegation.Covers{Inherit: true}, delegation.AbilityOrgAdmin))
			status, body := h.do(http.MethodDelete, "/orgs/"+dropped+"/"+delegation.CollectionRole+"/"+gone[strings.LastIndex(gone, "/")+1:], dropped, nil)
			require.Equal(t, http.StatusOK, status, body)
			// A role in a repository whose DID DIMO later records as a person,
			// who cannot have members.
			h.grantRole(demoted, roleRecord(demoted, member, delegation.Covers{Inherit: true}, delegation.AbilityOrgAdmin))
			status, body = h.do(http.MethodPut, "/parties/"+demoted, dimoDID, map[string]any{"kind": "person"})
			require.Equal(t, http.StatusOK, status, body)

			status, body = h.do(http.MethodGet, "/me/roles", member, nil)
			require.Equal(t, http.StatusOK, status, body)
			roles := body["roles"].([]any)
			require.Len(t, roles, 1, "only the live role in an org that can have members")
			role := roles[0].(map[string]any)
			assert.Equal(t, kept, role["org"])
			assert.Equal(t, held, role["uri"])
			assert.Equal(t, member, role["record"].(map[string]any)["assignee"])

			status, body = h.do(http.MethodGet, "/me/roles", base+"-stranger", nil)
			require.Equal(t, http.StatusOK, status, body)
			assert.Empty(t, body["roles"])

			status, _ = h.do(http.MethodGet, "/me/roles", "", nil)
			assert.Equal(t, http.StatusUnauthorized, status)
		})
	}
}

func TestMyDelegations(t *testing.T) {
	for name, st := range stores(t) {
		t.Run(name, func(t *testing.T) {
			h := newHost(t, st)
			base := newOrgDID()
			owner, stranger, dealer := base+"-owner", base+"-stranger", base+"-dealer"
			car, notTheirs := base+"-car", base+"-other-car"
			h.clock = day(1)
			for _, did := range []string{owner, stranger, dealer} {
				h.publish(did)
				status, body := h.do(http.MethodPost, "/orgs/"+did, did, nil)
				require.Equal(t, http.StatusCreated, status, body)
			}
			status, body := h.do(http.MethodPut, "/parties/"+owner, dimoDID, map[string]any{"kind": "person"})
			require.Equal(t, http.StatusOK, status, body)
			h.control(car, owner)
			h.control(notTheirs, owner)

			grant := func(from, to, vehicle string) delegation.Record {
				return delegation.Record{
					Type: delegation.TypeDelegation, From: from, To: to, Covers: delegation.Covers{Vehicle: vehicle},
					Abilities:  []string{"telemetry:read"},
					DataWindow: delegation.Window{From: tp(day(1))}, Validity: delegation.Window{From: tp(day(1))},
					Redelegate: delegation.Redelegate{Mode: delegation.RedelegateNone}, CreatedAt: day(1),
				}
			}
			put := func(org, rkey string, rec delegation.Record) string {
				t.Helper()
				status, body := h.do(http.MethodPut, "/orgs/"+org+"/"+delegation.CollectionDelegation+"/"+rkey, org, rec)
				require.Equal(t, http.StatusCreated, status, body)
				return body["uri"].(string)
			}
			consent := put(owner, "consent", grant(owner, dealer, car))
			// Anyone may write a record naming the dealer; this one is over a car
			// its issuer does not control, so it gives nothing.
			bogus := put(stranger, "bogus", grant(stranger, dealer, notTheirs))
			put(owner, "elsewhere", grant(owner, stranger, car))

			h.clock = day(2)
			status, body = h.do(http.MethodGet, "/me/delegations", dealer, nil)
			require.Equal(t, http.StatusOK, status, body)
			list := body["delegations"].([]any)
			uris := []string{}
			for _, d := range list {
				d := d.(map[string]any)
				uris = append(uris, d["uri"].(string))
				assert.Nil(t, d["coverage"], "nothing is evaluated without a vehicle")
				assert.Nil(t, d["refused"])
			}
			assert.ElementsMatch(t, []string{consent, bogus}, uris)
			assert.Nil(t, body["vehicle"])

			status, body = h.do(http.MethodGet, "/me/delegations?vehicle="+car, dealer, nil)
			require.Equal(t, http.StatusOK, status, body)
			assert.Equal(t, car, body["vehicle"])
			byURI := map[string]map[string]any{}
			for _, d := range body["delegations"].([]any) {
				d := d.(map[string]any)
				byURI[d["uri"].(string)] = d
			}
			require.Len(t, byURI, 2)
			assert.Nil(t, byURI[consent]["refused"])
			assert.True(t, window(t, byURI[consent]["coverage"].(map[string]any), "telemetry:read").Contains(day(2)))
			assert.Nil(t, byURI[bogus]["coverage"])
			assert.NotEmpty(t, byURI[bogus]["refused"])

			status, _ = h.do(http.MethodGet, "/me/delegations?vehicle=not-a-did", dealer, nil)
			assert.Equal(t, http.StatusBadRequest, status)
		})
	}
}
