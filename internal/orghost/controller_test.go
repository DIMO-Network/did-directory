package orghost

import (
	"net/http"
	"testing"

	"github.com/DIMO-Network/did-directory/internal/orghost/store"
	"github.com/DIMO-Network/did-directory/pkg/control"
	"github.com/DIMO-Network/did-directory/pkg/delegation"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// A controller holds every ability over its own vehicles with no record
// granting it (spec §7): /authorize with no uri. Its members act through
// their roles, a sale ends the seller's era and starts the buyer's, and
// admin abilities are not data.
func TestControllerRoot(t *testing.T) {
	for name, st := range stores(t) {
		t.Run(name, func(t *testing.T) {
			a := newAvis(t, st)
			car1, car2 := a.cars[0], a.cars[1]
			// Members minted per run: the role lookup is host-wide, and a shared
			// test database keeps every run's roles for a fixed DID.
			manager, admin := a.org+"-manager", a.org+"-admin"
			a.grantRole(a.org, roleRecord(a.org, manager, delegation.Covers{Tag: a.tag["fl-fleet"]}, "delegation:create", "tag:write", "telemetry:read", "events:read"))
			a.grantRole(a.org, roleRecord(a.org, admin, delegation.Covers{Inherit: true}, "org:admin", "telemetry:read", "location:precise"))
			a.clock = day(2)
			status, body := a.do(http.MethodPost, a.path(delegation.CollectionTagMembership, ""), a.org, a.join("fl-fleet", car1, day(2)))
			require.Equal(t, http.StatusCreated, status, body)

			status, body = a.authorize(day(5), "", a.org, car1, "telemetry:read", "command:lock")
			require.Equal(t, http.StatusOK, status, body)
			assert.Equal(t, []any{delegation.ControlURI(a.org, car1)}, body["chain"], "the opening is the root")
			w := window(t, body, "telemetry:read")
			assert.True(t, w.Contains(day(1)) && w.Contains(day(5)))
			assert.Equal(t, []any{"command:lock"}, body["live"])

			// The manager's role is telemetry and events over fl-fleet: car1 is
			// in it, car2 is not, and it has no commands.
			status, body = a.authorize(day(5), "", manager, car1, "telemetry:read")
			require.Equal(t, http.StatusOK, status, body)
			assert.Equal(t, []any{delegation.ControlURI(a.org, car1)}, body["chain"])
			status, body = a.authorize(day(5), "", manager, car1, "command:lock")
			assert.Equal(t, http.StatusForbidden, status, body)
			assert.Equal(t, CodeNotCovered, body["code"])
			status, body = a.authorize(day(5), "", manager, car2, "telemetry:read")
			assert.Equal(t, http.StatusForbidden, status, body)
			assert.Equal(t, CodeNotCovered, body["code"])
			// The admin's role is over every car, without commands either.
			status, body = a.authorize(day(5), "", admin, car2, "location:precise")
			require.Equal(t, http.StatusOK, status, body)
			status, body = a.authorize(day(5), "", admin, car2, "command:lock")
			assert.Equal(t, http.StatusForbidden, status, body)

			// A partner with no role controls nothing, and an admin ability
			// reads nothing.
			status, body = a.authorize(day(5), "", insurer, car1, "telemetry:read")
			assert.Equal(t, http.StatusForbidden, status, body)
			assert.Equal(t, CodeNotCovered, body["code"])
			status, body = a.authorize(day(5), "", a.org, car1, "delegation:create")
			assert.Equal(t, http.StatusForbidden, status, body)
			assert.Equal(t, CodeNotCovered, body["code"])

			// The org sells car1 on day 12.
			buyer := a.org + "-buyer"
			a.clock = day(12)
			a.publish(buyer)
			status, body = a.do(http.MethodPost, "/orgs/"+buyer, buyer, nil)
			require.Equal(t, http.StatusCreated, status, body)
			salt, err := control.NewSalt()
			require.NoError(t, err)
			opening := control.Opening{Controller: buyer, Era: 1, Salt: salt}
			commitment, err := control.Commit(opening)
			require.NoError(t, err)
			a.directory.mu.Lock()
			eras := a.directory.states[car1].Eras
			eras[0].End = new(day(12))
			a.directory.states[car1].Eras = append(eras, control.Era{Number: 1, Start: new(day(12)), Commitment: commitment})
			a.directory.mu.Unlock()
			status, body = a.do(http.MethodPut, "/orgs/"+buyer+"/"+delegation.CollectionVehicleControl+"/"+car1, buyer, opening)
			require.Equal(t, http.StatusCreated, status, body)

			// The seller keeps its era's history and loses the car.
			status, body = a.authorize(day(13), "", a.org, car1, "telemetry:read")
			require.Equal(t, http.StatusOK, status, body)
			w = window(t, body, "telemetry:read")
			assert.True(t, w.Contains(day(5)))
			assert.False(t, w.Contains(day(13)))
			status, body = a.authorize(day(13), "", a.org, car1, "command:lock")
			assert.Equal(t, http.StatusForbidden, status, body)
			assert.Equal(t, CodeNotCovered, body["code"])
			// The buyer starts at the sale.
			status, body = a.authorize(day(13), "", buyer, car1, "telemetry:read", "command:lock")
			require.Equal(t, http.StatusOK, status, body)
			assert.Equal(t, []any{delegation.ControlURI(buyer, car1)}, body["chain"])
			w = window(t, body, "telemetry:read")
			assert.True(t, w.Contains(day(13)))
			assert.False(t, w.Contains(day(5)))
			assert.Equal(t, []any{"command:lock"}, body["live"])

			status, body = a.do(http.MethodPost, "/authorize", dauthDID, AuthorizeRequest{Caller: a.org, Vehicle: "not-a-did", Abilities: []string{"telemetry:read"}})
			assert.Equal(t, http.StatusBadRequest, status, body)
		})
	}
}

// A renter's exclusive custody suspends the controller's commands as it
// suspends any partner's (spec §12.2): the operator learns somebody is
// driving, and still reads the car's data.
func TestControllerRootUnderCustody(t *testing.T) {
	h := newHost(t, store.NewMemoryStore())
	org := newOrgDID()
	car := carOf(org)
	h.fleet(org)
	h.clock = day(9)
	driving := rental(org)
	h.commitGrants(org, h.compile(&driving, day(11)))

	status, body := h.authorize(day(11), "", org, car, "command:lock")
	assert.Equal(t, http.StatusForbidden, status, body)
	assert.Equal(t, CodeExclusiveHold, body["code"])
	assert.Equal(t, []any{"command:lock"}, body["suspended"])

	status, body = h.authorize(day(11), "", org, car, "telemetry:read", "command:lock")
	require.Equal(t, http.StatusOK, status, body)
	assert.Equal(t, []any{"command:lock"}, body["suspended"])
	assert.Nil(t, body["live"])
	assert.True(t, window(t, body, "telemetry:read").Contains(day(10)))

	// After the rental ends the commands are the org's again.
	status, body = h.authorize(day(20), "", org, car, "command:lock")
	require.Equal(t, http.StatusOK, status, body)
	assert.Equal(t, []any{"command:lock"}, body["live"])
}
