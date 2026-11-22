package orghost

import (
	"net/http"
	"testing"

	"github.com/DIMO-Network/did-directory/pkg/delegation"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestForeignEvidenceCountsForNothing is the attack in which anybody registers
// a repository on the host and writes records about somebody else's car into
// it. Registering needs nothing, and an org's writes to its own repository need
// no authority over the vehicle, so what stops these records is the evaluator:
// custody narrows a grant only when its issuer recorded it, and an exclusive
// claim suspends anybody only when its own chain reaches the controller.
func TestForeignEvidenceCountsForNothing(t *testing.T) {
	const crew = "did:dimo:crew"
	for name, st := range stores(t) {
		t.Run(name, func(t *testing.T) {
			h := newHost(t, st)
			org := newOrgDID()
			car := carOf(org)
			h.fleet(org)

			// Avis's custody-narrowed history grant to a renter who never had the car,
			// and a live command grant to its own crew, approved by the admin.
			history := delegation.Record{
				Type: delegation.TypeDelegation, From: org, To: renter, Covers: delegation.Covers{Vehicle: car},
				Abilities: []string{"telemetry:read"}, DataWindow: delegation.Window{From: tp(day(1))},
				Validity: delegation.Window{From: tp(day(1))}, NarrowToCustody: true,
				Redelegate: delegation.Redelegate{Mode: delegation.RedelegateNone}, CreatedAt: day(1),
			}
			status, body := h.do(http.MethodPut, "/orgs/"+org+"/"+delegation.CollectionDelegation+"/history", org, history)
			require.Equal(t, http.StatusCreated, status, body)
			historyURI := "at://" + org + "/" + delegation.CollectionDelegation + "/history"

			commands := delegation.Record{
				Type: delegation.TypeDelegation, From: org, To: crew, Covers: delegation.Covers{Vehicle: car},
				Abilities: []string{"command:unlock"}, Validity: delegation.Window{From: tp(day(1))},
				Redelegate: delegation.Redelegate{Mode: delegation.RedelegateNone}, CreatedAt: day(1),
			}
			status, body = h.do(http.MethodPut, "/orgs/"+org+"/"+delegation.CollectionDelegation+"/crew", org, commands)
			require.Equal(t, http.StatusAccepted, status, body)
			status, body = h.do(http.MethodPost, "/orgs/"+org+"/pending/"+body["pending"].(string)+"/approve", admin, nil)
			require.Equal(t, http.StatusCreated, status, body)
			commandsURI := "at://" + org + "/" + delegation.CollectionDelegation + "/crew"

			status, body = h.authorize(day(5), historyURI, renter, car, "telemetry:read")
			require.Equal(t, http.StatusForbidden, status, body)
			assert.Equal(t, CodeNotCovered, body["code"])
			status, body = h.authorize(day(5), commandsURI, crew, car, "command:unlock")
			require.Equal(t, http.StatusOK, status, body)

			// The attacker registers a repository, and a puppet with a role in it so
			// the attacker's writes can be approved by somebody other than the author.
			attacker := newOrgDID()
			puppet := attacker + "-puppet"
			h.clock = day(2)
			h.publish(attacker)
			status, body = h.do(http.MethodPost, "/orgs/"+attacker, attacker, nil)
			require.Equal(t, http.StatusCreated, status, body)
			h.grantRole(attacker, roleRecord(attacker, puppet, delegation.Covers{Inherit: true}, "delegation:create"))

			// Custody for the renter, in the attacker's repository.
			status, body = h.do(http.MethodPut, "/orgs/"+attacker+"/"+delegation.CollectionCustody+"/forged", attacker,
				delegation.CustodyPeriod{Vehicle: car, Holder: renter, From: day(1)})
			require.Equal(t, http.StatusCreated, status, body)

			// An exclusive hold over Avis's car, from the attacker to an accomplice.
			hold := delegation.Record{
				Type: delegation.TypeDelegation, From: attacker, To: attacker + "-accomplice", Covers: delegation.Covers{Vehicle: car},
				Abilities: []string{"command:unlock"}, Exclusive: []string{"command:unlock"},
				Validity:   delegation.Window{From: tp(day(2))},
				Redelegate: delegation.Redelegate{Mode: delegation.RedelegateNone}, CreatedAt: day(2),
			}
			status, body = h.do(http.MethodPut, "/orgs/"+attacker+"/"+delegation.CollectionDelegation+"/hold", attacker, hold)
			if status == http.StatusAccepted {
				status, body = h.do(http.MethodPost, "/orgs/"+attacker+"/pending/"+body["pending"].(string)+"/approve", puppet, nil)
			}
			require.Equal(t, http.StatusCreated, status, body)

			// Neither record moves Avis's grants.
			status, body = h.authorize(day(5), historyURI, renter, car, "telemetry:read")
			require.Equal(t, http.StatusForbidden, status, body)
			assert.Equal(t, CodeNotCovered, body["code"])
			status, body = h.authorize(day(5), commandsURI, crew, car, "command:unlock")
			require.Equal(t, http.StatusOK, status, body)
			assert.Equal(t, []any{"command:unlock"}, body["live"])

			// Custody Avis records itself still narrows the grant.
			status, body = h.do(http.MethodPut, "/orgs/"+org+"/"+delegation.CollectionCustody+"/real", org,
				delegation.CustodyPeriod{Vehicle: car, Holder: renter, From: day(3), Until: tp(day(4))})
			require.Equal(t, http.StatusCreated, status, body)
			status, body = h.authorize(day(5), historyURI, renter, car, "telemetry:read")
			require.Equal(t, http.StatusOK, status, body)
			assert.Equal(t, delegation.Span(tp(day(3)), tp(day(4))), window(t, body, "telemetry:read"))
		})
	}
}
