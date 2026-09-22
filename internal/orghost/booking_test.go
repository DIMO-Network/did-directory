package orghost

import (
	"context"
	"encoding/json"
	"net/http"
	"testing"
	"time"

	dimocrypto "github.com/DIMO-Network/did-directory/internal/crypto"
	"github.com/DIMO-Network/did-directory/internal/orghost/store"
	"github.com/DIMO-Network/did-directory/pkg/agreement"
	"github.com/DIMO-Network/did-directory/pkg/agreement/booking"
	"github.com/DIMO-Network/did-directory/pkg/delegation"
	"github.com/DIMO-Network/did-directory/pkg/repo"
	"github.com/gofiber/fiber/v2"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const roadside = "did:dimo:roadside"

// fiberTransport lets a real http.Client reach the host in-process, so the
// SDK is exercised exactly as an operator would link it, down to the wire.
type fiberTransport struct{ app *fiber.App }

func (t fiberTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	return t.app.Test(req, -1)
}

// bookingService stands in for an operator's booking system: it holds one
// agreement, moves it through its lifecycle, and syncs the host after every
// move, which is how the SDK is meant to be driven (plan §6 step 5).
type bookingService struct {
	h      *host
	org    string
	client *booking.Client
	a      agreement.Agreement
}

// newBookingService starts a booking of org's car at the point a customer
// reserves a class: unpaid, and no car assigned yet.
func newBookingService(h *host, org, as string) *bookingService {
	b := &bookingService{h: h, org: org, a: rental(org)}
	b.a.State = agreement.StateBooked
	b.a.Duties[0].FulfilledAt = nil
	b.a.Target.Vehicle, b.a.Target.AssignedAt = "", nil
	b.a.CreatedBy = as
	b.client = &booking.Client{
		Host:  "http://org-host.test/",
		Token: func(context.Context) (string, error) { return h.issuer.identity(h.t, as), nil },
		HTTP:  &http.Client{Transport: fiberTransport{h.app}},
	}
	return b
}

func (b *bookingService) sync(now time.Time) *booking.Result {
	b.h.t.Helper()
	b.h.clock = now
	res, err := b.client.Sync(b.h.t.Context(), &b.a, agreement.RentalCatalog(), now)
	require.NoError(b.h.t, err)
	return res
}

func ops(outs []booking.Outcome) []string {
	out := make([]string, 0, len(outs))
	for _, o := range outs {
		out = append(out, o.Key+" "+o.Op)
	}
	return out
}

// TestBookingServiceDrivesTheHost is the plan's step 5 test: booking, paid,
// picked up, returned, driven from a booking service through the SDK, with
// /authorize asked as dauth would for the renter and the blocked operator at
// each stage.
func TestBookingServiceDrivesTheHost(t *testing.T) {
	for name, st := range stores(t) {
		t.Run(name, func(t *testing.T) {
			h := newHost(t, st)
			org := newOrgDID()
			car := carOf(org)
			h.fleet(org)
			ctx := t.Context()

			// The valet crew's standing grant, as in TestCompiledGrantsAuthorizeOverHTTP.
			status, body := h.do(http.MethodPut, "/orgs/"+org+"/"+delegation.CollectionDelegation+"/valet", org, delegation.Record{
				Type: delegation.TypeDelegation, From: org, To: valet,
				Covers:     delegation.Covers{Vehicle: car},
				Abilities:  []string{"command:unlock", "command:lock", "telemetry:read"},
				Validity:   span(1, 400),
				Redelegate: delegation.Redelegate{Mode: delegation.RedelegateNone}, CreatedAt: day(1),
			})
			require.Equal(t, http.StatusAccepted, status, body)
			status, body = h.do(http.MethodPost, "/orgs/"+org+"/pending/"+body["pending"].(string)+"/approve", admin, nil)
			require.Equal(t, http.StatusCreated, status, body)

			custodyURI := "at://" + org + "/" + delegation.CollectionDelegation + "/bk-1:rental:custody"
			historyURI := "at://" + org + "/" + delegation.CollectionDelegation + "/bk-1:rental:history"
			roadsideURI := "at://" + org + "/" + delegation.CollectionDelegation + "/bk-1:roadside:roadside:inc-1"
			valetURI := "at://" + org + "/" + delegation.CollectionDelegation + "/valet"
			legKey := booking.CustodyKey("bk-1", day(10))
			delegations := func() int {
				status, body := h.do(http.MethodGet, "/orgs/"+org+"/"+delegation.CollectionDelegation, backend, nil)
				require.Equal(t, http.StatusOK, status, body)
				return len(body["records"].([]any))
			}

			b := newBookingService(h, org, backend)

			// Booked: nothing is granted yet, and there is nothing to revoke.
			res := b.sync(day(1))
			assert.Empty(t, res.Grants)
			assert.Empty(t, res.Custody)
			assert.Empty(t, res.Revoked)
			assert.Equal(t, 1, delegations(), "only the valet grant")

			// Paid, but the desk has not handed over a car: still nothing, since a
			// grant has to name the car it opens.
			b.a.Duties[0].FulfilledAt = tp(day(2))
			b.a.State = agreement.StatePaid
			res = b.sync(day(2))
			assert.Empty(t, res.Grants)
			assert.Equal(t, 1, delegations())

			// The car is assigned on the morning of pickup. Custody and history
			// grants land, unattended, under the booking role.
			b.a.Target.Vehicle, b.a.Target.AssignedAt = car, tp(day(10))
			res = b.sync(day(10))
			assert.Equal(t, []string{"bk-1:rental:custody create", "bk-1:rental:history create"}, ops(res.Grants))
			assert.Equal(t, custodyURI, res.Grants[0].URI)
			assert.NotEmpty(t, res.Grants[0].CID)
			assert.Empty(t, res.Custody, "no custody event has synced")
			assert.Empty(t, res.Revoked)

			t.Run("renter can unlock during the booking", func(t *testing.T) {
				status, body := h.authorize(day(11), custodyURI, renter, car, "command:unlock")
				require.Equal(t, http.StatusOK, status, body)
				assert.Equal(t, []any{"command:unlock"}, body["live"])
			})
			t.Run("the operator is blocked while somebody is driving", func(t *testing.T) {
				status, body := h.authorize(day(11), valetURI, valet, car, "command:unlock")
				require.Equal(t, http.StatusForbidden, status, body)
				assert.Equal(t, CodeExclusiveHold, body["code"])
				assert.Equal(t, []any{"command:unlock"}, body["suspended"])
			})

			// The device syncs the pickup: an open custody leg. The grants are
			// recommitted, and the leg is written under its own key.
			b.a.Custody = []agreement.Custody{{Start: day(10)}}
			b.a.State = agreement.StatePickedUp
			res = b.sync(day(11))
			assert.Equal(t, []string{legKey + " create"}, ops(res.Custody))
			assert.Equal(t, []string{"bk-1:rental:custody update", "bk-1:rental:history update"}, ops(res.Grants))
			assert.Empty(t, res.Revoked)
			status, body = h.do(http.MethodGet, "/orgs/"+org+"/"+delegation.CollectionCustody+"/"+legKey, backend, nil)
			require.Equal(t, http.StatusOK, status, body)
			leg := body["record"].(map[string]any)
			assert.Equal(t, renter, leg["holder"])
			assert.Equal(t, car, leg["vehicle"])
			assert.Nil(t, leg["until"])

			// A breakdown that afternoon. Roadside gets precise location for as
			// long as the incident is open.
			b.a.Services = append(b.a.Services, agreement.Service{Code: "roadside"})
			b.a.Incidents = []agreement.Incident{{ID: "inc-1", Responder: roadside, OpenedAt: day(11).Add(6 * time.Hour)}}
			res = b.sync(day(11).Add(7 * time.Hour))
			assert.Equal(t, []string{"bk-1:rental:custody update", "bk-1:rental:history update", "bk-1:roadside:roadside:inc-1 create"}, ops(res.Grants))
			assert.Empty(t, res.Revoked)
			t.Run("roadside can locate the car while the incident is open", func(t *testing.T) {
				status, body := h.authorize(day(11).Add(8*time.Hour), roadsideURI, roadside, car, "location:precise")
				require.Equal(t, http.StatusOK, status, body)
				assert.True(t, window(t, body, "location:precise").Contains(day(11).Add(7*time.Hour)))
			})

			// The incident closes, the car comes back on day 12 and the device
			// syncs the return. Custody and roadside drop out of the compilation
			// and are tombstoned; the leg closes; history narrows to the drive.
			b.a.Incidents[0].ClosedAt = tp(day(11).Add(10 * time.Hour))
			b.a.Custody[0].End = tp(day(12))
			b.a.State = agreement.StateReturned
			res = b.sync(day(13))
			assert.Equal(t, []string{legKey + " update"}, ops(res.Custody))
			assert.Equal(t, []string{"bk-1:rental:history update"}, ops(res.Grants))
			assert.Equal(t, []string{"bk-1:rental:custody tombstone", "bk-1:roadside:roadside:inc-1 tombstone"}, ops(res.Revoked))
			assert.Equal(t, custodyURI, res.Revoked[0].URI)
			status, body = h.do(http.MethodGet, "/orgs/"+org+"/"+delegation.CollectionDelegation+"/bk-1:rental:custody", backend, nil)
			require.Equal(t, http.StatusGone, status, body)
			assert.Equal(t, backend, body["tombstone"].(map[string]any)["by"], "the booking service's own revocation")
			status, body = h.do(http.MethodGet, "/orgs/"+org+"/"+delegation.CollectionCustody+"/"+legKey, backend, nil)
			require.Equal(t, http.StatusOK, status, body)
			assert.Equal(t, day(12).Format(time.RFC3339), body["record"].(map[string]any)["until"])
			assert.Equal(t, 2, delegations(), "valet and history")

			t.Run("the renter's commands are gone", func(t *testing.T) {
				status, body := h.authorize(day(13), custodyURI, renter, car, "command:unlock")
				require.Equal(t, http.StatusForbidden, status, body)
				assert.Equal(t, CodeRevoked, body["code"])
			})
			t.Run("the operator gets its car back", func(t *testing.T) {
				status, body := h.authorize(day(13), valetURI, valet, car, "command:unlock")
				require.Equal(t, http.StatusOK, status, body)
				assert.Equal(t, []any{"command:unlock"}, body["live"])
			})
			t.Run("roadside is done", func(t *testing.T) {
				status, body := h.authorize(day(13), roadsideURI, roadside, car, "location:precise")
				require.Equal(t, http.StatusForbidden, status, body)
				assert.Equal(t, CodeRevoked, body["code"])
			})
			t.Run("history covers the drive and nothing else", func(t *testing.T) {
				status, body := h.authorize(day(20), historyURI, renter, car, "telemetry:read")
				require.Equal(t, http.StatusOK, status, body)
				w := window(t, body, "telemetry:read")
				assert.True(t, w.Contains(day(11)))
				assert.False(t, w.Contains(day(14)))
				assert.False(t, w.Contains(day(9)))
			})
			t.Run("history stops when retention runs out", func(t *testing.T) {
				status, body := h.authorize(day(60), historyURI, renter, car, "telemetry:read")
				require.Equal(t, http.StatusForbidden, status, body)
				assert.Equal(t, CodeNotValid, body["code"])
			})

			// Syncing the same state again is harmless: the live records are
			// recommitted and there is nothing left to revoke.
			res = b.sync(day(14))
			assert.Equal(t, []string{"bk-1:rental:history update"}, ops(res.Grants))
			assert.Empty(t, res.Revoked)

			// Once retention has run out the history grant drops out too, and the
			// booking has no records left on the host.
			res = b.sync(day(60))
			assert.Empty(t, res.Grants)
			assert.Equal(t, []string{"bk-1:rental:history tombstone"}, ops(res.Revoked))
			assert.Equal(t, 1, delegations(), "only the valet grant")

			// Everything the SDK wrote verifies offline against #dimo_org.
			status, body = h.do(http.MethodGet, "/orgs/"+org, backend, nil)
			require.Equal(t, http.StatusOK, status, body)
			pub, err := dimocrypto.DecodeDIDKey(body["key"].(string))
			require.NoError(t, err)
			log, err := h.repo.Log(ctx, org, 0, 0)
			require.NoError(t, err)
			_, err = repo.VerifyLog(org, log, pub)
			require.NoError(t, err)
		})
	}
}

// A cancellation before pickup compiles to nothing, so the next sync revokes
// whatever the assignment had committed. A cancellation after the drive keeps
// the history.
func TestBookingServiceCancellation(t *testing.T) {
	h := newHost(t, store.NewMemoryStore())
	org := newOrgDID()
	car := carOf(org)
	h.fleet(org)

	b := newBookingService(h, org, backend)
	b.a.Duties[0].FulfilledAt = tp(day(2))
	b.a.State = agreement.StatePaid
	b.a.Target.Vehicle, b.a.Target.AssignedAt = car, tp(day(10))
	res := b.sync(day(10))
	require.Len(t, res.Grants, 2)

	b.a.State = agreement.StateCancelled
	b.a.Timestamps.CancelledAt = tp(day(10).Add(time.Hour))
	res = b.sync(day(10).Add(2 * time.Hour))
	assert.Empty(t, res.Grants)
	assert.Equal(t, []string{"bk-1:rental:custody tombstone", "bk-1:rental:history tombstone"}, ops(res.Revoked))

	// Cancelled again, or synced again: nothing to do.
	res = b.sync(day(11))
	assert.Empty(t, res.Grants)
	assert.Empty(t, res.Revoked)

	custodyURI := "at://" + org + "/" + delegation.CollectionDelegation + "/bk-1:rental:custody"
	status, body := h.authorize(day(11), custodyURI, renter, car, "command:unlock")
	require.Equal(t, http.StatusForbidden, status, body)
	assert.Equal(t, CodeRevoked, body["code"])
}

// The host's refusals come back typed, and a sync stops where the refusal
// happened. Here the booking service signs as a DID the agreement does not
// name as its author, which the host refuses before any role check.
func TestBookingServiceRefused(t *testing.T) {
	h := newHost(t, store.NewMemoryStore())
	org := newOrgDID()
	h.fleet(org)

	b := newBookingService(h, org, valet)
	b.a.CreatedBy = backend
	b.a.Duties[0].FulfilledAt = tp(day(2))
	b.a.State = agreement.StatePaid
	b.a.Target.Vehicle, b.a.Target.AssignedAt = carOf(org), tp(day(10))
	h.clock = day(10)
	res, err := b.client.Sync(t.Context(), &b.a, agreement.RentalCatalog(), day(10))
	assert.Nil(t, res)
	var refused *booking.Error
	require.ErrorAs(t, err, &refused)
	assert.Equal(t, http.StatusBadRequest, refused.Status)
	assert.Equal(t, http.MethodPut, refused.Method)
	assert.Contains(t, refused.Message, "createdBy claims "+backend)
	assert.Contains(t, err.Error(), "400")

	// A compile error never reaches the host.
	b = newBookingService(h, org, backend)
	b.a.Duties = []agreement.Duty{{Action: agreement.DutyPay, FulfilledAt: tp(day(2))}}
	b.a.State = agreement.StatePaid
	b.a.Target.Vehicle, b.a.Target.AssignedAt = carOf(org), tp(day(10))
	b.a.Window.To = nil
	_, err = b.client.Sync(t.Context(), &b.a, agreement.RentalCatalog(), day(10))
	assert.ErrorIs(t, err, agreement.ErrUnboundedBooking)
	_, err = (&booking.Client{Host: b.client.Host, HTTP: b.client.HTTP}).Sync(t.Context(), &b.a, agreement.RentalCatalog(), day(10))
	assert.Error(t, err, "no token source")
}

// A booking role that names no policy commits under the default one, which
// parks every grant of a live ability. The SDK reports the parked write rather
// than treating it as committed, and the admin's approval lands it.
func TestBookingServicePending(t *testing.T) {
	h := newHost(t, store.NewMemoryStore())
	org := newOrgDID()
	car := carOf(org)
	h.fleet(org)
	const desk = "did:dimo:avis-desk"
	h.clock = day(1)
	role := roleRecord(org, desk, delegation.Covers{Inherit: true}, agreement.RentalCatalog().Abilities()...)
	role.Constraints = &delegation.RoleConstraints{AllowExclusive: true}
	status, body := h.do(http.MethodPost, "/orgs/"+org+"/"+delegation.CollectionRole, org, role)
	require.Equal(t, http.StatusAccepted, status, body)
	status, body = h.do(http.MethodPost, "/orgs/"+org+"/pending/"+body["pending"].(string)+"/approve", admin, nil)
	require.Equal(t, http.StatusCreated, status, body)

	b := newBookingService(h, org, desk)
	b.a.Duties[0].FulfilledAt = tp(day(2))
	b.a.State = agreement.StatePaid
	b.a.Target.Vehicle, b.a.Target.AssignedAt = car, tp(day(10))
	res := b.sync(day(10))
	require.Len(t, res.Grants, 2)
	assert.Equal(t, booking.OpPending, res.Grants[0].Op)
	assert.NotEmpty(t, res.Grants[0].Pending)
	assert.Contains(t, res.Grants[0].Reasons, "grants live ability command:unlock")
	assert.Equal(t, "create", res.Grants[1].Op, "history reads, and needs nobody's approval")

	custodyURI := "at://" + org + "/" + delegation.CollectionDelegation + "/bk-1:rental:custody"
	status, body = h.authorize(day(11), custodyURI, renter, car, "command:unlock")
	assert.Equal(t, http.StatusNotFound, status, body)
	status, body = h.do(http.MethodPost, "/orgs/"+org+"/pending/"+res.Grants[0].Pending+"/approve", admin, nil)
	require.Equal(t, http.StatusCreated, status, body)
	status, body = h.authorize(day(11), custodyURI, renter, car, "command:unlock")
	require.Equal(t, http.StatusOK, status, body)
	raw, _ := json.Marshal(body["chain"])
	assert.Equal(t, `["`+custodyURI+`"]`, string(raw))
}
