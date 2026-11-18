package orghost

import (
	"net/http"
	"testing"
	"time"

	"github.com/DIMO-Network/did-directory/internal/orghost/store"
	"github.com/DIMO-Network/did-directory/pkg/agreement"
	"github.com/DIMO-Network/did-directory/pkg/control"
	"github.com/DIMO-Network/did-directory/pkg/delegation"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// The principals of the Avis rental in pkg/agreement/evaluate_test.go. The org
// and its car are minted per test: custody and exclusive claims are read across
// repositories, so repeated runs against one Postgres database would otherwise
// see each other's records.
const (
	admin   = "did:dimo:avis-admin"
	backend = "did:dimo:avis-backend"
	renter  = "did:dimo:renter"
	insurer = "did:dimo:insurer"
	valet   = "did:dimo:valet"
)

func carOf(org string) string { return org + "-car" }

func day(d int) time.Time       { return time.Date(2026, 1, d, 0, 0, 0, 0, time.UTC) }
func tp(t time.Time) *time.Time { return &t }
func span(a, b int) delegation.Window {
	return delegation.Window{From: tp(day(a)), To: tp(day(b))}
}

// rental is the booking from pkg/agreement/evaluate_test.go: a paid rental of
// car from day 10 to day 15, retained for 30 days after the car comes back.
func rental(org string) agreement.Agreement {
	return agreement.Agreement{
		Type:     agreement.TypeAgreement,
		ID:       "bk-1",
		Assigner: org,
		Assignee: renter,
		Target:   agreement.Target{Class: "suv-intermediate", Vehicle: carOf(org), AssignedAt: tp(day(10))},
		Services: []agreement.Service{{Code: "rental"}},
		Duties: []agreement.Duty{
			{Action: agreement.DutyPay, FulfilledAt: tp(day(2))},
			{Action: agreement.DutyReturn, DueBy: tp(day(15))},
			{Action: agreement.DutyRetention, Term: 30 * 24 * time.Hour},
		},
		Window:     span(10, 15),
		State:      agreement.StatePaid,
		Timestamps: agreement.Timestamps{BookedAt: day(1)},
		Terms:      "sha256:9f2c",
		CreatedBy:  backend,
	}
}

// fleet stands up one org on the host as the controller of record for car:
// registered, attested an operator, its opening committed and the directory
// holding the matching commitment. It is the HTTP counterpart of the fleet in
// pkg/agreement/evaluate_test.go.
func (h *host) fleet(org string) {
	h.t.Helper()
	car := carOf(org)
	h.clock = day(1)
	status, body := h.do(http.MethodPost, "/orgs/"+org, org, nil)
	require.Equal(h.t, http.StatusCreated, status, body)
	status, body = h.do(http.MethodPut, "/parties/"+org, dimoDID, map[string]any{"kind": "org", "operator": true})
	require.Equal(h.t, http.StatusOK, status, body)

	salt, err := control.NewSalt()
	require.NoError(h.t, err)
	opening := control.Opening{Controller: org, Era: 0, Salt: salt}
	commitment, err := control.Commit(opening)
	require.NoError(h.t, err)
	h.directory.set(car, &control.State{DID: car, Eras: []control.Era{{Number: 0, Commitment: commitment}}})
	status, body = h.do(http.MethodPut, "/orgs/"+org+"/"+delegation.CollectionVehicleControl+"/"+car, org, opening)
	require.Equal(h.t, http.StatusCreated, status, body)

	// The org's first role: an admin who may issue roles and grants, with no
	// live abilities, so it commits with nobody to approve it yet.
	h.grantRole(org, roleRecord(org, admin, delegation.Covers{Inherit: true}, "org:admin", "org:members", "delegation:create", "tag:write"))

	// The booking service's role: delegation:create plus everything the catalog
	// hands out, over every car, committing under the booking policy so its
	// grants of live abilities do not each wait for two admins (plan §3.2).
	// The role itself hands out commands, so the admin approves it.
	role := delegation.Record{
		Type: delegation.TypeRole, From: org, To: backend,
		Covers: delegation.Covers{Inherit: true}, Abilities: agreement.RentalCatalog().Abilities(),
		Constraints: &delegation.RoleConstraints{Policy: agreement.CommitPolicy().Name, AllowExclusive: true},
		Redelegate:  delegation.Redelegate{Mode: delegation.RedelegateNone}, CreatedAt: day(1),
	}
	status, body = h.do(http.MethodPost, "/orgs/"+org+"/"+delegation.CollectionRole, org, role)
	require.Equal(h.t, http.StatusAccepted, status, body)
	status, body = h.do(http.MethodPost, "/orgs/"+org+"/pending/"+body["pending"].(string)+"/approve", admin, nil)
	require.Equal(h.t, http.StatusCreated, status, body)
}

// commitGrants is what a booking service does with a compilation: PUT each
// grant under its stable key, as itself.
func (h *host) commitGrants(org string, grants []agreement.Grant) {
	h.t.Helper()
	for _, g := range grants {
		status, body := h.do(http.MethodPut, "/orgs/"+org+"/"+delegation.CollectionDelegation+"/"+g.Key, backend, g.Record)
		require.Contains(h.t, []int{http.StatusCreated, http.StatusOK}, status, body)
	}
}

func (h *host) compile(a *agreement.Agreement, now time.Time) []agreement.Grant {
	h.t.Helper()
	grants, err := agreement.Compile(a, agreement.RentalCatalog(), now)
	require.NoError(h.t, err)
	return grants
}

// authorize asks the host as dauth would.
func (h *host) authorize(at time.Time, uri, caller, vehicle string, abilities ...string) (int, map[string]any) {
	h.t.Helper()
	h.clock = at
	return h.do(http.MethodPost, "/authorize", dauthDID, AuthorizeRequest{URI: uri, Caller: caller, Vehicle: vehicle, Abilities: abilities})
}

// window reads a historical ability's windows out of a response.
func window(t *testing.T, body map[string]any, ability string) delegation.Set {
	t.Helper()
	hist, _ := body["historical"].(map[string]any)
	raw, ok := hist[ability]
	require.True(t, ok, "no window for %s in %v", ability, body)
	var set delegation.Set
	for _, iv := range raw.([]any) {
		pair := iv.([]any)
		var from, to *time.Time
		if s, ok := pair[0].(string); ok {
			ts, err := time.Parse(time.RFC3339Nano, s)
			require.NoError(t, err)
			from = &ts
		}
		if s, ok := pair[1].(string); ok {
			ts, err := time.Parse(time.RFC3339Nano, s)
			require.NoError(t, err)
			to = &ts
		}
		set = set.Union(delegation.Span(from, to))
	}
	return set
}

// TestCompiledGrantsAuthorizeOverHTTP replays TestCompiledGrantsEvaluate from
// pkg/agreement through the host: the same records committed over HTTP, the
// same questions asked of /authorize, the same coverage back.
func TestCompiledGrantsAuthorizeOverHTTP(t *testing.T) {
	for name, st := range stores(t) {
		t.Run(name, func(t *testing.T) {
			h := newHost(t, st)
			org := newOrgDID()
			car := carOf(org)
			h.fleet(org)

			// The booking, as first compiled while the renter is driving.
			h.clock = day(9)
			driving := rental(org)
			h.commitGrants(org, h.compile(&driving, day(11)))

			// Avis grants its valet crew the same commands, with no exclusive claim,
			// plus telemetry so the record has something to say while the commands
			// are suspended. Commands wait for the admin, even from the org.
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

			// Pickup and return, as the fleet's own custody record; then the booking
			// recompiled after return, which upserts the history grant with the
			// narrowed window and no longer produces custody.
			h.clock = day(13)
			status, body = h.do(http.MethodPost, "/orgs/"+org+"/"+delegation.CollectionCustody, backend,
				delegation.CustodyPeriod{Vehicle: car, Holder: renter, From: day(10), Until: tp(day(12))})
			require.Equal(t, http.StatusCreated, status, body)
			returned := rental(org)
			returned.Custody = []agreement.Custody{{Start: day(10), End: tp(day(12))}}
			returned.State = agreement.StateReturned
			returnedGrants := h.compile(&returned, day(13))
			require.Len(t, returnedGrants, 1)
			h.commitGrants(org, returnedGrants)

			custodyURI := "at://" + org + "/" + delegation.TypeDelegation + "/bk-1:rental:custody"
			historyURI := "at://" + org + "/" + delegation.TypeDelegation + "/bk-1:rental:history"
			valetURI := "at://" + org + "/" + delegation.TypeDelegation + "/valet"

			t.Run("renter can unlock during the booking", func(t *testing.T) {
				status, body := h.authorize(day(11), custodyURI, renter, car, "command:unlock")
				require.Equal(t, http.StatusOK, status, body)
				assert.Equal(t, []any{"command:unlock"}, body["live"])
				assert.Nil(t, body["suspended"])
				assert.Equal(t, []any{custodyURI}, body["chain"])
				assert.Equal(t, day(11).Format(time.RFC3339), body["at"])
			})

			t.Run("the operator's commands are suspended while somebody is driving", func(t *testing.T) {
				status, body := h.authorize(day(11), valetURI, valet, car, "command:unlock")
				require.Equal(t, http.StatusForbidden, status, body)
				assert.Equal(t, CodeExclusiveHold, body["code"], "the operator is told somebody is driving, not that they were never granted this")
				assert.Equal(t, []any{"command:unlock"}, body["suspended"])

				status, body = h.authorize(day(11), valetURI, valet, car, "command:unlock", "command:lock", "telemetry:read")
				require.Equal(t, http.StatusOK, status, body)
				assert.Nil(t, body["live"])
				assert.ElementsMatch(t, []any{"command:unlock", "command:lock"}, body["suspended"])
				assert.True(t, window(t, body, "telemetry:read").Contains(day(11)), "seeing the car is not commanding it")
			})

			t.Run("the operator gets its car back when the booking window ends", func(t *testing.T) {
				status, body := h.authorize(day(16), valetURI, valet, car, "command:unlock")
				require.Equal(t, http.StatusOK, status, body)
				assert.Equal(t, []any{"command:unlock"}, body["live"])
			})

			t.Run("custody does not outlive the booking window", func(t *testing.T) {
				status, body := h.authorize(day(16), custodyURI, renter, car, "command:unlock")
				require.Equal(t, http.StatusForbidden, status, body)
				assert.Equal(t, CodeNotValid, body["code"])
			})

			t.Run("history outlives custody and covers only the drive", func(t *testing.T) {
				status, body := h.authorize(day(20), historyURI, renter, car, "telemetry:read")
				require.Equal(t, http.StatusOK, status, body)
				w := window(t, body, "telemetry:read")
				assert.True(t, w.Contains(day(11)), "the day they drove")
				assert.False(t, w.Contains(day(14)), "after they handed the car back")
				assert.False(t, w.Contains(day(9)), "before they picked it up")
			})

			t.Run("history stops when retention runs out", func(t *testing.T) {
				status, body := h.authorize(day(60), historyURI, renter, car, "telemetry:read")
				require.Equal(t, http.StatusForbidden, status, body)
				assert.Equal(t, CodeNotValid, body["code"])
			})

			t.Run("nobody else may use the renter's grant", func(t *testing.T) {
				status, body := h.authorize(day(20), historyURI, valet, car, "telemetry:read")
				require.Equal(t, http.StatusForbidden, status, body)
				assert.Equal(t, CodeUnauthorized, body["code"])
			})

			t.Run("a car the directory does not know is not covered", func(t *testing.T) {
				status, body := h.authorize(day(11), custodyURI, renter, "did:dimo:car2", "command:unlock")
				require.Equal(t, http.StatusForbidden, status, body)
				assert.Equal(t, CodeNotCovered, body["code"])
			})

			t.Run("a tombstoned grant is revoked", func(t *testing.T) {
				status, body := h.do(http.MethodDelete, "/orgs/"+org+"/"+delegation.CollectionDelegation+"/valet", org, nil)
				require.Equal(t, http.StatusOK, status, body)
				status, body = h.authorize(day(30), valetURI, valet, car, "command:unlock")
				require.Equal(t, http.StatusForbidden, status, body)
				assert.Equal(t, CodeRevoked, body["code"])
			})
		})
	}
}

// TestInsurerGrantAuthorizesOverHTTP replays TestInsurerGrantEvaluates: the
// insurer behind a damage waiver never had the car, and still gets the
// customer's drive.
func TestInsurerGrantAuthorizesOverHTTP(t *testing.T) {
	h := newHost(t, store.NewMemoryStore())
	org := newOrgDID()
	car := carOf(org)
	h.fleet(org)

	h.clock = day(13)
	a := rental(org)
	a.Services = append(a.Services, agreement.Service{Code: "waiver", Beneficiary: insurer, Term: span(1, 400)})
	a.Custody = []agreement.Custody{{Start: day(10), End: tp(day(12))}}
	a.State = agreement.StateReturned
	status, body := h.do(http.MethodPost, "/orgs/"+org+"/"+delegation.CollectionCustody, backend,
		delegation.CustodyPeriod{Vehicle: car, Holder: renter, From: day(10), Until: tp(day(12))})
	require.Equal(t, http.StatusCreated, status, body)
	h.commitGrants(org, h.compile(&a, day(13)))

	uri := "at://" + org + "/" + delegation.TypeDelegation + "/bk-1:waiver:insurer"
	status, body = h.authorize(day(20), uri, insurer, car, "events:read")
	require.Equal(t, http.StatusOK, status, body, "the insurer bought a look at the customer's drive")
	w := window(t, body, "events:read")
	assert.True(t, w.Contains(day(11)), "the day the customer drove")
	assert.False(t, w.Contains(day(14)), "after the car came back")
	assert.False(t, w.Contains(day(9)), "before the customer picked it up")
}

// The route is for the issuer, takes a well-formed question, and answers a
// record that is not here with 404.
func TestAuthorizeGuards(t *testing.T) {
	h := newHost(t, store.NewMemoryStore())
	org := newOrgDID()
	car := carOf(org)
	h.fleet(org)
	uri := "at://" + org + "/" + delegation.TypeDelegation + "/nothing"
	good := AuthorizeRequest{URI: uri, Caller: renter, Vehicle: car, Abilities: []string{"command:unlock"}}

	status, body := h.do(http.MethodPost, "/authorize", "", good)
	assert.Equal(t, http.StatusUnauthorized, status, body)
	status, body = h.do(http.MethodPost, "/authorize", renter, good)
	assert.Equal(t, http.StatusForbidden, status, body)
	status, body = h.do(http.MethodPost, "/authorize", dauthDID, good)
	assert.Equal(t, http.StatusNotFound, status, body)
	assert.Equal(t, "not_found", body["code"])

	with := func(mutate func(r *AuthorizeRequest)) AuthorizeRequest {
		r := good
		r.Abilities = append([]string(nil), r.Abilities...)
		mutate(&r)
		return r
	}
	for name, req := range map[string]AuthorizeRequest{
		"bad uri":        with(func(r *AuthorizeRequest) { r.URI = "https://x" }),
		"caller not did": with(func(r *AuthorizeRequest) { r.Caller = "renter" }),
		"vehicle empty":  with(func(r *AuthorizeRequest) { r.Vehicle = "" }),
		"no abilities":   with(func(r *AuthorizeRequest) { r.Abilities = nil }),
		"empty ability":  with(func(r *AuthorizeRequest) { r.Abilities = []string{""} }),
		"at":             with(func(r *AuthorizeRequest) { r.At = tp(day(1)) }),
	} {
		t.Run(name, func(t *testing.T) {
			status, body := h.do(http.MethodPost, "/authorize", dauthDID, req)
			assert.Equal(t, http.StatusBadRequest, status, body)
		})
	}
	status, body = h.do(http.MethodPost, "/authorize", dauthDID, `{`)
	assert.Equal(t, http.StatusBadRequest, status, body)

	// A role URI is a record, but not one that can be exercised.
	status, body = h.do(http.MethodGet, "/orgs/"+org+"/"+delegation.CollectionRole, org, nil)
	require.Equal(t, http.StatusOK, status, body)
	roleURI := body["records"].([]any)[0].(map[string]any)["uri"].(string)
	status, body = h.authorize(day(2), roleURI, backend, car, "telemetry:read")
	assert.Equal(t, http.StatusForbidden, status, body)
	assert.Equal(t, CodeDenied, body["code"])
}

// Parties are DIMO's to set; anyone authenticated may read them; an org with
// no row is an org, and a stranger is nobody in particular.
func TestParties(t *testing.T) {
	h := newHost(t, store.NewMemoryStore())
	org := newOrgDID()
	status, body := h.do(http.MethodPost, "/orgs/"+org, org, nil)
	require.Equal(t, http.StatusCreated, status, body)

	status, body = h.do(http.MethodPut, "/parties/"+org, org, map[string]any{"kind": "org", "operator": true})
	assert.Equal(t, http.StatusForbidden, status, body)
	status, body = h.do(http.MethodGet, "/parties/"+org, org, nil)
	assert.Equal(t, http.StatusNotFound, status, body)
	status, body = h.do(http.MethodPut, "/parties/"+org, dimoDID, map[string]any{"kind": "company"})
	assert.Equal(t, http.StatusBadRequest, status, body)
	status, body = h.do(http.MethodPut, "/parties/notadid", dimoDID, map[string]any{"kind": "org"})
	assert.Equal(t, http.StatusBadRequest, status, body)

	ctx := t.Context()
	r := &Resolver{Store: h.repo.Store, Control: h.directory}
	p, err := r.Party(ctx, org)
	require.NoError(t, err)
	assert.Equal(t, delegation.Party{Kind: delegation.KindOrg}, p, "a registered org with no row is an org, not an operator")
	p, err = r.Party(ctx, renter)
	require.NoError(t, err)
	assert.Equal(t, delegation.Party{}, p)

	status, body = h.do(http.MethodPut, "/parties/"+org, dimoDID, map[string]any{"kind": "org", "operator": true})
	require.Equal(t, http.StatusOK, status, body)
	status, body = h.do(http.MethodGet, "/parties/"+org, renter, nil)
	require.Equal(t, http.StatusOK, status, body)
	assert.Equal(t, true, body["operator"])
	p, err = r.Party(ctx, org)
	require.NoError(t, err)
	assert.Equal(t, delegation.Party{Kind: delegation.KindOrg, Operator: true}, p)

	// A sole proprietor: a person who is an attested operator.
	status, body = h.do(http.MethodPut, "/parties/"+renter, dimoDID, map[string]any{"kind": "person", "operator": true})
	require.Equal(t, http.StatusOK, status, body)
	p, err = r.Party(ctx, renter)
	require.NoError(t, err)
	assert.Equal(t, delegation.Party{Kind: delegation.KindPerson, Operator: true}, p)
	assert.True(t, p.CanHaveMembers())
}

// Control state is read from the directory once per TTL, and a vehicle the
// directory does not hold has no eras.
func TestControlStateCache(t *testing.T) {
	h := newHost(t, store.NewMemoryStore())
	car := carOf(newOrgDID())
	h.clock = day(1)
	r := &Resolver{Store: h.repo.Store, Control: h.directory, Now: h.repo.now}
	ctx := t.Context()

	st, err := r.ControlState(ctx, car)
	require.NoError(t, err)
	assert.Empty(t, st.Eras)
	assert.Equal(t, 1, h.directory.calls)

	h.directory.set(car, &control.State{DID: car, Eras: []control.Era{{Number: 0, Commitment: "sha256:x"}}})
	st, err = r.ControlState(ctx, car)
	require.NoError(t, err)
	assert.Empty(t, st.Eras, "served from cache")
	assert.Equal(t, 1, h.directory.calls)

	h.clock = day(1).Add(DefaultControlCacheTTL)
	st, err = r.ControlState(ctx, car)
	require.NoError(t, err)
	assert.Len(t, st.Eras, 1)
	assert.Equal(t, 2, h.directory.calls)
}
