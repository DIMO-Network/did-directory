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

// The people of spec §13.1, Avis with three partners, and what each may do.
const (
	alice      = "did:dimo:alice"      // fleet manager: delegation:create + tag:write over fl-fleet
	carol      = "did:dimo:carol"      // admin: org:admin, org:members and the partner abilities over everything
	bob        = "did:dimo:bob"        // finance: delegation:create over financed-fc
	dave       = "did:dimo:dave"       // tag editor: tag:write + telemetry:read over fl-fleet
	fordCredit = "did:dimo:fordcredit" // lender
	integrator = "did:dimo:integrator" // Ford Pro's downstream
	partner    = "did:dimo:partner"    // a bob-authored grant's recipient
)

// avis is the §13.1 org on the host: registered, attested, three cars whose
// openings it holds, three tags and its staff roles. The default policy is
// narrowed to two vehicles so growth checks can be reached with three cars.
type avis struct {
	*host
	org string
	// fordPro is the telematics partner, an org on this host too. It is minted
	// with the org so runs against one Postgres database do not collide.
	fordPro string
	cars    []string
	tag     map[string]string // slug -> URI
}

func newAvis(t *testing.T, st store.Store) *avis {
	t.Helper()
	tight := delegation.DefaultPolicy()
	tight.VehicleApprovalThreshold = 2
	booking := agreement.CommitPolicy()
	h := newHostWith(t, st, Policies{tight.Name: tight, booking.Name: booking})
	a := &avis{host: h, org: newOrgDID(), tag: map[string]string{}}
	a.fordPro = a.org + "-fordpro"
	a.clock = day(1)

	status, body := a.do(http.MethodPost, "/orgs/"+a.org, a.org, nil)
	require.Equal(t, http.StatusCreated, status, body)
	status, body = a.do(http.MethodPut, "/parties/"+a.org, dimoDID, map[string]any{"kind": "org", "operator": true})
	require.Equal(t, http.StatusOK, status, body)

	for i := range 3 {
		car := a.org + "-car" + string(rune('1'+i))
		a.cars = append(a.cars, car)
		a.control(car, a.org)
	}
	for _, slug := range []string{"fl-fleet", "ford-pro-enrolled", "financed-fc"} {
		a.tag[slug] = "at://" + a.org + "/" + delegation.CollectionTag + "/" + slug
		status, body := a.do(http.MethodPut, "/orgs/"+a.org+"/"+delegation.CollectionTag+"/"+slug, a.org, map[string]any{"name": slug})
		require.Equal(t, http.StatusCreated, status, body)
	}
	fl := delegation.Covers{Tag: a.tag["fl-fleet"]}
	all := delegation.Covers{Inherit: true}
	a.grantRole(a.org, roleRecord(a.org, alice, fl, "delegation:create", "tag:write", "telemetry:read", "events:read"))
	a.grantRole(a.org, roleRecord(a.org, carol, all, "org:admin", "org:members", "delegation:create", "tag:write",
		"telemetry:read", "events:read", "location:precise", "health:read"))
	a.grantRole(a.org, roleRecord(a.org, bob, delegation.Covers{Tag: a.tag["financed-fc"]}, "delegation:create", "location:precise", "health:read"))
	a.grantRole(a.org, roleRecord(a.org, dave, fl, "tag:write", "telemetry:read"))
	return a
}

// control makes controller the controller of record for car, era 0, with the
// opening in controller's repository and the commitment in the directory.
func (h *host) control(car, controller string) {
	h.t.Helper()
	salt, err := control.NewSalt()
	require.NoError(h.t, err)
	opening := control.Opening{Controller: controller, Era: 0, Salt: salt}
	commitment, err := control.Commit(opening)
	require.NoError(h.t, err)
	h.directory.set(car, &control.State{DID: car, Eras: []control.Era{{Number: 0, Commitment: commitment}}})
	status, body := h.do(http.MethodPut, "/orgs/"+controller+"/"+delegation.CollectionVehicleControl+"/"+car, controller, opening)
	require.Equal(h.t, http.StatusCreated, status, body)
}

// keys returns a map's keys.
func keys[V any](m map[string]V) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	return out
}

// records returns the records in a collection that as can list.
func (a *avis) records(collection, as string) []map[string]any {
	a.t.Helper()
	status, body := a.do(http.MethodGet, "/orgs/"+a.org+"/"+collection, as, nil)
	require.Equal(a.t, http.StatusOK, status, body)
	out := []map[string]any{}
	for _, r := range body["records"].([]any) {
		out = append(out, r.(map[string]any))
	}
	return out
}

// listed returns the URIs of the records in a collection that as can list.
func (a *avis) listed(collection, as string) []string {
	a.t.Helper()
	out := []string{}
	for _, r := range a.records(collection, as) {
		out = append(out, r["uri"].(string))
	}
	return out
}

func (a *avis) path(collection, rkey string) string {
	return "/orgs/" + a.org + "/" + collection + "/" + rkey
}

func (a *avis) uri(collection, rkey string) string {
	return "at://" + a.org + "/" + collection + "/" + rkey
}

func (a *avis) grant(to string, covers delegation.Covers, abilities ...string) delegation.Record {
	return delegation.Record{
		Type: delegation.TypeDelegation, From: a.org, To: to, Covers: covers, Abilities: abilities,
		Validity:   delegation.Window{From: tp(day(1))},
		Redelegate: delegation.Redelegate{Mode: delegation.RedelegateNone}, CreatedAt: day(1),
	}
}

func (a *avis) join(tag, car string, at time.Time) delegation.MembershipRecord {
	return delegation.MembershipRecord{Tag: a.tag[tag], Vehicle: car, JoinedAt: at}
}

// approve has approver approve a pending write and returns the response.
func (a *avis) approve(id, approver string) (int, map[string]any) {
	a.t.Helper()
	return a.do(http.MethodPost, "/orgs/"+a.org+"/pending/"+id+"/approve", approver, nil)
}

// TestAvisActions walks the spec §13.1 table through the host, action by
// action: the three partner grants, adding cars, the transparency reads, the
// dealer's own-staff grant, dropping Ford Pro, Alice leaving, a compromised
// member and a defleeted car.
func TestAvisActions(t *testing.T) {
	for name, st := range stores(t) {
		t.Run(name, func(t *testing.T) {
			a := newAvis(t, st)
			car1, car2, car3 := a.cars[0], a.cars[1], a.cars[2]
			fl := delegation.Covers{Tag: a.tag["fl-fleet"]}
			fordPro := a.fordPro
			insurerURI := a.uri(delegation.CollectionDelegation, "insurer")
			fcURI := a.uri(delegation.CollectionDelegation, "fordcredit")
			fordProURI := a.uri(delegation.CollectionDelegation, "fordpro")
			integratorURI := "at://" + fordPro + "/" + delegation.CollectionDelegation + "/integrator"

			t.Run("grant three partners", func(t *testing.T) {
				// The insurer, over fl-fleet, by the fleet manager: inside her role,
				// nothing live, no approval needed.
				status, body := a.do(http.MethodPut, a.path(delegation.CollectionDelegation, "insurer"), alice,
					a.grant(insurer, fl, "telemetry:read", "events:read"))
				require.Equal(t, http.StatusCreated, status, body)

				// Ford Credit's lien, by finance: revocable only by the lender, so it
				// waits for a second approval. Not from Bob, not from the lender.
				lien := a.grant(fordCredit, delegation.Covers{Tag: a.tag["financed-fc"]}, "location:precise", "health:read")
				lien.RevocableBy = delegation.RevocableByTo
				lien.AfterTransfer = delegation.Drop
				status, body = a.do(http.MethodPut, a.path(delegation.CollectionDelegation, "fordcredit"), bob, lien)
				require.Equal(t, http.StatusAccepted, status, body)
				assert.Equal(t, []any{"cannot be revoked by the issuer"}, body["reasons"])
				id := body["pending"].(string)

				status, body = a.approve(id, bob)
				assert.Equal(t, http.StatusForbidden, status, body)
				status, body = a.approve(id, fordCredit)
				assert.Equal(t, http.StatusForbidden, status, body)
				status, body = a.approve(id, alice)
				assert.Equal(t, http.StatusForbidden, status, body, "alice's role does not cover financed-fc")
				// The pending list shows each member what they wrote or could
				// approve, nothing else.
				pending := func(as string) int {
					t.Helper()
					status, body := a.do(http.MethodGet, "/orgs/"+a.org+"/pending", as, nil)
					require.Equal(t, http.StatusOK, status, body)
					return len(body["pending"].([]any))
				}
				assert.Equal(t, 1, pending(carol), "carol may approve it")
				assert.Equal(t, 1, pending(bob), "bob wrote it")
				assert.Equal(t, 0, pending(alice), "outside alice's scope")
				assert.Equal(t, 0, pending(dave), "dave issues no grants")
				status, body = a.approve(id, carol)
				require.Equal(t, http.StatusCreated, status, body)
				status, body = a.approve(id, carol)
				assert.Equal(t, http.StatusNotFound, status, body, "approved once")
				status, body = a.do(http.MethodGet, a.path(delegation.CollectionDelegation, "fordcredit"), carol, nil)
				require.Equal(t, http.StatusOK, status, body)
				assert.Equal(t, bob, body["committedBy"])
				assert.Equal(t, []any{carol}, body["approvedBy"])

				// A lien from an org nobody attested as an operator is refused
				// outright, not parked.
				other := newOrgDID()
				status, body = a.do(http.MethodPost, "/orgs/"+other, other, nil)
				require.Equal(t, http.StatusCreated, status, body)
				stranger := lien
				stranger.From = other
				stranger.Covers = delegation.Covers{Vehicle: car1}
				status, body = a.do(http.MethodPut, "/orgs/"+other+"/"+delegation.CollectionDelegation+"/lien", other, stranger)
				assert.Equal(t, http.StatusForbidden, status, body)
				assert.Contains(t, body["error"], "attested operator")

				// Ford Pro gets commands: nobody on staff holds those, so the org
				// writes it as itself, and the org's own writes wait for approval
				// like anyone's. Carol may approve a grant over a scope she may
				// issue grants in, though she could not have written this one.
				fp := a.grant(fordPro, delegation.Covers{Tag: a.tag["ford-pro-enrolled"]}, "telemetry:read", "command:lock", "command:unlock")
				fp.Redelegate = delegation.Redelegate{Mode: delegation.RedelegateAttenuated, MaxDepth: 1}
				status, body = a.do(http.MethodPut, a.path(delegation.CollectionDelegation, "fordpro"), carol, fp)
				assert.Equal(t, http.StatusForbidden, status, body)
				assert.Contains(t, body["error"], "command:lock")
				status, body = a.do(http.MethodPut, a.path(delegation.CollectionDelegation, "fordpro"), a.org, fp)
				require.Equal(t, http.StatusAccepted, status, body)
				assert.ElementsMatch(t, []any{"grants live ability command:lock", "grants live ability command:unlock"}, body["reasons"])
				id = body["pending"].(string)
				status, body = a.approve(id, a.org)
				assert.Equal(t, http.StatusForbidden, status, body, "the org cannot approve its own write")
				assert.Equal(t, 1, pending(carol), "carol may approve what she could not write")
				assert.Equal(t, 0, pending(bob))
				status, body = a.approve(id, bob)
				assert.Equal(t, http.StatusForbidden, status, body, "bob's role does not cover ford-pro-enrolled")
				status, body = a.approve(id, carol)
				require.Equal(t, http.StatusCreated, status, body)

				// Ford Pro passes telemetry to its integrator from its own repository.
				status, body = a.do(http.MethodPost, "/orgs/"+fordPro, fordPro, nil)
				require.Equal(t, http.StatusCreated, status, body)
				status, body = a.do(http.MethodPut, "/parties/"+fordPro, dimoDID, map[string]any{"kind": "org", "operator": true})
				require.Equal(t, http.StatusOK, status, body)
				down := delegation.Record{
					Type: delegation.TypeDelegation, From: fordPro, To: integrator, Basis: []string{fordProURI},
					Covers: delegation.Covers{Inherit: true}, Abilities: []string{"telemetry:read"},
					Validity:   delegation.Window{From: tp(day(1))},
					Redelegate: delegation.Redelegate{Mode: delegation.RedelegateNone}, CreatedAt: day(1),
				}
				status, body = a.do(http.MethodPut, "/orgs/"+fordPro+"/"+delegation.CollectionDelegation+"/integrator", fordPro, down)
				require.Equal(t, http.StatusCreated, status, body)
			})

			t.Run("add a car", func(t *testing.T) {
				a.clock = day(2)
				status, body := a.do(http.MethodPost, a.path(delegation.CollectionTagMembership, ""), alice, a.join("fl-fleet", car1, day(2)))
				require.Equal(t, http.StatusCreated, status, body)

				// Dave may edit the tag, but the insurer's grant covers events:read
				// and Dave never held that, so his membership would not count (§9.2).
				status, body = a.do(http.MethodPost, a.path(delegation.CollectionTagMembership, ""), dave, a.join("fl-fleet", car2, day(2)))
				require.Equal(t, http.StatusForbidden, status, body)
				assert.Contains(t, body["error"], insurerURI)

				status, body = a.do(http.MethodPost, a.path(delegation.CollectionTagMembership, ""), alice, a.join("fl-fleet", car2, day(2)))
				require.Equal(t, http.StatusCreated, status, body)

				// The third car pushes the insurer's grant past the threshold.
				status, body = a.do(http.MethodPost, a.path(delegation.CollectionTagMembership, ""), alice, a.join("fl-fleet", car3, day(2)))
				require.Equal(t, http.StatusAccepted, status, body)
				assert.Contains(t, body["reasons"].([]any)[0], "3 vehicles")
				status, body = a.approve(body["pending"].(string), carol)
				require.Equal(t, http.StatusCreated, status, body)
				assert.Equal(t, "create", body["op"])

				// Other tags are other roles' business.
				status, body = a.do(http.MethodPost, a.path(delegation.CollectionTagMembership, ""), alice, a.join("financed-fc", car1, day(2)))
				assert.Equal(t, http.StatusForbidden, status, body)
				status, body = a.do(http.MethodPost, a.path(delegation.CollectionTagMembership, ""), bob, a.join("financed-fc", car1, day(2)))
				assert.Equal(t, http.StatusForbidden, status, body, "bob has no tag:write")
				status, body = a.do(http.MethodPost, a.path(delegation.CollectionTagMembership, ""), a.org, a.join("financed-fc", car1, day(2)))
				require.Equal(t, http.StatusCreated, status, body)
				status, body = a.do(http.MethodPost, a.path(delegation.CollectionTagMembership, ""), carol, a.join("ford-pro-enrolled", car1, day(2)))
				require.Equal(t, http.StatusForbidden, status, body, "carol cannot widen a grant of commands")
				assert.Contains(t, body["error"], fordProURI)
				status, body = a.do(http.MethodPost, a.path(delegation.CollectionTagMembership, ""), a.org, a.join("ford-pro-enrolled", car1, day(2)))
				require.Equal(t, http.StatusCreated, status, body)
			})

			t.Run("the partners are authorized", func(t *testing.T) {
				status, body := a.authorize(day(5), insurerURI, insurer, car1, "telemetry:read")
				require.Equal(t, http.StatusOK, status, body)
				assert.True(t, window(t, body, "telemetry:read").Contains(day(3)))
				status, body = a.authorize(day(5), insurerURI, insurer, car3, "events:read")
				require.Equal(t, http.StatusOK, status, body, "the approved membership counts")
				status, body = a.authorize(day(5), fcURI, fordCredit, car1, "location:precise")
				require.Equal(t, http.StatusOK, status, body, "the approved lien evaluates")
				status, body = a.authorize(day(5), fordProURI, fordPro, car1, "command:lock")
				require.Equal(t, http.StatusOK, status, body)
				assert.Equal(t, []any{"command:lock"}, body["live"])
				status, body = a.authorize(day(5), integratorURI, integrator, car1, "telemetry:read")
				require.Equal(t, http.StatusOK, status, body, "a chain through two repositories on this host")
				assert.Equal(t, []any{integratorURI, fordProURI}, body["chain"])
			})

			t.Run("who may read", func(t *testing.T) {
				a.clock = day(5)
				status, body := a.do(http.MethodGet, a.path(delegation.CollectionDelegation, "insurer"), fordCredit, nil)
				assert.Equal(t, http.StatusForbidden, status, body, "grantees do not read the repository")
				status, body = a.do(http.MethodGet, a.path(delegation.CollectionDelegation, "insurer"), alice, nil)
				assert.Equal(t, http.StatusOK, status, body)
				status, body = a.do(http.MethodGet, a.path(delegation.CollectionVehicleControl, car1), alice, nil)
				assert.Equal(t, http.StatusForbidden, status, body, "openings are for admins")
				status, body = a.do(http.MethodGet, a.path(delegation.CollectionVehicleControl, car1), carol, nil)
				assert.Equal(t, http.StatusOK, status, body)
				status, body = a.do(http.MethodGet, "/orgs/"+a.org+"/commits", alice, nil)
				assert.Equal(t, http.StatusForbidden, status, body)
				status, body = a.do(http.MethodGet, "/orgs/"+a.org+"/commits", carol, nil)
				assert.Equal(t, http.StatusOK, status, body)
				status, body = a.do(http.MethodGet, "/orgs/"+a.org+"/pending", fordCredit, nil)
				assert.Equal(t, http.StatusForbidden, status, body)

				// Without org:read a member reads only what they wrote (spec §6.2).
				// A record out of reach is not found, as if it did not exist.
				status, body = a.do(http.MethodGet, a.path(delegation.CollectionDelegation, "insurer"), dave, nil)
				assert.Equal(t, http.StatusNotFound, status, body, "dave did not write the insurer's grant")
				status, body = a.do(http.MethodGet, a.path(delegation.CollectionDelegation, "fordcredit"), bob, nil)
				assert.Equal(t, http.StatusOK, status, body, "bob wrote the lien")
				assert.ElementsMatch(t, []string{a.uri(delegation.CollectionDelegation, "fordcredit")}, a.listed(delegation.CollectionDelegation, bob))
				assert.Empty(t, a.listed(delegation.CollectionDelegation, dave))

				// An org:read role over fl-fleet reads the records about that tag and
				// its cars: the insurer's grant and the tag itself, not the lien, not
				// Ford Pro's grant, not another tag, and never the openings.
				reader := a.org + "-reader"
				// A role over a tag with more cars than this fixture's threshold of
				// two waits for a second approval, here Carol's.
				readRole := func(member string, covers delegation.Covers) {
					t.Helper()
					status, body := a.do(http.MethodPost, a.path(delegation.CollectionRole, ""), a.org, roleRecord(a.org, member, covers, delegation.AbilityOrgRead))
					if status == http.StatusAccepted {
						status, body = a.approve(body["pending"].(string), carol)
					}
					require.Equal(t, http.StatusCreated, status, body)
				}
				readRole(reader, fl)
				assert.ElementsMatch(t, []string{insurerURI}, a.listed(delegation.CollectionDelegation, reader))
				status, body = a.do(http.MethodGet, a.path(delegation.CollectionDelegation, "fordcredit"), reader, nil)
				assert.Equal(t, http.StatusNotFound, status, body)
				status, body = a.do(http.MethodGet, a.path(delegation.CollectionTag, "fl-fleet"), reader, nil)
				assert.Equal(t, http.StatusOK, status, body)
				status, body = a.do(http.MethodGet, a.path(delegation.CollectionTag, "financed-fc"), reader, nil)
				assert.Equal(t, http.StatusNotFound, status, body)
				status, body = a.do(http.MethodGet, a.path(delegation.CollectionVehicleControl, car1), reader, nil)
				assert.Equal(t, http.StatusForbidden, status, body)
				// Memberships: every one in fl-fleet, and those of other tags only
				// for cars in fl-fleet now.
				all := a.records(delegation.CollectionTagMembership, carol)
				inFleet := map[string]bool{}
				for _, m := range all {
					rec := m["record"].(map[string]any)
					if rec["tag"] == a.tag["fl-fleet"] && rec["leftAt"] == nil {
						inFleet[rec["vehicle"].(string)] = true
					}
				}
				want := []string{}
				for _, m := range all {
					rec := m["record"].(map[string]any)
					if rec["tag"] == a.tag["fl-fleet"] || inFleet[rec["vehicle"].(string)] {
						want = append(want, m["uri"].(string))
					}
				}
				require.NotEmpty(t, want)
				assert.ElementsMatch(t, want, a.listed(delegation.CollectionTagMembership, reader))

				// Paging past records the reader may not see: one record a page, the
				// last key as the cursor, ends with what one unpaged list shows.
				paged, after := []string{}, ""
				for range 20 {
					status, body := a.do(http.MethodGet, "/orgs/"+a.org+"/"+delegation.CollectionDelegation+"?limit=1&after="+after, reader, nil)
					require.Equal(t, http.StatusOK, status, body)
					page := body["records"].([]any)
					if len(page) == 0 {
						break
					}
					require.Len(t, page, 1)
					r := page[0].(map[string]any)
					paged = append(paged, r["uri"].(string))
					after = r["rkey"].(string)
				}
				assert.Equal(t, []string{insurerURI}, paged)
				assert.Greater(t, len(a.listed(delegation.CollectionDelegation, carol)), 2, "the reader's grant is not the first key")

				// An org-wide org:read role reads every record, still not the openings
				// or the log.
				wide := a.org + "-auditor"
				readRole(wide, delegation.Covers{Inherit: true})
				assert.ElementsMatch(t, a.listed(delegation.CollectionDelegation, carol), a.listed(delegation.CollectionDelegation, wide))
				status, body = a.do(http.MethodGet, "/orgs/"+a.org+"/commits", wide, nil)
				assert.Equal(t, http.StatusForbidden, status, body)
				status, body = a.do(http.MethodGet, a.path(delegation.CollectionVehicleControl, car1), wide, nil)
				assert.Equal(t, http.StatusForbidden, status, body)
			})

			t.Run("who can reach a car", func(t *testing.T) {
				a.clock = day(5)
				access := func(car, as string) (int, map[string]any, map[string]map[string]any) {
					t.Helper()
					status, body := a.do(http.MethodGet, "/orgs/"+a.org+"/vehicles/"+car+"/access", as, nil)
					byURI := map[string]map[string]any{}
					if list, ok := body["access"].([]any); ok {
						for _, d := range list {
							d := d.(map[string]any)
							byURI[d["uri"].(string)] = d
						}
					}
					return status, body, byURI
				}

				// car1 is in all three tags: each partner's grant reaches it, and
				// Ford Pro's integrator one step further down, in Ford Pro's own
				// repository.
				status, body, got := access(car1, a.org)
				require.Equal(t, http.StatusOK, status, body)
				assert.ElementsMatch(t, []any{a.tag["fl-fleet"], a.tag["financed-fc"], a.tag["ford-pro-enrolled"]}, body["tags"])
				assert.ElementsMatch(t, []string{insurerURI, fcURI, fordProURI, integratorURI}, keys(got))
				for _, uri := range []string{insurerURI, fcURI, fordProURI} {
					assert.Equal(t, float64(1), got[uri]["depth"], uri)
				}
				assert.Equal(t, float64(2), got[integratorURI]["depth"])
				assert.Equal(t, []any{fordProURI}, got[integratorURI]["basis"])
				for uri, d := range got {
					assert.Nil(t, d["refused"], uri)
					assert.NotNil(t, d["coverage"], uri)
				}

				// car3 is only in fl-fleet.
				status, body, got = access(car3, carol)
				require.Equal(t, http.StatusOK, status, body)
				assert.Equal(t, []any{a.tag["fl-fleet"]}, body["tags"])
				assert.ElementsMatch(t, []string{insurerURI}, keys(got))

				// It is the org's view, and org:admin's; a scoped reader does not get it.
				status, body, _ = access(car1, alice)
				assert.Equal(t, http.StatusForbidden, status, body)
				status, body, _ = access(car1, a.org+"-reader")
				assert.Equal(t, http.StatusForbidden, status, body)
				status, body, _ = access(car1, fordPro)
				assert.Equal(t, http.StatusForbidden, status, body)
				status, body, _ = access("not-a-did", a.org)
				assert.Equal(t, http.StatusBadRequest, status, body)
			})

			t.Run("what a grant reaches", func(t *testing.T) {
				a.clock = day(5)
				// The vehicles a grant covers now, by DID, for its recipient and
				// the org that holds it.
				reaches := func(org, rkey, as, query string) (int, map[string]any, []string) {
					t.Helper()
					status, body := a.do(http.MethodGet, "/orgs/"+org+"/delegations/"+rkey+"/vehicles"+query, as, nil)
					cars := []string{}
					if list, ok := body["vehicles"].([]any); ok {
						for _, v := range list {
							v := v.(map[string]any)
							cars = append(cars, v["vehicle"].(string))
							assert.NotEmpty(t, v["historical"], "each comes with what the grant gives there")
						}
					}
					return status, body, cars
				}
				status, body, cars := reaches(a.org, "insurer", insurer, "")
				require.Equal(t, http.StatusOK, status, body)
				assert.Equal(t, insurerURI, body["delegation"])
				assert.Equal(t, []string{car1, car2, car3}, cars, "every car in fl-fleet")
				_, _, cars = reaches(a.org, "fordcredit", fordCredit, "")
				assert.Equal(t, []string{car1}, cars)
				_, _, cars = reaches(a.org, "fordpro", fordPro, "")
				assert.Equal(t, []string{car1}, cars)
				// covers.inherit reaches what its basis does, across repositories.
				_, _, cars = reaches(fordPro, "integrator", integrator, "")
				assert.Equal(t, []string{car1}, cars)
				_, _, cars = reaches(a.org, "insurer", a.org, "")
				assert.Equal(t, []string{car1, car2, car3}, cars, "the org may ask too")

				// Pages are filled with covered cars; the last is the cursor.
				_, _, cars = reaches(a.org, "insurer", insurer, "?limit=2")
				assert.Equal(t, []string{car1, car2}, cars)
				_, _, cars = reaches(a.org, "insurer", insurer, "?limit=2&after="+car2)
				assert.Equal(t, []string{car3}, cars)

				// The org's admin reads every record already, so may ask too.
				_, _, cars = reaches(a.org, "insurer", carol, "")
				assert.Equal(t, []string{car1, car2, car3}, cars, "org:admin")
				// Nobody else: a scoped member, another partner. They are told
				// what a key never written tells them, so a guessed key confirms
				// no grant and names no partner.
				status, missing, _ := reaches(a.org, "nope", insurer, "")
				assert.Equal(t, http.StatusNotFound, status, missing)
				for _, as := range []string{alice, fordCredit} {
					status, body, _ = reaches(a.org, "insurer", as, "")
					assert.Equal(t, http.StatusNotFound, status, "%s: %v", as, body)
					assert.Equal(t, missing, body)
				}
			})

			t.Run("recipients read their own records", func(t *testing.T) {
				a.clock = day(5)
				// The insurer holds no role in the org, but the grant is addressed
				// to it.
				status, body := a.do(http.MethodGet, a.path(delegation.CollectionDelegation, "insurer"), insurer, nil)
				require.Equal(t, http.StatusOK, status, body)
				assert.Equal(t, insurerURI, body["uri"])
				// Anything else is refused the same way, whether or not it exists.
				status, body = a.do(http.MethodGet, a.path(delegation.CollectionDelegation, "fordcredit"), insurer, nil)
				assert.Equal(t, http.StatusForbidden, status, body)
				refused := body["error"]
				status, body = a.do(http.MethodGet, a.path(delegation.CollectionDelegation, "nope"), insurer, nil)
				assert.Equal(t, http.StatusForbidden, status, body)
				assert.Equal(t, refused, body["error"], "no existence oracle")
				status, body = a.do(http.MethodGet, a.path(delegation.CollectionTag, "fl-fleet"), insurer, nil)
				assert.Equal(t, http.StatusForbidden, status, body, "only delegations and roles are addressed")

				// A member reads the role addressed to them without org:read; a
				// member who could not read it otherwise still gets 404.
				roles, err := a.repo.Store.Roles(t.Context(), a.org, alice)
				require.NoError(t, err)
				require.Len(t, roles, 1)
				rkey := roles[0].RKey
				status, body = a.do(http.MethodGet, a.path(delegation.CollectionRole, rkey), alice, nil)
				assert.Equal(t, http.StatusOK, status, body)
				status, body = a.do(http.MethodGet, a.path(delegation.CollectionRole, rkey), dave, nil)
				assert.Equal(t, http.StatusNotFound, status, body)
			})

			t.Run("staff are customers too", func(t *testing.T) {
				a.clock = day(5)
				status, body := a.do(http.MethodPut, a.path(delegation.CollectionDelegation, "alice-self"), alice, a.grant(alice, fl, "telemetry:read"))
				require.Equal(t, http.StatusAccepted, status, body)
				assert.Contains(t, body["reasons"], "author is the recipient")
				id := body["pending"].(string)
				status, body = a.approve(id, alice)
				assert.Equal(t, http.StatusForbidden, status, body)
				status, body = a.approve(id, carol)
				require.Equal(t, http.StatusCreated, status, body)
				status, body = a.authorize(day(5), a.uri(delegation.CollectionDelegation, "alice-self"), alice, car1, "telemetry:read")
				require.Equal(t, http.StatusOK, status, body)

				// Or she thinks better of it.
				status, body = a.do(http.MethodPut, a.path(delegation.CollectionDelegation, "alice-more"), alice, a.grant(alice, fl, "events:read"))
				require.Equal(t, http.StatusAccepted, status, body)
				id = body["pending"].(string)
				status, body = a.do(http.MethodDelete, "/orgs/"+a.org+"/pending/"+id, bob, nil)
				assert.Equal(t, http.StatusForbidden, status, body)
				status, body = a.do(http.MethodDelete, "/orgs/"+a.org+"/pending/"+id, alice, nil)
				assert.Equal(t, http.StatusOK, status, body)
				status, body = a.approve(id, carol)
				assert.Equal(t, http.StatusNotFound, status, body)

				// Somebody with no authority to grant is refused, not parked.
				status, body = a.do(http.MethodPut, a.path(delegation.CollectionDelegation, "dave-self"), dave, a.grant(dave, fl, "telemetry:read"))
				assert.Equal(t, http.StatusForbidden, status, body)
			})

			t.Run("roles written by members", func(t *testing.T) {
				a.clock = day(5)
				erin := "did:dimo:erin"
				// Carol may hand out what she holds, and no more. A role over the
				// three-car tag is past the threshold, so the org approves it.
				status, body := a.do(http.MethodPost, a.path(delegation.CollectionRole, ""), carol, roleRecord(a.org, erin, fl, "tag:write", "telemetry:read", "events:read"))
				require.Equal(t, http.StatusAccepted, status, body)
				assert.Equal(t, []any{"covers 3 vehicles (threshold 2)"}, body["reasons"])
				erinRole := body["uri"].(string)
				status, body = a.approve(body["pending"].(string), a.org)
				require.Equal(t, http.StatusCreated, status, body)
				status, body = a.do(http.MethodGet, a.path(delegation.CollectionRole, ""), carol, nil)
				require.Equal(t, http.StatusOK, status, body)
				for _, r := range body["records"].([]any) {
					if r.(map[string]any)["uri"] == erinRole {
						assert.Equal(t, carol, r.(map[string]any)["committedBy"])
						assert.Equal(t, []any{a.org}, r.(map[string]any)["approvedBy"])
					}
				}
				status, body = a.do(http.MethodPost, a.path(delegation.CollectionTagMembership, ""), erin, a.join("fl-fleet", car1, day(5)))
				require.Equal(t, http.StatusCreated, status, "erin's role works: %v", body)
				status, body = a.do(http.MethodPost, a.path(delegation.CollectionRole, ""), carol, roleRecord(a.org, erin, fl, "command:unlock"))
				assert.Equal(t, http.StatusForbidden, status, body)
				status, body = a.do(http.MethodPost, a.path(delegation.CollectionRole, ""), alice, roleRecord(a.org, erin, fl, "tag:write"))
				assert.Equal(t, http.StatusForbidden, status, body, "alice has no org:members")

				// A role names a policy the host knows, or nothing.
				bad := roleRecord(a.org, erin, fl, "tag:write")
				bad.Constraints = &delegation.RoleConstraints{Policy: "nope"}
				status, body = a.do(http.MethodPost, a.path(delegation.CollectionRole, ""), a.org, bad)
				assert.Equal(t, http.StatusBadRequest, status, body)

				// And Carol may end what she handed out.
				_, _, rkey, err := delegation.ParseURI(erinRole)
				require.NoError(t, err)
				status, body = a.do(http.MethodDelete, a.path(delegation.CollectionRole, rkey), alice, nil)
				assert.Equal(t, http.StatusForbidden, status, body)
				status, body = a.do(http.MethodDelete, a.path(delegation.CollectionRole, rkey), carol, nil)
				require.Equal(t, http.StatusOK, status, body)
				status, body = a.do(http.MethodPost, a.path(delegation.CollectionTagMembership, ""), erin, a.join("fl-fleet", car2, day(5)))
				assert.Equal(t, http.StatusForbidden, status, body, "the tombstone by a member counts")
			})

			t.Run("drop Ford Pro", func(t *testing.T) {
				a.clock = day(6)
				status, body := a.do(http.MethodDelete, a.path(delegation.CollectionDelegation, "fordpro"), alice, nil)
				assert.Equal(t, http.StatusForbidden, status, body, "alice's role does not cover ford-pro-enrolled")
				status, body = a.do(http.MethodDelete, a.path(delegation.CollectionDelegation, "fordpro"), fordPro, nil)
				assert.Equal(t, http.StatusForbidden, status, body, "the recipient cannot revoke a grant revocable by its issuer")
				status, body = a.do(http.MethodDelete, a.path(delegation.CollectionDelegation, "fordpro"), carol, nil)
				require.Equal(t, http.StatusOK, status, body)
				status, body = a.authorize(day(7), fordProURI, fordPro, car1, "command:lock")
				require.Equal(t, http.StatusForbidden, status, body)
				assert.Equal(t, CodeRevoked, body["code"], "a member's tombstone is honoured by the evaluator")
				status, body = a.authorize(day(7), integratorURI, integrator, car1, "telemetry:read")
				require.Equal(t, http.StatusForbidden, status, body)
				assert.Equal(t, CodeRevoked, body["code"], "the integrator's delegation dies with it")

				// The recipient still reads what it was given, as a tombstone, and
				// it reaches no car.
				status, body = a.do(http.MethodGet, a.path(delegation.CollectionDelegation, "fordpro"), fordPro, nil)
				assert.Equal(t, http.StatusGone, status, body)
				assert.NotNil(t, body["tombstone"])
				status, body = a.do(http.MethodGet, "/orgs/"+a.org+"/delegations/fordpro/vehicles", fordPro, nil)
				require.Equal(t, http.StatusOK, status, body)
				assert.Empty(t, body["vehicles"])
			})

			t.Run("Alice leaves", func(t *testing.T) {
				a.clock = day(8)
				status, body := a.do(http.MethodGet, a.path(delegation.CollectionRole, ""), carol, nil)
				require.Equal(t, http.StatusOK, status, body)
				var aliceRole string
				for _, r := range body["records"].([]any) {
					rec := r.(map[string]any)["record"].(map[string]any)
					if rec["assignee"] == alice {
						aliceRole = r.(map[string]any)["rkey"].(string)
					}
				}
				require.NotEmpty(t, aliceRole)
				status, body = a.do(http.MethodDelete, a.path(delegation.CollectionRole, aliceRole), bob, nil)
				assert.Equal(t, http.StatusForbidden, status, body)
				status, body = a.do(http.MethodDelete, a.path(delegation.CollectionRole, aliceRole), carol, nil)
				require.Equal(t, http.StatusOK, status, body)

				status, body = a.do(http.MethodPost, a.path(delegation.CollectionTagMembership, ""), alice, a.join("fl-fleet", car1, day(8)))
				assert.Equal(t, http.StatusForbidden, status, body)
				status, body = a.do(http.MethodGet, a.path(delegation.CollectionDelegation, "insurer"), alice, nil)
				assert.Equal(t, http.StatusForbidden, status, body, "no longer a member")
				status, body = a.authorize(day(9), insurerURI, insurer, car1, "telemetry:read")
				require.Equal(t, http.StatusOK, status, body, "her agreements survive")
			})

			t.Run("compromised member", func(t *testing.T) {
				a.clock = day(10)
				status, body := a.do(http.MethodPut, a.path(delegation.CollectionDelegation, "partner"), bob,
					a.grant(partner, delegation.Covers{Tag: a.tag["financed-fc"]}, "location:precise"))
				require.Equal(t, http.StatusCreated, status, body)
				partnerURI := a.uri(delegation.CollectionDelegation, "partner")
				status, body = a.authorize(day(10), partnerURI, partner, car1, "location:precise")
				require.Equal(t, http.StatusOK, status, body)

				review := map[string]any{"member": bob, "since": day(0).Format(time.RFC3339)}
				status, body = a.do(http.MethodPost, "/orgs/"+a.org+"/revoke-authored-by", fordCredit, review)
				assert.Equal(t, http.StatusForbidden, status, body)
				status, body = a.do(http.MethodPost, "/orgs/"+a.org+"/revoke-authored-by", carol, review)
				require.Equal(t, http.StatusOK, status, body)
				var uris []string
				for _, r := range body["records"].([]any) {
					uris = append(uris, r.(map[string]any)["uri"].(string))
				}
				assert.ElementsMatch(t, []string{fcURI, partnerURI}, uris)

				// The lien is the lender's to release, so the batch as reviewed is
				// refused before anything is written.
				review["uris"] = uris
				status, body = a.do(http.MethodPost, "/orgs/"+a.org+"/revoke-authored-by", carol, review)
				assert.Equal(t, http.StatusForbidden, status, body)
				assert.Contains(t, body["error"], fcURI)
				status, body = a.authorize(day(10), partnerURI, partner, car1, "location:precise")
				require.Equal(t, http.StatusOK, status, body, "nothing was revoked")

				review["uris"] = []string{partnerURI, insurerURI}
				status, body = a.do(http.MethodPost, "/orgs/"+a.org+"/revoke-authored-by", carol, review)
				assert.Equal(t, http.StatusBadRequest, status, body, "the insurer's grant is not bob's")

				review["uris"] = []string{partnerURI}
				status, body = a.do(http.MethodPost, "/orgs/"+a.org+"/revoke-authored-by", carol, review)
				require.Equal(t, http.StatusOK, status, body)
				assert.Len(t, body["revoked"], 1)
				status, body = a.authorize(day(11), partnerURI, partner, car1, "location:precise")
				require.Equal(t, http.StatusForbidden, status, body)
				assert.Equal(t, CodeRevoked, body["code"])

				// The lender releases its own lien.
				status, body = a.do(http.MethodDelete, a.path(delegation.CollectionDelegation, "fordcredit"), fordCredit, nil)
				require.Equal(t, http.StatusOK, status, body)
				status, body = a.authorize(day(11), fcURI, fordCredit, car1, "location:precise")
				require.Equal(t, http.StatusForbidden, status, body)
				assert.Equal(t, CodeRevoked, body["code"])
			})

			t.Run("car defleeted", func(t *testing.T) {
				// One transfer op in the directory ends the era on day 12.
				a.directory.mu.Lock()
				st := a.directory.states[car1]
				st.Eras[0].End = tp(day(12))
				a.directory.mu.Unlock()

				status, body := a.authorize(day(13), insurerURI, insurer, car1, "telemetry:read")
				require.Equal(t, http.StatusOK, status, body, "the insurer keeps its Avis-era history")
				w := window(t, body, "telemetry:read")
				assert.True(t, w.Contains(day(5)))
				assert.False(t, w.Contains(day(12)))

				// The insurer's grant keeps history, so car1 is still among its
				// cars; the lien drops at transfer, so the lender's list is empty.
				a.clock = day(13)
				status, body = a.do(http.MethodGet, "/orgs/"+a.org+"/delegations/insurer/vehicles", insurer, nil)
				require.Equal(t, http.StatusOK, status, body)
				assert.Equal(t, car1, body["vehicles"].([]any)[0].(map[string]any)["vehicle"])
				status, body = a.do(http.MethodGet, "/orgs/"+a.org+"/delegations/fordcredit/vehicles", fordCredit, nil)
				require.Equal(t, http.StatusOK, status, body)
				assert.Empty(t, body["vehicles"])
			})
		})
	}
}

// The booking service commits custody grants unattended because its role
// names the booking policy; a role without it parks every live grant, and a
// role naming it still cannot exceed its constraints.
func TestBookingRolePolicy(t *testing.T) {
	h := newHost(t, store.NewMemoryStore())
	org := newOrgDID()
	car := carOf(org)
	h.fleet(org)
	h.clock = day(9)

	// The compiled custody grant lands directly under the booking role.
	driving := rental(org)
	grants := h.compile(&driving, day(11))
	require.NotEmpty(t, grants)
	h.commitGrants(org, grants)

	// A second service with the same abilities but no policy waits for
	// approval on every live grant.
	const plain = "did:dimo:plain-backend"
	status, body := h.do(http.MethodPost, "/orgs/"+org+"/"+delegation.CollectionRole, org,
		roleRecord(org, plain, delegation.Covers{Inherit: true}, agreement.RentalCatalog().Abilities()...))
	require.Equal(t, http.StatusAccepted, status, body)
	status, body = h.do(http.MethodPost, "/orgs/"+org+"/pending/"+body["pending"].(string)+"/approve", admin, nil)
	require.Equal(t, http.StatusCreated, status, body)
	custody := grants[0].Record
	custody.CreatedBy = plain
	status, body = h.do(http.MethodPut, "/orgs/"+org+"/"+delegation.CollectionDelegation+"/plain", plain, custody)
	require.Equal(t, http.StatusAccepted, status, body)
	assert.Contains(t, body["reasons"].([]any)[0], "grants live ability")

	// And the booking role's constraints still bind: no redelegable grants.
	wide := grants[0].Record
	wide.Redelegate = delegation.Redelegate{Mode: delegation.RedelegateAttenuated, MaxDepth: 1}
	status, body = h.do(http.MethodPut, "/orgs/"+org+"/"+delegation.CollectionDelegation+"/wide", backend, wide)
	require.Equal(t, http.StatusForbidden, status, body)
	assert.Contains(t, body["error"], "redelegable")

	// Custody periods take delegation:create over the car.
	status, body = h.do(http.MethodPost, "/orgs/"+org+"/"+delegation.CollectionCustody, valet,
		delegation.CustodyPeriod{Vehicle: car, Holder: renter, From: day(10)})
	assert.Equal(t, http.StatusForbidden, status, body)
	status, body = h.do(http.MethodPost, "/orgs/"+org+"/"+delegation.CollectionCustody, backend,
		delegation.CustodyPeriod{Vehicle: car, Holder: renter, From: day(10)})
	assert.Equal(t, http.StatusCreated, status, body)
}

// TestOverwriteTakesWhatRevokingTakes: a PUT onto a live record's key replaces
// it, which takes the old record away as a tombstone would. Checking only the
// new body let an issuer release a lien only its lender may release, and let a
// member replace a grant outside their scope with one inside it.
func TestOverwriteTakesWhatRevokingTakes(t *testing.T) {
	for name, st := range stores(t) {
		t.Run(name, func(t *testing.T) {
			a := newAvis(t, st)
			fl := delegation.Covers{Tag: a.tag["fl-fleet"]}
			financed := delegation.Covers{Tag: a.tag["financed-fc"]}

			lien := a.grant(fordCredit, financed, "location:precise", "health:read")
			lien.RevocableBy = delegation.RevocableByTo
			status, body := a.do(http.MethodPut, a.path(delegation.CollectionDelegation, "fordcredit"), bob, lien)
			require.Equal(t, http.StatusAccepted, status, body)
			status, body = a.approve(body["pending"].(string), carol)
			require.Equal(t, http.StatusCreated, status, body)

			// Neither the author nor the org may revoke it, so neither may rewrite it.
			released := lien
			released.RevocableBy = delegation.RevocableByFrom
			for _, as := range []string{bob, a.org} {
				status, body = a.do(http.MethodPut, a.path(delegation.CollectionDelegation, "fordcredit"), as, released)
				assert.Equal(t, http.StatusForbidden, status, body)
				assert.Contains(t, body["error"], "overwriting")
			}
			status, body = a.do(http.MethodGet, a.path(delegation.CollectionDelegation, "fordcredit"), carol, nil)
			require.Equal(t, http.StatusOK, status, body)
			assert.Equal(t, "to", body["record"].(map[string]any)["dimo:revocableBy"])

			// Alice's insurer grant over fl-fleet is outside Bob's role, so he cannot
			// replace it with one inside it.
			status, body = a.do(http.MethodPut, a.path(delegation.CollectionDelegation, "insurer"), alice,
				a.grant(insurer, fl, "telemetry:read", "events:read"))
			require.Equal(t, http.StatusCreated, status, body)
			status, body = a.do(http.MethodPut, a.path(delegation.CollectionDelegation, "insurer"), bob,
				a.grant(insurer, financed, "location:precise"))
			assert.Equal(t, http.StatusForbidden, status, body)
			assert.Contains(t, body["error"], "overwriting")

			// Alice may still update her own grant under its stable key, which is
			// how a booking service upserts.
			status, body = a.do(http.MethodPut, a.path(delegation.CollectionDelegation, "insurer"), alice,
				a.grant(insurer, fl, "telemetry:read"))
			assert.Equal(t, http.StatusOK, status, body)
		})
	}
}
