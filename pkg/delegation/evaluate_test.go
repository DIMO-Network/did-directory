package delegation

import (
	"context"
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/DIMO-Network/did-directory/pkg/control"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const (
	avis       = "did:dimo:avis"
	fordCredit = "did:dimo:fordcredit"
	fordPro    = "did:dimo:fordpro"
	integrator = "did:dimo:integrator"
	insurer    = "did:dimo:insurer"
	alice      = "did:dimo:alice"
	bob        = "did:dimo:bob"
	fcAnalyst  = "did:dimo:fc-analyst"
	owner      = "did:dimo:owner"
	dealer     = "did:dimo:dealer"
	rooftop    = "did:dimo:rooftop"
	marketing  = "did:dimo:marketing"
	buyer      = "did:dimo:buyer"
	car        = "did:dimo:car1"
	otherCar   = "did:dimo:car2"
)

var (
	ctx   = context.Background()
	flTag = "at://" + avis + "/" + CollectionTag + "/fl-fleet"
)

// memResolver is an in-memory Resolver.
type memResolver struct {
	records     map[string]*Stored
	memberships map[string][]Membership // tag|vehicle
	roles       map[string][]Stored     // org|member
	states      map[string]*control.State
	openings    map[string]*control.Opening // vehicle|era|controller
	kinds       map[string]Kind
}

func newResolver() *memResolver {
	return &memResolver{
		records:     map[string]*Stored{},
		memberships: map[string][]Membership{},
		roles:       map[string][]Stored{},
		states:      map[string]*control.State{},
		openings:    map[string]*control.Opening{},
		kinds: map[string]Kind{
			avis: KindOrg, fordCredit: KindOrg, fordPro: KindOrg, integrator: KindOrg, insurer: KindOrg,
			dealer: KindOrg, rooftop: KindOrg, marketing: KindOrg,
			alice: KindPerson, bob: KindPerson, fcAnalyst: KindPerson, owner: KindPerson, buyer: KindPerson,
		},
	}
}

func (m *memResolver) Record(_ context.Context, uri string) (*Stored, error) {
	s, ok := m.records[uri]
	if !ok {
		return nil, fmt.Errorf("record %s not found", uri)
	}
	return s, nil
}

func (m *memResolver) Memberships(_ context.Context, tag, vehicle string) ([]Membership, error) {
	return m.memberships[tag+"|"+vehicle], nil
}

func (m *memResolver) Roles(_ context.Context, org, member string) ([]Stored, error) {
	return m.roles[org+"|"+member], nil
}

func (m *memResolver) ControlState(_ context.Context, vehicle string) (*control.State, error) {
	if s, ok := m.states[vehicle]; ok {
		return s, nil
	}
	return &control.State{DID: vehicle}, nil
}

func (m *memResolver) Opening(_ context.Context, vehicle string, era uint64, controller string) (*control.Opening, error) {
	return m.openings[fmt.Sprintf("%s|%d|%s", vehicle, era, controller)], nil
}

func (m *memResolver) Kind(_ context.Context, did string) (Kind, error) {
	return m.kinds[did], nil
}

// control gives controller era 0 of vehicle, starting at the beginning of time.
func (m *memResolver) control(t *testing.T, vehicle, controller string) {
	t.Helper()
	m.states[vehicle] = &control.State{DID: vehicle}
	m.addEra(t, vehicle, controller, nil)
}

// addEra ends the current era at start (if any) and adds a new one for controller.
func (m *memResolver) addEra(t *testing.T, vehicle, controller string, start *time.Time) {
	t.Helper()
	st := m.states[vehicle]
	n := uint64(len(st.Eras))
	if n > 0 {
		st.Eras[n-1].End = start
	}
	salt, err := control.NewSalt()
	require.NoError(t, err)
	o := &control.Opening{Controller: controller, Era: n, Salt: salt}
	c, err := control.Commit(*o)
	require.NoError(t, err)
	st.Eras = append(st.Eras, control.Era{Number: n, Start: start, Commitment: c})
	m.openings[fmt.Sprintf("%s|%d|%s", vehicle, n, controller)] = o
}

func (m *memResolver) put(uri string, rec Record, committedAt time.Time) *Stored {
	s := &Stored{URI: uri, Record: rec, CommittedAt: committedAt}
	m.records[uri] = s
	return s
}

func (m *memResolver) role(org, member string, covers Covers, abilities []string, committedAt time.Time) *Stored {
	s := Stored{
		URI: fmt.Sprintf("at://%s/%s/%s", org, TypeRole, member),
		Record: Record{
			Type: TypeRole, From: org, To: member, Covers: covers, Abilities: abilities,
		},
		CommittedAt: committedAt,
	}
	key := org + "|" + member
	m.roles[key] = append(m.roles[key], s)
	return &m.roles[key][len(m.roles[key])-1]
}

func (m *memResolver) join(tag, vehicle, author string, joined time.Time, left *time.Time) {
	key := tag + "|" + vehicle
	m.memberships[key] = append(m.memberships[key], Membership{
		Tag: tag, Vehicle: vehicle, JoinedAt: joined, LeftAt: left, CreatedBy: author, CommittedAt: joined,
	})
}

func uri(did, rkey string) string { return "at://" + did + "/" + TypeDelegation + "/" + rkey }

func delegation(from, to string, covers Covers, abilities ...string) Record {
	return Record{Type: TypeDelegation, From: from, To: to, Covers: covers, Abilities: abilities}
}

// avisFleet: Avis controls car; car in fl-fleet since day 3 (added by the org);
// Ford Credit gets telemetry + location over fl-fleet with data from day 2.
func avisFleet(t *testing.T) (*memResolver, *Evaluator, string) {
	r := newResolver()
	r.control(t, car, avis)
	r.join(flTag, car, avis, day(3), nil)
	rec := delegation(avis, fordCredit, Covers{Tag: flTag}, "telemetry:read", "location:precise", "command:unlock")
	rec.DataWindow = Window{From: tp(day(2))}
	u := uri(avis, "fc")
	r.put(u, rec, day(2))
	return r, &Evaluator{Resolver: r}, u
}

func TestRoot_TagCoverageStartsAtJoin(t *testing.T) {
	_, e, u := avisFleet(t)
	cov, err := e.Coverage(ctx, u, car, day(10))
	require.NoError(t, err)
	assert.Equal(t, Span(tp(day(3)), nil), cov.Historical["telemetry:read"], "data before the car joined the tag is not covered")
	assert.Equal(t, []string{"command:unlock"}, cov.Live)
	assert.Equal(t, []string{u}, cov.Chain)
}

func TestRoot_VehicleNotInTag(t *testing.T) {
	r, e, u := avisFleet(t)
	r.control(t, otherCar, avis)
	_, err := e.Coverage(ctx, u, otherCar, day(10))
	assert.ErrorIs(t, err, ErrNotCovered)
}

func TestRoot_IssuerMustBeController(t *testing.T) {
	r, e, u := avisFleet(t)
	r.control(t, car, "did:dimo:hertz")
	_, err := e.Coverage(ctx, u, car, day(10))
	assert.ErrorIs(t, err, ErrNotCovered)
}

func TestRoot_ForgedOpeningRejected(t *testing.T) {
	r, e, u := avisFleet(t)
	salt, err := control.NewSalt()
	require.NoError(t, err)
	r.openings[car+"|0|"+avis] = &control.Opening{Controller: avis, Era: 0, Salt: salt}
	_, err = e.Coverage(ctx, u, car, day(10))
	assert.ErrorIs(t, err, ErrNotCovered)
}

func TestTag_RemovalRetainsHistoryDropsLive(t *testing.T) {
	r, e, u := avisFleet(t)
	r.memberships[flTag+"|"+car] = nil
	r.join(flTag, car, avis, day(3), tp(day(8)))

	cov, err := e.Coverage(ctx, u, car, day(10))
	require.NoError(t, err)
	assert.Equal(t, Span(tp(day(3)), tp(day(8))), cov.Historical["location:precise"])
	assert.Empty(t, cov.Live)

	r.records[u].Record.AfterRemoval = Drop
	_, err = e.Coverage(ctx, u, car, day(10))
	assert.ErrorIs(t, err, ErrNotCovered)
}

func TestTag_RejoinProducesMultipleWindows(t *testing.T) {
	r, e, u := avisFleet(t)
	r.memberships[flTag+"|"+car] = nil
	r.join(flTag, car, avis, day(3), tp(day(5)))
	r.join(flTag, car, avis, day(9), nil)

	cov, err := e.Coverage(ctx, u, car, day(12))
	require.NoError(t, err)
	assert.Equal(t, Span(tp(day(3)), tp(day(5))).Union(Span(tp(day(9)), nil)), cov.Historical["telemetry:read"])
	assert.Equal(t, []string{"command:unlock"}, cov.Live)
}

func TestTag_EditByUnderprivilegedMemberIgnored(t *testing.T) {
	r, e, u := avisFleet(t)
	// Bob can edit the tag but cannot grant location:precise.
	r.role(avis, bob, Covers{Tag: flTag}, []string{"tag:write", "telemetry:read"}, day(1))
	r.control(t, otherCar, avis)
	r.join(flTag, otherCar, bob, day(4), nil)

	_, err := e.Coverage(ctx, u, otherCar, day(10))
	assert.ErrorIs(t, err, ErrNotCovered, "a tag edit cannot widen a delegation beyond its author's authority")

	r.role(avis, alice, Covers{Tag: flTag}, []string{"tag:write", "telemetry:read", "location:precise", "command:unlock"}, day(1))
	r.join(flTag, otherCar, alice, day(6), nil)
	cov, err := e.Coverage(ctx, u, otherCar, day(10))
	require.NoError(t, err)
	assert.Equal(t, Span(tp(day(6)), nil), cov.Historical["telemetry:read"])
}

func TestTag_OwnedByAnotherOrgRejected(t *testing.T) {
	r, e, _ := avisFleet(t)
	rec := delegation(fordCredit, insurer, Covers{Tag: flTag}, "telemetry:read")
	u := uri(fordCredit, "steal")
	r.put(u, rec, day(2))
	_, err := e.Coverage(ctx, u, car, day(10))
	assert.ErrorIs(t, err, ErrNotNarrowing)
}

func TestAuthor_DepartureDoesNotInvalidate(t *testing.T) {
	r, e, u := avisFleet(t)
	r.records[u].Record.CreatedBy = alice
	role := r.role(avis, alice, Covers{Tag: flTag},
		[]string{"delegation:create", "telemetry:read", "location:precise", "command:unlock"}, day(1))

	_, err := e.Coverage(ctx, u, car, day(10))
	require.NoError(t, err)

	role.Tombstone = &Tombstone{At: day(5), By: avis}
	_, err = e.Coverage(ctx, u, car, day(10))
	assert.NoError(t, err, "alice leaving does not invalidate what Avis committed while she held the role")
}

func TestAuthor_WithoutRoleRejected(t *testing.T) {
	r, e, u := avisFleet(t)
	r.records[u].Record.CreatedBy = bob
	_, err := e.Coverage(ctx, u, car, day(10))
	assert.ErrorContains(t, err, "lacked authority")

	// A role granted after the commit does not retroactively authorize it.
	r.role(avis, bob, Covers{Inherit: true}, []string{"delegation:create", "telemetry:read", "location:precise", "command:unlock"}, day(5))
	_, err = e.Coverage(ctx, u, car, day(10))
	assert.ErrorContains(t, err, "lacked authority")
}

func TestTransfer_RetainsOwnEraHistoryOnly(t *testing.T) {
	r, e, u := avisFleet(t)
	r.addEra(t, car, buyer, tp(day(20)))

	cov, err := e.Coverage(ctx, u, car, day(25))
	require.NoError(t, err)
	assert.Equal(t, Span(tp(day(3)), tp(day(20))), cov.Historical["telemetry:read"])
	assert.Empty(t, cov.Live, "live abilities end at transfer")

	r.records[u].Record.AfterTransfer = Drop
	_, err = e.Coverage(ctx, u, car, day(25))
	assert.ErrorIs(t, err, ErrNotCovered)
}

func TestTransfer_BuybackCoversBothAvisEras(t *testing.T) {
	r, e, u := avisFleet(t)
	r.addEra(t, car, buyer, tp(day(10)))
	r.addEra(t, car, avis, tp(day(15)))

	cov, err := e.Coverage(ctx, u, car, day(20))
	require.NoError(t, err)
	assert.Equal(t, Span(tp(day(3)), tp(day(10))).Union(Span(tp(day(15)), nil)), cov.Historical["telemetry:read"])
	assert.Equal(t, []string{"command:unlock"}, cov.Live)
}

func TestRevocationWindow(t *testing.T) {
	r, e, u := avisFleet(t)
	r.states[car].Eras[0].Revocations = []control.Revocation{{From: day(1), To: day(4)}}
	_, err := e.Coverage(ctx, u, car, day(10))
	assert.ErrorIs(t, err, ErrNotCovered, "delegation committed during the compromise window")

	r.records[u].CommittedAt = day(5)
	_, err = e.Coverage(ctx, u, car, day(10))
	assert.NoError(t, err)
}

func TestLien(t *testing.T) {
	r, e, u := avisFleet(t)
	r.records[u].Record.RevocableBy = RevocableByTo

	r.records[u].Tombstone = &Tombstone{At: day(6), By: avis}
	_, err := e.Coverage(ctx, u, car, day(10))
	assert.NoError(t, err, "the issuer cannot revoke a lien")

	r.records[u].Tombstone = &Tombstone{At: day(6), By: fordCredit}
	_, err = e.Coverage(ctx, u, car, day(10))
	assert.ErrorIs(t, err, ErrRevoked)
}

func TestLien_ConsumerCannotIssueIrrevocable(t *testing.T) {
	r := newResolver()
	r.control(t, car, owner)
	rec := delegation(owner, fordCredit, Covers{Vehicle: car}, "location:precise")
	rec.RevocableBy = RevocableByTo
	u := uri(owner, "lien")
	r.put(u, rec, day(1))
	_, err := (&Evaluator{Resolver: r}).Coverage(ctx, u, car, day(2))
	assert.ErrorIs(t, err, ErrLienNotAllowed)
}

func TestChain_AttenuatedRedelegation(t *testing.T) {
	r := newResolver()
	r.control(t, car, avis)
	parent := delegation(avis, fordPro, Covers{Vehicle: car}, "telemetry:read", "command:lock")
	parent.Redelegate = Redelegate{Mode: RedelegateAttenuated, MaxDepth: 1}
	pu := uri(avis, "fordpro")
	r.put(pu, parent, day(1))

	child := delegation(fordPro, integrator, Covers{Inherit: true}, "telemetry:read")
	child.Basis = []string{pu}
	cu := uri(fordPro, "integrator")
	r.put(cu, child, day(2))

	e := &Evaluator{Resolver: r}
	cov, err := e.Coverage(ctx, cu, car, day(3))
	require.NoError(t, err)
	assert.Equal(t, All(), cov.Historical["telemetry:read"])
	assert.Equal(t, []string{cu, pu}, cov.Chain)

	// Integrator tries to pass it on: depth exhausted.
	grand := delegation(integrator, marketing, Covers{Inherit: true}, "telemetry:read")
	grand.Basis = []string{cu}
	gu := uri(integrator, "resell")
	r.put(gu, grand, day(3))
	_, err = e.Coverage(ctx, gu, car, day(4))
	assert.ErrorIs(t, err, ErrNotNarrowing)

	// Widening abilities is rejected.
	wide := delegation(fordPro, integrator, Covers{Inherit: true}, "telemetry:read", "command:unlock")
	wide.Basis = []string{pu}
	wu := uri(fordPro, "wide")
	r.put(wu, wide, day(2))
	_, err = e.Coverage(ctx, wu, car, day(3))
	assert.ErrorIs(t, err, ErrNotNarrowing)

	// Revoking the parent kills the child.
	r.records[pu].Tombstone = &Tombstone{At: day(5), By: avis}
	_, err = e.Coverage(ctx, cu, car, day(6))
	assert.ErrorIs(t, err, ErrRevoked)
}

func TestChain_ValidityCannotOutliveBasis(t *testing.T) {
	r := newResolver()
	r.control(t, car, avis)
	parent := delegation(avis, fordPro, Covers{Vehicle: car}, "telemetry:read")
	parent.Redelegate = Redelegate{Mode: RedelegateAttenuated, MaxDepth: 1}
	parent.Validity = Window{To: tp(day(10))}
	pu := uri(avis, "p")
	r.put(pu, parent, day(1))

	child := delegation(fordPro, integrator, Covers{Inherit: true}, "telemetry:read")
	child.Basis = []string{pu}
	cu := uri(fordPro, "c")
	r.put(cu, child, day(2))

	_, err := (&Evaluator{Resolver: r}).Coverage(ctx, cu, car, day(3))
	assert.ErrorIs(t, err, ErrNotNarrowing)
}

func TestDealerConsent(t *testing.T) {
	r := newResolver()
	r.control(t, car, owner)

	consent := delegation(owner, dealer, Covers{Vehicle: car}, "telemetry:read", "health:read")
	consent.Purpose = "service"
	consent.Redelegate = Redelegate{Mode: RedelegateAllowlist, Grantees: []string{rooftop}}
	consentURI := uri(owner, "consent")
	r.put(consentURI, consent, day(1))

	toRooftop := delegation(dealer, rooftop, Covers{Inherit: true}, "health:read")
	toRooftop.Basis = []string{consentURI}
	rooftopURI := uri(dealer, "rooftop")
	r.put(rooftopURI, toRooftop, day(2))

	toMarketing := delegation(dealer, marketing, Covers{Inherit: true}, "telemetry:read")
	toMarketing.Basis = []string{consentURI}
	marketingURI := uri(dealer, "marketing")
	r.put(marketingURI, toMarketing, day(2))

	e := &Evaluator{Resolver: r}
	_, err := e.Coverage(ctx, rooftopURI, car, day(3))
	require.NoError(t, err)

	_, err = e.Coverage(ctx, marketingURI, car, day(3))
	assert.ErrorIs(t, err, ErrNotNarrowing, "the dealer cannot share beyond what the owner consented to")

	r.records[consentURI].Tombstone = &Tombstone{At: day(5), By: owner}
	_, err = e.Coverage(ctx, rooftopURI, car, day(6))
	assert.ErrorIs(t, err, ErrRevoked, "owner revocation cuts every descendant")
}

func TestChain_DepthAndCycle(t *testing.T) {
	r := newResolver()
	r.control(t, car, avis)
	orgs := []string{avis, fordPro, integrator, insurer, dealer, rooftop, marketing}
	prev := ""
	for i := 0; i < len(orgs)-1; i++ {
		rec := delegation(orgs[i], orgs[i+1], Covers{Vehicle: car}, "telemetry:read")
		rec.Redelegate = Redelegate{Mode: RedelegateAttenuated, MaxDepth: 10 - i}
		if prev != "" {
			rec.Covers = Covers{Inherit: true}
			rec.Basis = []string{prev}
		}
		u := uri(orgs[i], fmt.Sprintf("hop%d", i))
		r.put(u, rec, day(1))
		prev = u
	}
	_, err := (&Evaluator{Resolver: r}).Coverage(ctx, prev, car, day(2))
	assert.True(t, errors.Is(err, ErrChainTooDeep), "got %v", err)

	a := delegation(fordPro, integrator, Covers{Inherit: true}, "telemetry:read")
	a.Redelegate = Redelegate{Mode: RedelegateAttenuated, MaxDepth: 3}
	a.Basis = []string{uri(integrator, "b")}
	b := delegation(integrator, fordPro, Covers{Inherit: true}, "telemetry:read")
	b.Redelegate = Redelegate{Mode: RedelegateAttenuated, MaxDepth: 3}
	b.Basis = []string{uri(fordPro, "a")}
	r.put(uri(fordPro, "a"), a, day(1))
	r.put(uri(integrator, "b"), b, day(1))
	_, err = (&Evaluator{Resolver: r}).Coverage(ctx, uri(fordPro, "a"), car, day(2))
	assert.Error(t, err)
}

func TestAuthorize_OrgMemberAndClientAllowlist(t *testing.T) {
	r, e, u := avisFleet(t)
	r.records[u].Record.ClientAllowlist = []string{"fc-portal"}
	r.role(fordCredit, fcAnalyst, Covers{Inherit: true}, []string{"location:precise"}, day(1))

	cov, err := e.Authorize(ctx, u, fcAnalyst, "fc-portal", car, []string{"location:precise"}, day(10))
	require.NoError(t, err)
	assert.Equal(t, Span(tp(day(3)), nil), cov.Historical["location:precise"])
	assert.NotContains(t, cov.Historical, "telemetry:read", "coverage is filtered to the request")

	_, err = e.Authorize(ctx, u, fcAnalyst, "fc-portal", car, []string{"command:unlock"}, day(10))
	assert.ErrorIs(t, err, ErrUnauthorized, "role lacks the requested ability")

	_, err = e.Authorize(ctx, u, fcAnalyst, "rogue-app", car, []string{"location:precise"}, day(10))
	assert.ErrorIs(t, err, ErrClientNotAllowed)

	_, err = e.Authorize(ctx, u, "did:dimo:stranger", "fc-portal", car, []string{"location:precise"}, day(10))
	assert.ErrorIs(t, err, ErrUnauthorized)

	cov, err = e.Authorize(ctx, u, fordCredit, "fc-portal", car, []string{"command:unlock"}, day(10))
	require.NoError(t, err)
	assert.Equal(t, []string{"command:unlock"}, cov.Live)
}

func TestValidity(t *testing.T) {
	r, e, u := avisFleet(t)
	r.records[u].Record.Validity = Window{From: tp(day(5)), To: tp(day(9))}
	_, err := e.Coverage(ctx, u, car, day(10))
	assert.ErrorIs(t, err, ErrNotValid)
	_, err = e.Coverage(ctx, u, car, day(6))
	assert.NoError(t, err)
}
