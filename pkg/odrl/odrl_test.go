package odrl

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/DIMO-Network/did-directory/pkg/delegation"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const (
	avis       = "did:dimo:avis"
	fordCredit = "did:dimo:fordcredit"
	renter     = "did:dimo:renter"
	alice      = "did:dimo:alice"
	car        = "did:dimo:car1"
	flTag      = "at://did:dimo:avis/" + delegation.CollectionTag + "/fl-fleet"
	grantURI   = "at://did:dimo:avis/" + delegation.TypeDelegation + "/3kx2a"
)

func tp(t time.Time) *time.Time { return &t }

func day(d int) time.Time { return time.Date(2026, 9, d, 0, 0, 0, 0, time.UTC) }

// fleetAgreement is the §12 worked example: Ford Credit over a tag, with the
// full field set so the round trip has something to lose.
func fleetAgreement() delegation.Record {
	return delegation.Record{
		Type:            delegation.TypeDelegation,
		From:            avis,
		To:              fordCredit,
		Covers:          delegation.Covers{Tag: flTag},
		Abilities:       []string{"telemetry:read", "location:precise"},
		DataWindow:      delegation.Window{From: tp(day(16))},
		Validity:        delegation.Window{From: tp(day(16)), To: tp(day(30))},
		Redelegate:      delegation.Redelegate{Mode: delegation.RedelegateAttenuated, MaxDepth: 1},
		RevocableBy:     delegation.RevocableByTo,
		AfterRemoval:    delegation.RetainHistory,
		AfterTransfer:   delegation.Drop,
		Purpose:         "fleet-financing",
		Terms:           "sha256:9f2c",
		ClientAllowlist: []string{"fc-portal"},
		CreatedBy:       alice,
		CreatedAt:       day(16),
	}
}

func roundTrip(t *testing.T, rec delegation.Record) delegation.Record {
	t.Helper()
	data, err := Marshal(&rec, grantURI)
	require.NoError(t, err)

	back, uid, duties, err := Unmarshal(data)
	require.NoError(t, err)
	assert.Equal(t, grantURI, uid)
	assert.Empty(t, duties)
	return *back
}

// A term nobody can read back is a term nobody agreed to.
func TestRoundTrip_Lossless(t *testing.T) {
	rec := fleetAgreement()
	assert.Equal(t, rec, roundTrip(t, rec))
}

func TestRoundTrip_CustodyAndExclusivity(t *testing.T) {
	rec := delegation.Record{
		Type:            delegation.TypeDelegation,
		From:            avis,
		To:              renter,
		Covers:          delegation.Covers{Vehicle: car},
		Abilities:       []string{"command:unlock", "command:lock"},
		Exclusive:       []string{"command:unlock", "command:lock"},
		Validity:        delegation.Window{From: tp(day(20)), To: tp(day(23))},
		DataWindow:      delegation.Window{From: tp(day(20)), To: tp(day(23))},
		NarrowToCustody: true,
		Purpose:         "rental",
	}
	assert.Equal(t, rec, roundTrip(t, rec))
}

func TestRoundTrip_InheritedAndRecovery(t *testing.T) {
	rec := delegation.Record{
		Type:       delegation.TypeDelegation,
		From:       "did:dimo:platform",
		To:         renter,
		Basis:      []string{grantURI},
		Covers:     delegation.Covers{Inherit: true},
		Abilities:  []string{"command:unlock"},
		Recovery:   true,
		Redelegate: delegation.Redelegate{Mode: delegation.RedelegateAllowlist, Grantees: []string{renter}, Exclusive: true},
	}
	assert.Equal(t, rec, roundTrip(t, rec))
}

func TestRoundTrip_RoleWithConstraints(t *testing.T) {
	rec := delegation.Record{
		Type:      delegation.TypeRole,
		From:      avis,
		To:        "did:dimo:booking-svc",
		Covers:    delegation.Covers{Tag: flTag},
		Abilities: []string{"delegation:create", "command:unlock", "telemetry:read"},
		Constraints: &delegation.RoleConstraints{
			MaxVehicles:    1,
			MaxValidity:    30 * 24 * time.Hour,
			Abilities:      []string{"command:unlock"},
			AllowExclusive: true,
		},
	}
	back := roundTrip(t, rec)
	assert.Equal(t, rec, back)

	// A role is a Set: an org's own rule about its staff, not a bargain.
	p, err := ToPolicy(&rec, grantURI)
	require.NoError(t, err)
	assert.Equal(t, TypeSet, p.Type)
}

// Durations cross the wire in seconds. Go nanoseconds are unreadable to
// everyone else, and a term nobody else can read is not a term.
func TestConstraints_DurationIsSeconds(t *testing.T) {
	rec := delegation.Record{
		Type: delegation.TypeRole, From: avis, To: "did:dimo:svc",
		Covers:      delegation.Covers{Vehicle: car},
		Abilities:   []string{"delegation:create"},
		Constraints: &delegation.RoleConstraints{MaxValidity: 90 * time.Minute},
	}
	data, err := Marshal(&rec, grantURI)
	require.NoError(t, err)
	assert.Contains(t, string(data), `"maxValiditySeconds": 5400`)
	assert.NotContains(t, string(data), "5400000000000")
}

func TestPolicy_Shape(t *testing.T) {
	rec := fleetAgreement()
	data, err := Marshal(&rec, grantURI)
	require.NoError(t, err)

	var raw map[string]any
	require.NoError(t, json.Unmarshal(data, &raw))
	assert.Equal(t, []any{ContextODRL, ContextDIMO}, raw["@context"])
	assert.Equal(t, TypeAgreement, raw["@type"])
	assert.Equal(t, avis, raw["assigner"])
	assert.Equal(t, fordCredit, raw["assignee"])

	perm := raw["permission"].([]any)[0].(map[string]any)
	assert.Equal(t, flTag, perm["target"])
	assert.Equal(t, "AssetCollection", perm["@type"], "a tag is a set that changes over time")
	assert.Equal(t, []any{"dimo:telemetry.read", "dimo:location.precise"}, perm["action"])

	// dateTime is ODRL's own; the data window is a profile term, because ODRL has
	// no concept of "which timestamps may be read".
	var left []string
	for _, c := range perm["constraint"].([]any) {
		left = append(left, c.(map[string]any)["leftOperand"].(string))
	}
	assert.Contains(t, left, LeftDateTime)
	assert.Contains(t, left, LeftDataTime)
	assert.Contains(t, left, LeftPurpose)
	assert.Contains(t, left, LeftClient)
}

// Duties are what code cannot enforce. They ride through untouched.
func TestDutiesSurvive(t *testing.T) {
	rec := fleetAgreement()
	duties := []Duty{
		{Action: "odrl:compensate", Constraint: []Constraint{{LeftOperand: "payAmount", Operator: OpEQ, RightOperand: "89.00"}}},
		{Action: Prefix + "retain", Constraint: []Constraint{{LeftOperand: LeftDataTime, Operator: OpLTEQ, RightOperand: "2027-09-16T00:00:00Z"}}},
	}
	data, err := Marshal(&rec, grantURI, duties...)
	require.NoError(t, err)

	_, _, back, err := Unmarshal(data)
	require.NoError(t, err)
	assert.Equal(t, duties, back)
}

func TestAbilityIRIs(t *testing.T) {
	// A colon becomes a dot: "telemetry:read" as an IRI would read as the prefix
	// "telemetry".
	assert.Equal(t, "dimo:telemetry.read", Action("telemetry:read"))
	a, err := Ability("dimo:command.unlock")
	require.NoError(t, err)
	assert.Equal(t, "command:unlock", a)

	_, err = Ability("odrl:display")
	assert.ErrorIs(t, err, ErrUnsupported)
}

// An unknown constraint is a term this reader cannot honour. Dropping it
// silently would grant more than the policy says.
func TestUnknownConstraintIsRefused(t *testing.T) {
	rec := fleetAgreement()
	p, err := ToPolicy(&rec, grantURI)
	require.NoError(t, err)
	p.Permission[0].Constraint = append(p.Permission[0].Constraint,
		Constraint{LeftOperand: "spatial", Operator: OpEQ, RightOperand: "urn:eu"})

	_, err = FromPolicy(p)
	assert.ErrorIs(t, err, ErrUnsupported)
	assert.ErrorContains(t, err, "spatial")
}

func TestRejects(t *testing.T) {
	rec := fleetAgreement()
	good, err := ToPolicy(&rec, grantURI)
	require.NoError(t, err)

	t.Run("not ODRL", func(t *testing.T) {
		p := *good
		p.Context = []string{ContextDIMO}
		_, err := FromPolicy(&p)
		assert.ErrorIs(t, err, ErrNotODRL)
	})

	t.Run("another profile", func(t *testing.T) {
		p := *good
		p.Profile = "https://example.com/profile"
		_, err := FromPolicy(&p)
		assert.ErrorIs(t, err, ErrUnsupported)
	})

	t.Run("several permissions are several grants", func(t *testing.T) {
		p := *good
		p.Permission = append(p.Permission, p.Permission[0])
		_, err := FromPolicy(&p)
		assert.ErrorIs(t, err, ErrNoPermission)
	})

	t.Run("invalid records do not marshal", func(t *testing.T) {
		bad := fleetAgreement()
		bad.Abilities = nil
		_, err := Marshal(&bad, grantURI)
		assert.Error(t, err)
	})

	t.Run("garbage", func(t *testing.T) {
		_, _, _, err := Unmarshal([]byte("{"))
		assert.ErrorIs(t, err, ErrNotODRL)
	})
}

// What crosses the wire still has to pass the checks that govern a write.
func TestPolicyStillCommits(t *testing.T) {
	rec := fleetAgreement()
	back := roundTrip(t, rec)
	assert.NoError(t, delegation.CheckCommit(&back, delegation.CommitContext{
		From:            delegation.Party{Kind: delegation.KindOrg, Operator: true},
		CoveredVehicles: 12,
		Approved:        true,
	}))
}
