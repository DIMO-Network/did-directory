package delegation

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func validRecord() Record {
	return delegation(avis, fordCredit, Covers{Tag: flTag}, "telemetry:read")
}

func TestValidate(t *testing.T) {
	base := validRecord()
	assert.NoError(t, base.Validate())

	cases := map[string]func(r *Record){
		"unknown type":          func(r *Record) { r.Type = "x" },
		"self delegation":       func(r *Record) { r.To = r.From },
		"no covers":             func(r *Record) { r.Covers = Covers{} },
		"two covers":            func(r *Record) { r.Covers.Vehicle = car },
		"bad tag uri":           func(r *Record) { r.Covers.Tag = "fl-fleet" },
		"inherit without basis": func(r *Record) { r.Covers = Covers{Inherit: true} },
		"no abilities":          func(r *Record) { r.Abilities = nil },
		"repeated ability":      func(r *Record) { r.Abilities = []string{"a:b", "a:b"} },
		"inverted window":       func(r *Record) { r.DataWindow = Window{From: tp(day(5)), To: tp(day(1))} },
		"attenuated depth 0":    func(r *Record) { r.Redelegate = Redelegate{Mode: RedelegateAttenuated} },
		"empty allowlist":       func(r *Record) { r.Redelegate = Redelegate{Mode: RedelegateAllowlist} },
		"bad revocableBy":       func(r *Record) { r.RevocableBy = "anyone" },
		"bad history policy":    func(r *Record) { r.AfterTransfer = "forget" },
		"role with basis": func(r *Record) {
			r.Type = TypeRole
			r.Basis = []string{uri(avis, "x")}
		},
		"role redelegable": func(r *Record) {
			r.Type = TypeRole
			r.Redelegate = Redelegate{Mode: RedelegateAttenuated, MaxDepth: 1}
		},
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			r := validRecord()
			mutate(&r)
			assert.Error(t, r.Validate())
		})
	}
}

func TestClassOf(t *testing.T) {
	assert.Equal(t, Historical, ClassOf("telemetry:read"))
	assert.Equal(t, Historical, ClassOf("location:precise"))
	assert.Equal(t, Live, ClassOf("command:unlock"))
	assert.Equal(t, Live, ClassOf("stream:live"))
	assert.Equal(t, Admin, ClassOf("delegation:create"))
	assert.Equal(t, Admin, ClassOf("tag:write"))
	assert.Equal(t, Admin, ClassOf("license:developer"))
}

func TestParseURI(t *testing.T) {
	a, c, k, err := ParseURI(flTag)
	assert.NoError(t, err)
	assert.Equal(t, avis, a)
	assert.Equal(t, CollectionTag, c)
	assert.Equal(t, "fl-fleet", k)

	_, _, _, err = ParseURI("https://example.com/x/y")
	assert.Error(t, err)
	_, err = TagAuthority(uri(avis, "not-a-tag"))
	assert.Error(t, err)
}

func TestCheckCommit(t *testing.T) {
	r := validRecord()
	assert.NoError(t, CheckCommit(&r, CommitContext{From: Party{Kind: KindOrg, Operator: true}, CoveredVehicles: 10}))
	assert.ErrorIs(t, CheckCommit(&r, CommitContext{From: Party{Kind: KindOrg, Operator: true}, CoveredVehicles: 501}), ErrApprovalRequired)
	assert.NoError(t, CheckCommit(&r, CommitContext{From: Party{Kind: KindOrg, Operator: true}, CoveredVehicles: 501, Approved: true}))
	assert.NoError(t, CheckCommit(&r, CommitContext{From: Party{Kind: KindOrg, Operator: true}, CoveredVehicles: 900, Policy: Policy{Name: "big-fleet", VehicleApprovalThreshold: 1000}}))

	live := validRecord()
	live.Abilities = []string{"command:unlock"}
	assert.ErrorIs(t, CheckCommit(&live, CommitContext{From: Party{Kind: KindOrg, Operator: true}, CoveredVehicles: 1}), ErrApprovalRequired)

	lien := validRecord()
	lien.RevocableBy = RevocableByTo
	assert.ErrorIs(t, CheckCommit(&lien, CommitContext{From: Party{Kind: KindPerson, ConsumerProtected: true}, Approved: true}), ErrLienNotAllowed)
	assert.ErrorIs(t, CheckCommit(&lien, CommitContext{From: Party{Kind: KindOrg, Operator: true}}), ErrApprovalRequired)
	assert.NoError(t, CheckCommit(&lien, CommitContext{From: Party{Kind: KindOrg, Operator: true}, Approved: true}))

	role := validRecord()
	role.Type = TypeRole
	role.To = alice
	assert.Error(t, CheckCommit(&role, CommitContext{From: Party{Kind: KindPerson, ConsumerProtected: true}}))
}

func TestCheckMembershipGrowth(t *testing.T) {
	covering := []Record{validRecord()}
	assert.NoError(t, CheckMembershipGrowth(covering, 500, false, Policy{}))
	assert.ErrorIs(t, CheckMembershipGrowth(covering, 501, false, Policy{}), ErrApprovalRequired)
	assert.NoError(t, CheckMembershipGrowth(covering, 501, true, Policy{}))
	assert.NoError(t, CheckMembershipGrowth(nil, 10_000, false, Policy{}))
}

// A device sending a reading is doing it now. Checking a write against a data
// window asks whether it may write a reading it has not taken yet.
func TestClassOf_WritesAreLive(t *testing.T) {
	assert.Equal(t, Live, ClassOf("telemetry:write"))
	assert.Equal(t, Live, ClassOf("data:write"))
	assert.Equal(t, Live, ClassOf("data:deliver"))
	assert.Equal(t, Historical, ClassOf("telemetry:read"))
	assert.Equal(t, Admin, ClassOf("tag:write"), "editing a tag is not writing vehicle data")

	// Actuation is narrower than live, and it is what approval and custody are
	// about: pairing a device is not the thing two admins are guarding against.
	assert.True(t, IsActuating("command:unlock"))
	assert.False(t, IsActuating("telemetry:write"))

	pairing := validRecord()
	pairing.Abilities = []string{"telemetry:write"}
	assert.NoError(t, CheckCommit(&pairing, CommitContext{
		From: Party{Kind: KindOrg, Operator: true}, CoveredVehicles: 1,
	}), "a device pairing does not need two admins")

	unlock := validRecord()
	unlock.Abilities = []string{"command:unlock"}
	assert.ErrorIs(t, CheckCommit(&unlock, CommitContext{
		From: Party{Kind: KindOrg, Operator: true}, CoveredVehicles: 1,
	}), ErrApprovalRequired)
}

// Every permissive field here defaults to strict, so a partial literal cannot
// switch a protection off by saying nothing.
func TestPolicy_PartialLiteralStillRequiresApproval(t *testing.T) {
	unlock := validRecord()
	unlock.Abilities = []string{"command:unlock"}
	org := Party{Kind: KindOrg, Operator: true}

	partial := Policy{Name: "eu-consumer", VehicleApprovalThreshold: 100}
	assert.ErrorIs(t, CheckCommit(&unlock, CommitContext{From: org, CoveredVehicles: 1, Policy: partial}),
		ErrApprovalRequired, "a policy that says nothing about actuation still requires approval")

	permissive := partial
	permissive.AllowUnapprovedActuation = true
	assert.NoError(t, CheckCommit(&unlock, CommitContext{From: org, CoveredVehicles: 1, Policy: permissive}),
		"switching it off is something a profile has to say out loud")
}
