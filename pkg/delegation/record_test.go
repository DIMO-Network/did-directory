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
	assert.NoError(t, CheckCommit(&r, CommitContext{FromKind: KindOrg, CoveredVehicles: 10}))
	assert.ErrorIs(t, CheckCommit(&r, CommitContext{FromKind: KindOrg, CoveredVehicles: 501}), ErrApprovalRequired)
	assert.NoError(t, CheckCommit(&r, CommitContext{FromKind: KindOrg, CoveredVehicles: 501, Approved: true}))
	assert.NoError(t, CheckCommit(&r, CommitContext{FromKind: KindOrg, CoveredVehicles: 900, Threshold: 1000}))

	live := validRecord()
	live.Abilities = []string{"command:unlock"}
	assert.ErrorIs(t, CheckCommit(&live, CommitContext{FromKind: KindOrg, CoveredVehicles: 1}), ErrApprovalRequired)

	lien := validRecord()
	lien.RevocableBy = RevocableByTo
	assert.ErrorIs(t, CheckCommit(&lien, CommitContext{FromKind: KindPerson, Approved: true}), ErrLienNotAllowed)
	assert.ErrorIs(t, CheckCommit(&lien, CommitContext{FromKind: KindOrg}), ErrApprovalRequired)
	assert.NoError(t, CheckCommit(&lien, CommitContext{FromKind: KindOrg, Approved: true}))

	role := validRecord()
	role.Type = TypeRole
	role.To = alice
	assert.Error(t, CheckCommit(&role, CommitContext{FromKind: KindPerson}))
}

func TestCheckMembershipGrowth(t *testing.T) {
	covering := []Record{validRecord()}
	assert.NoError(t, CheckMembershipGrowth(covering, 500, false, 0))
	assert.ErrorIs(t, CheckMembershipGrowth(covering, 501, false, 0), ErrApprovalRequired)
	assert.NoError(t, CheckMembershipGrowth(covering, 501, true, 0))
	assert.NoError(t, CheckMembershipGrowth(nil, 10_000, false, 0))
}
