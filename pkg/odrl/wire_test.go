package odrl

import (
	"encoding/json"
	"reflect"
	"testing"
	"time"

	"github.com/DIMO-Network/did-directory/pkg/delegation"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// fullRecords between them set every field a record has, so a field the codec
// does not carry fails the round trip below.
func fullRecords() []delegation.Record {
	at := time.Date(2026, 9, 16, 14, 2, 11, 123456789, time.UTC)
	custody := delegation.Record{
		Type:            delegation.TypeDelegation,
		From:            avis,
		To:              renter,
		Basis:           []string{grantURI},
		Covers:          delegation.Covers{Vehicle: car},
		Abilities:       []string{"command:unlock", "telemetry:read"},
		DataWindow:      delegation.Window{From: tp(at), To: tp(at.Add(time.Hour))},
		Validity:        delegation.Window{From: tp(at), To: tp(at.Add(2 * time.Hour))},
		Redelegate:      delegation.Redelegate{Mode: delegation.RedelegateAllowlist, MaxDepth: 2, Grantees: []string{alice}, Exclusive: true},
		RevocableBy:     delegation.RevocableByEither,
		AfterRemoval:    delegation.Drop,
		AfterTransfer:   delegation.Drop,
		Purpose:         "rental",
		Terms:           "sha256:9f2c",
		ClientAllowlist: []string{"did:dimo:app"},
		Exclusive:       []string{"command:unlock"},
		Recovery:        true,
		NarrowToCustody: true,
		CreatedBy:       alice,
		CreatedAt:       at,
	}
	role := delegation.Record{
		Type:      delegation.TypeRole,
		From:      avis,
		To:        "did:dimo:booking-svc",
		Covers:    delegation.Covers{Tag: flTag},
		Abilities: []string{"delegation:create", "command:unlock"},
		Constraints: &delegation.RoleConstraints{
			MaxVehicles:       1,
			MaxValidity:       30 * 24 * time.Hour,
			MaxDataReach:      time.Hour,
			Abilities:         []string{"command:unlock"},
			AllowRedelegation: true,
			AllowExclusive:    true,
			Policy:            "rental-booking",
		},
	}
	inherited := delegation.Record{
		Type:      delegation.TypeDelegation,
		From:      "did:dimo:platform",
		To:        renter,
		Basis:     []string{grantURI},
		Covers:    delegation.Covers{Inherit: true},
		Abilities: []string{"telemetry:read"},
	}
	return []delegation.Record{custody, role, inherited}
}

// An org-wide role covers everything the org controls: it inherits with no
// basis to inherit from.
func TestOrgWideRoleRoundTrips(t *testing.T) {
	rec := delegation.Record{
		Type: delegation.TypeRole, From: avis, To: alice,
		Covers: delegation.Covers{Inherit: true}, Abilities: []string{"org:admin"},
	}
	assert.Equal(t, rec, roundTrip(t, rec))

	// A delegation still needs a basis to inherit from.
	p, err := ToPolicy(&fullRecords()[2], grantURI)
	require.NoError(t, err)
	p.Basis = nil
	_, err = FromPolicy(p)
	assert.ErrorContains(t, err, "basis")
}

// A field added to the record without a place in the wire format would be
// dropped on every write, and a dropped constraint is a widened grant. This
// fails until the fixtures above set the new field, and then the round trip
// fails until the codec carries it.
func TestEveryRecordFieldIsExercised(t *testing.T) {
	seen := map[string]bool{}
	var walk func(path string, v reflect.Value)
	walk = func(path string, v reflect.Value) {
		if v.Kind() == reflect.Pointer {
			if v.IsNil() {
				return
			}
			v = v.Elem()
		}
		if v.Kind() != reflect.Struct || v.Type() == reflect.TypeFor[time.Time]() {
			return
		}
		for i := range v.NumField() {
			f := v.Field(i)
			p := path + "." + v.Type().Field(i).Name
			if !f.IsZero() {
				seen[p] = true
			} else if _, ok := seen[p]; !ok {
				seen[p] = false
			}
			walk(p, f)
		}
	}
	for _, rec := range fullRecords() {
		walk("Record", reflect.ValueOf(rec))
	}
	for path, ok := range seen {
		assert.True(t, ok, "%s is never set in fullRecords, so the round trip cannot show the codec carries it", path)
	}
}

func TestFullRecordsRoundTrip(t *testing.T) {
	for _, rec := range fullRecords() {
		assert.Equal(t, rec, roundTrip(t, rec))
	}
}

func policyJSON(t *testing.T, edit func(raw map[string]any)) []byte {
	t.Helper()
	rec := fleetAgreement()
	data, err := Marshal(&rec, grantURI)
	require.NoError(t, err)
	var raw map[string]any
	require.NoError(t, json.Unmarshal(data, &raw))
	edit(raw)
	data, err = json.Marshal(raw)
	require.NoError(t, err)
	return data
}

// An unknown key is a term this reader would otherwise drop, at the top of the
// policy or inside it.
func TestUnknownKeysAreRefused(t *testing.T) {
	for name, edit := range map[string]func(map[string]any){
		"profile term": func(raw map[string]any) { raw["dimo:maxSpeed"] = 120 },
		"in the permission": func(raw map[string]any) {
			raw["permission"].([]any)[0].(map[string]any)["assigner"] = "did:dimo:someone"
		},
		"in the redelegation": func(raw map[string]any) {
			raw["dimo:redelegate"].(map[string]any)["depthUnlimited"] = true
		},
	} {
		t.Run(name, func(t *testing.T) {
			_, _, _, err := Unmarshal(policyJSON(t, edit))
			assert.ErrorIs(t, err, ErrNotODRL)
		})
	}
}

// Nothing here is processed as JSON-LD, but anyone who does process it would
// read the terms through the contexts, so a context we do not know could make
// the same document say something else to them.
func TestForeignContextIsRefused(t *testing.T) {
	data := policyJSON(t, func(raw map[string]any) {
		raw["@context"] = []any{ContextODRL, ContextDIMO, "https://example.com/redefine"}
	})
	_, _, _, err := Unmarshal(data)
	assert.ErrorIs(t, err, ErrUnsupported)
}

func TestNormalize(t *testing.T) {
	t.Run("fills in the uid", func(t *testing.T) {
		data := policyJSON(t, func(raw map[string]any) { delete(raw, "uid") })
		out, rec, err := Normalize(data, grantURI)
		require.NoError(t, err)
		back, uid, _, err := Unmarshal(out)
		require.NoError(t, err)
		assert.Equal(t, grantURI, uid)
		assert.Equal(t, rec, back)
	})

	t.Run("refuses another uid", func(t *testing.T) {
		_, _, err := Normalize(policyJSON(t, func(map[string]any) {}), "at://did:dimo:avis/network.dimo.delegation/other")
		assert.ErrorIs(t, err, ErrNotODRL)
	})

	t.Run("two spellings commit as one", func(t *testing.T) {
		// The tag target without its @type still reads as a tag; normalized, it
		// says so.
		a := policyJSON(t, func(raw map[string]any) {
			delete(raw["permission"].([]any)[0].(map[string]any), "@type")
		})
		b := policyJSON(t, func(map[string]any) {})
		na, _, err := Normalize(a, grantURI)
		require.NoError(t, err)
		nb, _, err := Normalize(b, grantURI)
		require.NoError(t, err)
		assert.JSONEq(t, string(nb), string(na))
	})

	t.Run("keeps obligations", func(t *testing.T) {
		rec := fleetAgreement()
		duty := Duty{Action: Prefix + "retain"}
		data, err := Marshal(&rec, grantURI, duty)
		require.NoError(t, err)
		out, _, err := Normalize(data, grantURI)
		require.NoError(t, err)
		_, _, duties, err := Unmarshal(out)
		require.NoError(t, err)
		assert.Equal(t, []Duty{duty}, duties)
	})
}

// Truncating a start time to the second moves it earlier and widens the
// window, so times cross with every digit they have.
func TestSubSecondTimesSurvive(t *testing.T) {
	rec := fleetAgreement()
	from := day(16).Add(500 * time.Millisecond)
	rec.Validity.From = &from
	assert.Equal(t, rec, roundTrip(t, rec))
}

func TestSubSecondMaxDataReachIsRefused(t *testing.T) {
	rec := fullRecords()[1]
	rec.Constraints.MaxDataReach = 1500 * time.Millisecond
	_, err := ToPolicy(&rec, grantURI)
	assert.ErrorIs(t, err, ErrUnsupported)
	assert.ErrorContains(t, err, "maxDataReach")
}
