package did

import (
	"fmt"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// junkKeys returns n strings that are not did:keys, so a test can tell a
// limit error (checked first) from a decode error.
func junkKeys(n int) []string {
	keys := make([]string, n)
	for i := range keys {
		keys[i] = fmt.Sprintf("junk-%d", i)
	}
	return keys
}

func junkMethods(n int) map[string]string {
	vms := make(map[string]string, n)
	for i := range n {
		vms[fmt.Sprintf("vm%02d", i)] = fmt.Sprintf("junk-%d", i)
	}
	return vms
}

// updateOfType is a well-formed update of each type, apart from its keys.
func updateOfType(t *testing.T, typ string) *Operation {
	t.Helper()
	op := &Operation{Type: typ, Prev: ptr("bafyreiprev"), Sig: "sig", AlsoKnownAs: []string{}, Services: map[string]Service{}}
	switch typ {
	case OpTypeTransfer:
		op.ControlCommitment = ptr(testCommitment(t, "did:dimo:hertz", 1))
		op.EffectiveAt = ptr("2026-11-22T00:00:00Z")
	case OpTypeRevokeSince:
		op.ControlCommitment = ptr(testCommitment(t, "did:dimo:avis", 1))
		op.RevokeSince = ptr("2026-11-21T00:00:00Z")
		op.EffectiveAt = ptr("2026-11-22T00:00:00Z")
	}
	return op
}

// R3-F1: the counts and the length of every did:key are bounded before any
// key is decoded, so an anonymous genesis cannot buy seconds of CPU.
func TestValidateCreate_LimitsBeforeDecoding(t *testing.T) {
	t.Run("rotation keys", func(t *testing.T) {
		op := &Operation{Type: OpTypeCreate, RotationKeys: junkKeys(MaxRotationKeys + 1),
			VerificationMethods: junkMethods(1), Sig: "sig"}
		err := ValidateCreate(op)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "at most 5 rotation keys")
	})
	t.Run("15,000 copies of one key", func(t *testing.T) {
		_, dk := generateTestKey(t)
		keys := make([]string, 15_000)
		for i := range keys {
			keys[i] = dk
		}
		err := ValidateCreate(&Operation{Type: OpTypeCreate, RotationKeys: keys, VerificationMethods: map[string]string{"signing": dk}, Sig: "sig"})
		require.Error(t, err)
		assert.Contains(t, err.Error(), "at most 5 rotation keys")
	})
	t.Run("verification methods", func(t *testing.T) {
		op := &Operation{Type: OpTypeCreate, RotationKeys: junkKeys(1),
			VerificationMethods: junkMethods(MaxVerificationMethods + 1), Sig: "sig"}
		err := ValidateCreate(op)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "at most 32 verification methods")
	})
	t.Run("long rotation key", func(t *testing.T) {
		long := "did:key:z" + strings.Repeat("2", 1_000_000)
		op := &Operation{Type: OpTypeCreate, RotationKeys: []string{"junk", long},
			VerificationMethods: junkMethods(1), Sig: "sig"}
		err := ValidateCreate(op)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "rotation key [1] is longer than 128 bytes")
	})
	t.Run("long verification method", func(t *testing.T) {
		vms := junkMethods(1)
		vms["signing"] = "did:key:z" + strings.Repeat("2", MaxDIDKeyBytes)
		op := &Operation{Type: OpTypeCreate, RotationKeys: junkKeys(1), VerificationMethods: vms, Sig: "sig"}
		err := ValidateCreate(op)
		require.Error(t, err)
		assert.Contains(t, err.Error(), `verification method "signing" is longer than 128 bytes`)
	})
}

func TestValidateCreate_AtTheLimits(t *testing.T) {
	_, dk := generateTestKey(t)
	keys := make([]string, MaxRotationKeys)
	for i := range keys {
		_, keys[i] = generateTestKey(t)
	}
	vms := make(map[string]string, MaxVerificationMethods)
	for i := range MaxVerificationMethods {
		vms[fmt.Sprintf("vm%02d", i)] = dk
	}
	assert.NoError(t, ValidateCreate(&Operation{Type: OpTypeCreate, RotationKeys: keys, VerificationMethods: vms, Sig: "sig"}))

	// A key at exactly the length bound is decoded, and fails as a bad key.
	edge := "did:key:z" + strings.Repeat("2", MaxDIDKeyBytes-len("did:key:z"))
	require.Len(t, edge, MaxDIDKeyBytes)
	err := ValidateCreate(&Operation{Type: OpTypeCreate, RotationKeys: []string{edge}, VerificationMethods: vms, Sig: "sig"})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "invalid rotation key [0]")
}

func TestValidateUpdate_LimitsBeforeDecoding(t *testing.T) {
	for _, typ := range []string{OpTypeCreate, OpTypeTransfer, OpTypeRevokeSince, OpTypeTombstone} {
		t.Run(typ, func(t *testing.T) {
			op := updateOfType(t, typ)
			op.RotationKeys = junkKeys(MaxRotationKeys + 1)
			err := ValidateUpdate(op)
			require.Error(t, err)
			assert.Contains(t, err.Error(), "at most 5 rotation keys")

			op = updateOfType(t, typ)
			op.RotationKeys = junkKeys(1)
			op.VerificationMethods = junkMethods(MaxVerificationMethods + 1)
			err = ValidateUpdate(op)
			require.Error(t, err)
			assert.Contains(t, err.Error(), "at most 32 verification methods")

			op = updateOfType(t, typ)
			op.RotationKeys = []string{"did:key:z" + strings.Repeat("2", 1_000_000)}
			err = ValidateUpdate(op)
			require.Error(t, err)
			assert.Contains(t, err.Error(), "rotation key [0] is longer than 128 bytes")
		})
	}
}

// R3-F4: an update that carries state has its keys decoded as a genesis
// does, so a typo'd rotation key cannot freeze the DID and a typo'd
// verification method cannot make it unresolvable.
func TestValidateUpdate_DecodesKeysOfStateCarryingTypes(t *testing.T) {
	_, good := generateTestKey(t)
	for _, typ := range []string{OpTypeCreate, OpTypeTransfer, OpTypeRevokeSince} {
		t.Run(typ, func(t *testing.T) {
			op := updateOfType(t, typ)
			op.RotationKeys = []string{good, "did:key:zNotAKey"}
			if typ == OpTypeCreate {
				op.VerificationMethods = map[string]string{"signing": good}
			}
			err := ValidateUpdate(op)
			require.Error(t, err)
			assert.Contains(t, err.Error(), "invalid rotation key [1]")

			op.RotationKeys = []string{good}
			assert.NoError(t, ValidateUpdate(op))
		})
	}

	op := updateOfType(t, OpTypeCreate)
	op.RotationKeys = []string{good}
	op.VerificationMethods = map[string]string{"signing": good, "phone": "did:key:zNotAKey"}
	err := ValidateUpdate(op)
	require.Error(t, err)
	assert.Contains(t, err.Error(), `invalid verification method "phone"`)

	// A tombstone carries no state: nothing after it is ever verified.
	tomb := updateOfType(t, OpTypeTombstone)
	tomb.RotationKeys = []string{"did:key:zNotAKey"}
	assert.NoError(t, ValidateUpdate(tomb))
}
