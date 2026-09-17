package did

import (
	"crypto/ecdsa"
	"encoding/json"
	"testing"

	dimocrypto "github.com/DIMO-Network/did-directory/internal/crypto"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func signOperation(t *testing.T, key *ecdsa.PrivateKey, op *Operation) string {
	t.Helper()

	unsigned := op.ToUnsigned()
	data, err := json.Marshal(unsigned)
	require.NoError(t, err)

	sig, err := dimocrypto.SignOperation(key, data)
	require.NoError(t, err)

	return sig
}

func TestValidateCreate_Valid(t *testing.T) {
	key, didKey := generateTestKey(t)

	op := &Operation{
		Type:         OpTypeCreate,
		RotationKeys: []string{didKey},
		VerificationMethods: map[string]string{
			"signing": didKey,
		},
		AlsoKnownAs: []string{},
		Services:     map[string]Service{},
		Prev:         nil,
	}
	op.Sig = signOperation(t, key, op)

	err := ValidateCreate(op)
	assert.NoError(t, err)
}

func TestValidateCreate_NoRotationKeys(t *testing.T) {
	op := &Operation{
		Type:         OpTypeCreate,
		RotationKeys: []string{},
		VerificationMethods: map[string]string{
			"signing": "did:key:zDnaerDaTF5BXEavCrfRZEk316dpbLsfPDZ3WJ5hRTPFU2169",
		},
		Sig: "test",
	}

	err := ValidateCreate(op)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "rotation key")
}

func TestValidateCreate_NoVerificationMethods(t *testing.T) {
	_, didKey := generateTestKey(t)

	op := &Operation{
		Type:                OpTypeCreate,
		RotationKeys:        []string{didKey},
		VerificationMethods: map[string]string{},
		Sig:                 "test",
	}

	err := ValidateCreate(op)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "verification method")
}

func TestValidateCreate_WithPrev(t *testing.T) {
	_, didKey := generateTestKey(t)
	prev := "bafyrei..."

	op := &Operation{
		Type:         OpTypeCreate,
		RotationKeys: []string{didKey},
		VerificationMethods: map[string]string{
			"signing": didKey,
		},
		Prev: &prev,
		Sig:  "test",
	}

	err := ValidateCreate(op)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "nil prev")
}

func TestValidateCreate_InvalidRotationKey(t *testing.T) {
	op := &Operation{
		Type:         OpTypeCreate,
		RotationKeys: []string{"not-a-did-key"},
		VerificationMethods: map[string]string{
			"signing": "also-not-a-did-key",
		},
		Sig: "test",
	}

	err := ValidateCreate(op)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "invalid rotation key")
}

func TestValidateUpdate_NoPrev(t *testing.T) {
	op := &Operation{
		Type: OpTypeCreate,
		Prev: nil,
		Sig:  "test",
	}

	err := ValidateUpdate(op)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "previous CID")
}

func TestVerifyOperationSignature(t *testing.T) {
	key, didKey := generateTestKey(t)

	op := &Operation{
		Type:         OpTypeCreate,
		RotationKeys: []string{didKey},
		VerificationMethods: map[string]string{
			"signing": didKey,
		},
		AlsoKnownAs: []string{},
		Services:     map[string]Service{},
	}
	op.Sig = signOperation(t, key, op)

	err := VerifyOperationSignature(op, []string{didKey})
	assert.NoError(t, err)
}

func TestVerifyOperationSignature_WrongKey(t *testing.T) {
	key, _ := generateTestKey(t)
	_, otherDIDKey := generateTestKey(t)

	op := &Operation{
		Type:         OpTypeCreate,
		RotationKeys: []string{otherDIDKey},
		VerificationMethods: map[string]string{
			"signing": otherDIDKey,
		},
		AlsoKnownAs: []string{},
		Services:     map[string]Service{},
	}
	op.Sig = signOperation(t, key, op)

	// Verify against a different key should fail.
	err := VerifyOperationSignature(op, []string{otherDIDKey})
	assert.Error(t, err)
}

func TestOperation_IsGenesis(t *testing.T) {
	op := &Operation{Type: OpTypeCreate, Prev: nil}
	assert.True(t, op.IsGenesis())

	prev := "bafyrei..."
	op2 := &Operation{Type: OpTypeCreate, Prev: &prev}
	assert.False(t, op2.IsGenesis())
}

func TestOperation_IsTombstone(t *testing.T) {
	op := &Operation{Type: OpTypeTombstone}
	assert.True(t, op.IsTombstone())

	op2 := &Operation{Type: OpTypeCreate}
	assert.False(t, op2.IsTombstone())
}

func TestOperation_ToUnsigned(t *testing.T) {
	op := &Operation{
		Type:         OpTypeCreate,
		RotationKeys: []string{"did:key:z..."},
		VerificationMethods: map[string]string{
			"signing": "did:key:z...",
		},
		AlsoKnownAs: []string{"at://test.dimo.zone"},
		Services: map[string]Service{
			"storage": {Type: "DimoStorageNode", Endpoint: "https://node.dimo.zone"},
		},
		Sig: "should-be-stripped",
	}

	unsigned := op.ToUnsigned()

	assert.Equal(t, op.Type, unsigned.Type)
	assert.Equal(t, op.RotationKeys, unsigned.RotationKeys)
	assert.Equal(t, op.VerificationMethods, unsigned.VerificationMethods)
	assert.Equal(t, op.AlsoKnownAs, unsigned.AlsoKnownAs)
	assert.Equal(t, op.Services, unsigned.Services)

	// Verify the unsigned struct doesn't have the "sig" JSON key.
	data, err := json.Marshal(unsigned)
	require.NoError(t, err)
	assert.NotContains(t, string(data), `"sig":`)
	assert.NotContains(t, string(data), "should-be-stripped")
}

