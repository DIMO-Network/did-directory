package did

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/json"
	"testing"

	dimocrypto "github.com/DIMO-Network/did-directory/internal/crypto"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func generateTestKey(t *testing.T) (*ecdsa.PrivateKey, string) {
	t.Helper()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	didKey, err := dimocrypto.EncodeDIDKey(&key.PublicKey)
	require.NoError(t, err)

	return key, didKey
}

func TestDeriveFromGenesis(t *testing.T) {
	_, didKey := generateTestKey(t)

	op := &Operation{
		Type:         OpTypeCreate,
		RotationKeys: []string{didKey},
		VerificationMethods: map[string]string{
			"signing": didKey,
		},
		AlsoKnownAs: []string{},
		Services:     map[string]Service{},
		Prev:         nil,
		Sig:          "placeholder",
	}

	derived, err := DeriveFromGenesis(op)
	require.NoError(t, err)

	assert.True(t, len(derived) > len(DIDPrefix))
	assert.Contains(t, derived, DIDPrefix)

	// The identifier portion should be exactly 24 chars.
	id, err := ParseDID(derived)
	require.NoError(t, err)
	assert.Len(t, id, truncLen)
}

func TestDeriveFromGenesis_Deterministic(t *testing.T) {
	_, didKey := generateTestKey(t)

	op := &Operation{
		Type:         OpTypeCreate,
		RotationKeys: []string{didKey},
		VerificationMethods: map[string]string{
			"signing": didKey,
		},
		AlsoKnownAs: []string{},
		Services:     map[string]Service{},
		Prev:         nil,
		Sig:          "placeholder",
	}

	did1, err := DeriveFromGenesis(op)
	require.NoError(t, err)

	did2, err := DeriveFromGenesis(op)
	require.NoError(t, err)

	assert.Equal(t, did1, did2, "derivation must be deterministic")
}

func TestDeriveFromGenesis_DifferentOps(t *testing.T) {
	_, didKey1 := generateTestKey(t)
	_, didKey2 := generateTestKey(t)

	op1 := &Operation{
		Type:         OpTypeCreate,
		RotationKeys: []string{didKey1},
		VerificationMethods: map[string]string{
			"signing": didKey1,
		},
		AlsoKnownAs: []string{},
		Services:     map[string]Service{},
	}

	op2 := &Operation{
		Type:         OpTypeCreate,
		RotationKeys: []string{didKey2},
		VerificationMethods: map[string]string{
			"signing": didKey2,
		},
		AlsoKnownAs: []string{},
		Services:     map[string]Service{},
	}

	did1, err := DeriveFromGenesis(op1)
	require.NoError(t, err)

	did2, err := DeriveFromGenesis(op2)
	require.NoError(t, err)

	assert.NotEqual(t, did1, did2, "different genesis ops must produce different DIDs")
}

func TestComputeCID(t *testing.T) {
	_, didKey := generateTestKey(t)

	op := &Operation{
		Type:         OpTypeCreate,
		RotationKeys: []string{didKey},
		VerificationMethods: map[string]string{
			"signing": didKey,
		},
		AlsoKnownAs: []string{},
		Services:     map[string]Service{},
		Sig:          "sig",
	}

	cid, err := ComputeCID(op)
	require.NoError(t, err)
	assert.NotEmpty(t, cid)

	// CID should be deterministic.
	cid2, err := ComputeCID(op)
	require.NoError(t, err)
	assert.Equal(t, cid, cid2)
}

func TestMarshalDAGCBOR(t *testing.T) {
	data := map[string]string{"hello": "world"}

	cbor, err := MarshalDAGCBOR(data)
	require.NoError(t, err)
	assert.NotEmpty(t, cbor)

	// CBOR should be different from JSON.
	jsonBytes, _ := json.Marshal(data)
	assert.NotEqual(t, jsonBytes, cbor)
}

func TestParseDID(t *testing.T) {
	tests := []struct {
		name    string
		input   string
		wantID  string
		wantErr bool
	}{
		{"valid", "did:dimo:abcdef1234567890abcdef12", "abcdef1234567890abcdef12", false},
		{"wrong method", "did:plc:abcdef", "", true},
		{"no identifier", "did:dimo:", "", true},
		{"not a DID", "hello", "", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			id, err := ParseDID(tt.input)
			if tt.wantErr {
				assert.Error(t, err)
			} else {
				require.NoError(t, err)
				assert.Equal(t, tt.wantID, id)
			}
		})
	}
}

func TestIsValidDID(t *testing.T) {
	assert.True(t, IsValidDID("did:dimo:abcdef1234567890abcdef12"))
	assert.False(t, IsValidDID("did:plc:abcdef"))
	assert.False(t, IsValidDID(""))
}
