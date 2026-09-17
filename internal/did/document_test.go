package did

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestGenerateDocument(t *testing.T) {
	_, didKey := generateTestKey(t)

	op := &Operation{
		Type:         OpTypeCreate,
		RotationKeys: []string{didKey},
		VerificationMethods: map[string]string{
			"signing": didKey,
		},
		AlsoKnownAs: []string{"at://my-vehicle.dimo.zone"},
		Services: map[string]Service{
			"dimo_storage": {
				Type:     "DimoStorageNode",
				Endpoint: "https://node7.dimo.zone",
			},
		},
	}

	doc, err := GenerateDocument("did:dimo:testidentifier12345678", op, nil)
	require.NoError(t, err)

	assert.Equal(t, "did:dimo:testidentifier12345678", doc.ID)
	assert.Contains(t, doc.Context, "https://www.w3.org/ns/did/v1")
	assert.Contains(t, doc.AlsoKnownAs, "at://my-vehicle.dimo.zone")

	// Verification methods.
	require.Len(t, doc.VerificationMethod, 1)
	vm := doc.VerificationMethod[0]
	assert.Equal(t, "did:dimo:testidentifier12345678#signing", vm.ID)
	assert.Equal(t, "Multikey", vm.Type)
	assert.Equal(t, "did:dimo:testidentifier12345678", vm.Controller)
	assert.NotEmpty(t, vm.PublicKeyMultibase)

	// Services.
	require.Len(t, doc.Service, 1)
	svc := doc.Service[0]
	assert.Equal(t, "#dimo_storage", svc.ID)
	assert.Equal(t, "DimoStorageNode", svc.Type)
	assert.Equal(t, "https://node7.dimo.zone", svc.ServiceEndpoint)
}

func TestGenerateDocument_Tombstone(t *testing.T) {
	op := &Operation{
		Type: OpTypeTombstone,
	}

	_, err := GenerateDocument("did:dimo:testidentifier12345678", op, nil)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "deactivated")
}

func TestGenerateDocument_EmptyAliases(t *testing.T) {
	_, didKey := generateTestKey(t)

	op := &Operation{
		Type:         OpTypeCreate,
		RotationKeys: []string{didKey},
		VerificationMethods: map[string]string{
			"signing": didKey,
		},
		AlsoKnownAs: nil,
		Services:     map[string]Service{},
	}

	doc, err := GenerateDocument("did:dimo:testidentifier12345678", op, nil)
	require.NoError(t, err)

	// Should be an empty slice, not nil.
	assert.NotNil(t, doc.AlsoKnownAs)
	assert.Len(t, doc.AlsoKnownAs, 0)
}

func TestGenerateDocument_MultipleVerificationMethods(t *testing.T) {
	_, didKey1 := generateTestKey(t)
	_, didKey2 := generateTestKey(t)

	op := &Operation{
		Type:         OpTypeCreate,
		RotationKeys: []string{didKey1},
		VerificationMethods: map[string]string{
			"signing":    didKey1,
			"encryption": didKey2,
		},
		AlsoKnownAs: []string{},
		Services:     map[string]Service{},
	}

	doc, err := GenerateDocument("did:dimo:testidentifier12345678", op, nil)
	require.NoError(t, err)

	assert.Len(t, doc.VerificationMethod, 2)
}

