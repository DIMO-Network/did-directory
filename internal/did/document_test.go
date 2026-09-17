package did

import (
	"encoding/json"
	"slices"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Ranging over op.VerificationMethods and op.Services randomises their order per
// resolve, which defeats any ETag or canonicalisation a relying party applies
// and makes "the first verification method" mean a different key each time.
func TestGenerateDocument_DeterministicOrder(t *testing.T) {
	op := &Operation{
		Type:                OpTypeCreate,
		VerificationMethods: map[string]string{},
		Services:            map[string]Service{},
	}
	for _, id := range []string{"signing", "auth", "recovery", "backup", "device", "passkey", "yubikey", "laptop"} {
		_, didKey := generateTestKey(t)
		op.VerificationMethods[id] = didKey
		op.Services[id] = Service{Type: "DimoStorageNode", Endpoint: "https://" + id + ".dimo.zone"}
	}

	first, err := GenerateDocument("did:dimo:person", op, nil)
	require.NoError(t, err)
	want, err := json.Marshal(first)
	require.NoError(t, err)

	for i := range 50 {
		doc, err := GenerateDocument("did:dimo:person", op, nil)
		require.NoError(t, err)
		got, err := json.Marshal(doc)
		require.NoError(t, err)
		require.Equal(t, string(want), string(got), "resolve %d reordered the document", i)
	}

	ids := make([]string, 0, len(first.VerificationMethod))
	for _, vm := range first.VerificationMethod {
		ids = append(ids, vm.ID)
	}
	assert.True(t, slices.IsSorted(ids), "verification methods must be ordered, got %v", ids)

	svcIDs := make([]string, 0, len(first.Service))
	for _, svc := range first.Service {
		svcIDs = append(svcIDs, svc.ID)
	}
	assert.True(t, slices.IsSorted(svcIDs), "services must be ordered, got %v", svcIDs)
}

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

