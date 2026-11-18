package main

import (
	"testing"

	dimocrypto "github.com/DIMO-Network/did-directory/internal/crypto"
	"github.com/DIMO-Network/did-directory/internal/did"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func signedGenesis(t *testing.T, plan *createPlan) (*did.Operation, string) {
	t.Helper()
	priv, rot, err := newKey()
	require.NoError(t, err)
	plan.Op.RotationKeys = []string{rot}
	if _, ok := plan.Op.VerificationMethods["signing"]; ok {
		plan.Op.VerificationMethods["signing"] = rot
	}
	op, err := signOp(priv, plan.Op)
	require.NoError(t, err)
	d, err := did.DeriveFromGenesis(op)
	require.NoError(t, err)
	return op, d
}

func TestBuildCreate_OrgPublishesCommitKeyAndHost(t *testing.T) {
	_, rot, err := newKey()
	require.NoError(t, err)

	plan, err := buildCreate(createOptions{Org: true, OrgHost: "https://orghost.dimo.zone"}, rot)
	require.NoError(t, err)
	require.NotNil(t, plan.OrgKey, "the CLI generated the org key, so it must hand it back for the keystore")
	require.Nil(t, plan.Opening)

	published := plan.Op.VerificationMethods[OrgKeyID]
	want, err := dimocrypto.EncodeDIDKey(&plan.OrgKey.PublicKey)
	require.NoError(t, err)
	assert.Equal(t, want, published, "#dimo_org is the public half of the generated key")
	assert.Equal(t, rot, plan.Op.VerificationMethods["signing"], "an org still signs as itself")
	assert.Equal(t, did.Service{Type: OrgHostServiceType, Endpoint: "https://orghost.dimo.zone"}, plan.Op.Services[OrgHostServiceID])

	op, d := signedGenesis(t, plan)
	require.NoError(t, did.ValidateCreate(op))

	doc, err := did.GenerateDocument(d, op, did.ResolveControlState(d, []did.Operation{*op}))
	require.NoError(t, err)
	var ids []string
	for _, vm := range doc.VerificationMethod {
		ids = append(ids, vm.ID)
	}
	assert.Contains(t, ids, d+"#"+OrgKeyID)
	require.Len(t, doc.Service, 1)
	assert.Equal(t, "#"+OrgHostServiceID, doc.Service[0].ID)
	assert.Equal(t, OrgHostServiceType, doc.Service[0].Type)
	assert.Equal(t, "https://orghost.dimo.zone", doc.Service[0].ServiceEndpoint)
	assert.Nil(t, doc.DimoControl, "an org is not a controlled asset")
}

// The host holds the commit key (decision C). When it generated the key itself
// the CLI only publishes the public half and keeps nothing.
func TestBuildCreate_OrgKeyFromHost(t *testing.T) {
	_, rot, err := newKey()
	require.NoError(t, err)
	_, hostKey, err := newKey()
	require.NoError(t, err)

	plan, err := buildCreate(createOptions{OrgKey: hostKey}, rot)
	require.NoError(t, err)
	assert.Nil(t, plan.OrgKey)
	assert.Equal(t, hostKey, plan.Op.VerificationMethods[OrgKeyID])

	_, err = buildCreate(createOptions{OrgKey: "did:key:zNotAKey"}, rot)
	assert.ErrorContains(t, err, "invalid --org-key")
}

func TestBuildCreate_OrgHostAloneImpliesOrg(t *testing.T) {
	_, rot, err := newKey()
	require.NoError(t, err)
	plan, err := buildCreate(createOptions{OrgHost: "https://orghost.dimo.zone"}, rot)
	require.NoError(t, err)
	assert.NotEmpty(t, plan.Op.VerificationMethods[OrgKeyID], "a DID with a host but no commit key would be an org nobody can write for")
}

func TestBuildCreate_PersonHasNoOrgFields(t *testing.T) {
	_, rot, err := newKey()
	require.NoError(t, err)
	plan, err := buildCreate(createOptions{}, rot)
	require.NoError(t, err)
	assert.Nil(t, plan.OrgKey)
	assert.Equal(t, map[string]string{"signing": rot}, plan.Op.VerificationMethods)
	assert.Empty(t, plan.Op.Services)
}

func TestBuildCreate_ControlledDIDCannotBeAnOrg(t *testing.T) {
	_, rot, err := newKey()
	require.NoError(t, err)
	for _, opts := range []createOptions{
		{Controller: "did:dimo:avis", Org: true},
		{Controller: "did:dimo:avis", OrgKey: rot},
		{Controller: "did:dimo:avis", OrgHost: "https://orghost.dimo.zone"},
	} {
		_, err := buildCreate(opts, rot)
		assert.ErrorContains(t, err, "controlled DID cannot be an org")
	}
}

func TestBuildUpdate_SetsOrgKeyAndHostAndKeepsTheRest(t *testing.T) {
	_, rot, err := newKey()
	require.NoError(t, err)
	current := &did.Operation{
		Type:                did.OpTypeCreate,
		RotationKeys:        []string{rot},
		VerificationMethods: map[string]string{"signing": rot},
		AlsoKnownAs:         []string{"at://avis"},
		Services:            map[string]did.Service{"dimo_storage": {Type: "DimoStorageNode", Endpoint: "https://node7.dimo.zone"}},
	}

	plan, err := buildUpdate(current, "cid1", updateOptions{NewOrgKey: true, OrgHost: "https://orghost.dimo.zone"})
	require.NoError(t, err)
	require.NotNil(t, plan.OrgKey)
	want, err := dimocrypto.EncodeDIDKey(&plan.OrgKey.PublicKey)
	require.NoError(t, err)
	assert.Equal(t, want, plan.Op.VerificationMethods[OrgKeyID])
	assert.Equal(t, rot, plan.Op.VerificationMethods["signing"])
	assert.Equal(t, "cid1", *plan.Op.Prev)
	assert.Equal(t, []string{"at://avis"}, plan.Op.AlsoKnownAs)
	assert.Equal(t, "https://node7.dimo.zone", plan.Op.Services["dimo_storage"].Endpoint, "existing services survive")
	assert.Equal(t, OrgHostServiceType, plan.Op.Services[OrgHostServiceID].Type)
	assert.Empty(t, current.Services[OrgHostServiceID], "the current operation is not mutated")
	assert.Empty(t, current.VerificationMethods[OrgKeyID], "the current operation is not mutated")

	// A given key wins and is not generated.
	_, hostKey, err := newKey()
	require.NoError(t, err)
	plan, err = buildUpdate(current, "cid1", updateOptions{OrgKey: hostKey})
	require.NoError(t, err)
	assert.Nil(t, plan.OrgKey)
	assert.Equal(t, hostKey, plan.Op.VerificationMethods[OrgKeyID])

	// Re-pointing the host keeps the key.
	withKey := &did.Operation{
		Type:                plan.Op.Type,
		RotationKeys:        plan.Op.RotationKeys,
		VerificationMethods: plan.Op.VerificationMethods,
		AlsoKnownAs:         plan.Op.AlsoKnownAs,
		Services:            plan.Op.Services,
	}
	plan, err = buildUpdate(withKey, "cid2", updateOptions{OrgHost: "https://avis.example/host"})
	require.NoError(t, err)
	assert.Equal(t, hostKey, plan.Op.VerificationMethods[OrgKeyID])
	assert.Equal(t, "https://avis.example/host", plan.Op.Services[OrgHostServiceID].Endpoint)
}

func TestBuildUpdate_ControlledDIDCannotCarryOrgKey(t *testing.T) {
	_, rot, err := newKey()
	require.NoError(t, err)
	_, commitment, err := newCommitment("did:dimo:avis", 0)
	require.NoError(t, err)
	current := &did.Operation{Type: did.OpTypeCreate, RotationKeys: []string{rot}, ControlCommitment: &commitment}

	_, err = buildUpdate(current, "cid1", updateOptions{NewOrgKey: true})
	assert.ErrorContains(t, err, "controlled DID cannot carry")

	// A controlled DID may still name services.
	plan, err := buildUpdate(current, "cid1", updateOptions{Services: "dimo_storage=DimoStorageNode:https://node7.dimo.zone"})
	require.NoError(t, err)
	assert.Nil(t, plan.Op.VerificationMethods)
	assert.Equal(t, &commitment, plan.Op.ControlCommitment)
}

func TestBuildRotate_KeepsOrgKey(t *testing.T) {
	_, rot, err := newKey()
	require.NoError(t, err)
	_, orgKey, err := newKey()
	require.NoError(t, err)
	_, next, err := newKey()
	require.NoError(t, err)
	current := &did.Operation{
		Type:                did.OpTypeCreate,
		RotationKeys:        []string{rot},
		VerificationMethods: map[string]string{"signing": rot, OrgKeyID: orgKey},
		Services:            map[string]did.Service{OrgHostServiceID: {Type: OrgHostServiceType, Endpoint: "https://orghost.dimo.zone"}},
	}

	op := buildRotate(current, "cid1", next)
	assert.Equal(t, []string{next}, op.RotationKeys)
	assert.Equal(t, map[string]string{"signing": next, OrgKeyID: orgKey}, op.VerificationMethods,
		"rotating the org root must not drop the host's commit key")
	assert.Equal(t, current.Services, op.Services)
	assert.Equal(t, orgKey, current.VerificationMethods[OrgKeyID], "the current operation is not mutated")

	_, commitment, err := newCommitment("did:dimo:avis", 0)
	require.NoError(t, err)
	controlled := &did.Operation{Type: did.OpTypeCreate, RotationKeys: []string{rot}, ControlCommitment: &commitment}
	assert.Nil(t, buildRotate(controlled, "cid1", next).VerificationMethods)
}

func TestOrgKeystore_RoundTrip(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	priv, _, err := newKey()
	require.NoError(t, err)

	require.NoError(t, SaveOrgKey("did:dimo:abc", priv))
	got, err := LoadOrgKey("did:dimo:abc")
	require.NoError(t, err)
	assert.True(t, priv.Equal(got))

	_, err = LoadKey("did:dimo:abc")
	assert.Error(t, err, "the org key is not the org's own signing key")
}

func TestBuildUpdate_SigningKeyHeldElsewhere(t *testing.T) {
	_, rot, err := newKey()
	require.NoError(t, err)
	_, kms, err := newKey()
	require.NoError(t, err)
	current := &did.Operation{Type: did.OpTypeCreate, RotationKeys: []string{rot}, VerificationMethods: map[string]string{"signing": rot}}

	plan, err := buildUpdate(current, "cid1", updateOptions{SigningKey: kms})
	require.NoError(t, err)
	assert.Equal(t, kms, plan.Op.VerificationMethods["signing"])
	assert.Equal(t, []string{rot}, plan.Op.RotationKeys, "the rotation key stays where it was")
	assert.Equal(t, rot, current.VerificationMethods["signing"], "the current operation is not modified")

	_, err = buildUpdate(current, "cid1", updateOptions{SigningKey: "did:key:zQ3shokFTS3brHcDQrn82RUDfCZESWL1ZdCEJwekUDPQiYBme"})
	assert.ErrorContains(t, err, "P-256")
}
