package did

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/DIMO-Network/did-directory/pkg/control"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func testCommitment(t *testing.T, controller string, era uint64) string {
	t.Helper()
	salt, err := control.NewSalt()
	require.NoError(t, err)
	c, err := control.Commit(control.Opening{Controller: controller, Era: era, Salt: salt})
	require.NoError(t, err)
	return c
}

func ptr[T any](v T) *T { return &v }

func controlledGenesis(t *testing.T) *Operation {
	t.Helper()
	key, custodyKey := generateTestKey(t)
	op := &Operation{
		Type:              OpTypeCreate,
		RotationKeys:      []string{custodyKey},
		AlsoKnownAs:       []string{},
		Services:          map[string]Service{},
		ControlCommitment: ptr(testCommitment(t, "did:dimo:avis", 0)),
	}
	op.Sig = signOperation(t, key, op)
	return op
}

func TestValidateCreate_ControlledWithoutVerificationMethods(t *testing.T) {
	assert.NoError(t, ValidateCreate(controlledGenesis(t)))
}

func TestValidateCreate_ControlledRejectsVerificationMethods(t *testing.T) {
	op := controlledGenesis(t)
	_, vk := generateTestKey(t)
	op.VerificationMethods = map[string]string{"signing": vk}
	assert.ErrorContains(t, ValidateCreate(op), "must not have verification methods")
}

func TestValidateCreate_UncontrolledRequiresVerificationMethod(t *testing.T) {
	op := controlledGenesis(t)
	op.ControlCommitment = nil
	assert.ErrorContains(t, ValidateCreate(op), "verification method")
}

func TestValidateCreate_RejectsBadCommitment(t *testing.T) {
	op := controlledGenesis(t)
	op.ControlCommitment = ptr("did:dimo:avis")
	assert.ErrorContains(t, ValidateCreate(op), "controlCommitment")
}

func TestValidateCreate_RejectsTransferFields(t *testing.T) {
	op := controlledGenesis(t)
	op.EffectiveAt = ptr(time.Now().UTC().Format(time.RFC3339))
	assert.ErrorContains(t, ValidateCreate(op), "effectiveAt")
}

func TestValidateUpdate_UnknownType(t *testing.T) {
	op := &Operation{Type: "bogus", Prev: ptr("cid"), Sig: "sig"}
	assert.ErrorContains(t, ValidateUpdate(op), "unknown operation type")
}

func TestValidateUpdate_TransferRequiresFields(t *testing.T) {
	_, k := generateTestKey(t)
	base := Operation{Type: OpTypeTransfer, Prev: ptr("cid"), Sig: "sig", RotationKeys: []string{k}}

	noCommit := base
	noCommit.EffectiveAt = ptr(time.Now().UTC().Format(time.RFC3339))
	assert.ErrorContains(t, ValidateUpdate(&noCommit), "controlCommitment")

	noTime := base
	noTime.ControlCommitment = ptr(testCommitment(t, "did:dimo:hertz", 1))
	assert.ErrorContains(t, ValidateUpdate(&noTime), "effectiveAt")
}

func TestValidateTransition_PlainUpdateCannotChangeController(t *testing.T) {
	head := controlledGenesis(t)
	state := ResolveControlState("did:dimo:veh", []Operation{*head})

	op := *head
	op.Prev = ptr("cid")
	op.ControlCommitment = ptr(testCommitment(t, "did:dimo:hertz", 0))
	assert.ErrorContains(t, ValidateTransition(head, state, &op, time.Now()), "dimo_transfer")

	op.ControlCommitment = nil
	assert.ErrorContains(t, ValidateTransition(head, state, &op, time.Now()), "dimo_transfer")
}

func TestValidateTransition_Transfer(t *testing.T) {
	now := time.Date(2026, 9, 16, 12, 0, 0, 0, time.UTC)
	head := controlledGenesis(t)
	state := ResolveControlState("did:dimo:veh", []Operation{*head})
	_, newKey := generateTestKey(t)

	transfer := &Operation{
		Type:              OpTypeTransfer,
		RotationKeys:      []string{newKey},
		ControlCommitment: ptr(testCommitment(t, "did:dimo:buyer", 1)),
		EffectiveAt:       ptr(now.Format(time.RFC3339)),
		Prev:              ptr("cid"),
		Sig:               "sig",
	}
	require.NoError(t, ValidateUpdate(transfer))
	assert.NoError(t, ValidateTransition(head, state, transfer, now))

	backdated := *transfer
	backdated.EffectiveAt = ptr(now.Add(-time.Hour).Format(time.RFC3339))
	assert.ErrorContains(t, ValidateTransition(head, state, &backdated, now), "within")

	same := *transfer
	same.ControlCommitment = head.ControlCommitment
	assert.ErrorContains(t, ValidateTransition(head, state, &same, now), "different")
}

func TestValidateTransition_TransferRequiresControlledDID(t *testing.T) {
	key, k := generateTestKey(t)
	head := &Operation{Type: OpTypeCreate, RotationKeys: []string{k}, VerificationMethods: map[string]string{"signing": k}}
	head.Sig = signOperation(t, key, head)
	state := ResolveControlState("did:dimo:person", []Operation{*head})

	transfer := &Operation{
		Type:              OpTypeTransfer,
		RotationKeys:      []string{k},
		ControlCommitment: ptr(testCommitment(t, "did:dimo:x", 1)),
		EffectiveAt:       ptr(time.Now().UTC().Format(time.RFC3339)),
	}
	assert.ErrorContains(t, ValidateTransition(head, state, transfer, time.Now()), "controlled DID")
}

func TestValidateTransition_RevokeSince(t *testing.T) {
	now := time.Date(2026, 9, 16, 12, 0, 0, 0, time.UTC)
	head := controlledGenesis(t)
	state := ResolveControlState("did:dimo:veh", []Operation{*head})
	_, newKey := generateTestKey(t)

	revoke := *head
	revoke.Type = OpTypeRevokeSince
	revoke.Prev = ptr("cid")
	revoke.RotationKeys = []string{newKey}
	// Same controller, next era: the revocation ends the era it revokes in.
	revoke.ControlCommitment = ptr(testCommitment(t, "did:dimo:avis", 1))
	revoke.RevokeSince = ptr(now.Add(-24 * time.Hour).Format(time.RFC3339))
	revoke.EffectiveAt = ptr(now.Format(time.RFC3339))
	require.NoError(t, ValidateUpdate(&revoke))
	assert.NoError(t, ValidateTransition(head, state, &revoke, now), "rotating custody and re-committing is allowed")

	inverted := revoke
	inverted.RevokeSince = ptr(now.Add(time.Hour).Format(time.RFC3339))
	assert.ErrorContains(t, ValidateUpdate(&inverted), "before effectiveAt")

	uncommitted := revoke
	uncommitted.ControlCommitment = nil
	assert.ErrorContains(t, ValidateUpdate(&uncommitted), "new controlCommitment")

	sameEra := revoke
	sameEra.ControlCommitment = head.ControlCommitment
	assert.ErrorContains(t, ValidateTransition(head, state, &sameEra, now), "different controlCommitment")

	stale := revoke
	stale.EffectiveAt = ptr(now.Add(-time.Hour).Format(time.RFC3339))
	assert.ErrorContains(t, ValidateTransition(head, state, &stale, now), "within")

	aliased := revoke
	aliased.AlsoKnownAs = []string{"at://other"}
	assert.ErrorContains(t, ValidateTransition(head, state, &aliased, now), "only rotate")

	// The commitment is opaque, so the directory cannot tell a re-commit under the
	// same controller from a covert handover. It does not have to: whoever holds
	// the custody key could already transfer, and a grantee learns which happened
	// from the opening it is given for the new era.
	shaped := revoke
	shaped.VerificationMethods = map[string]string{"signing": newKey}
	assert.ErrorContains(t, ValidateUpdate(&shaped), "must not have verification methods")
}

func TestValidateTransition_RevokeSinceBoundedToCurrentEra(t *testing.T) {
	eraStart := time.Date(2026, 9, 1, 0, 0, 0, 0, time.UTC)
	now := eraStart.Add(48 * time.Hour)
	head := controlledGenesis(t)
	transfer := *head
	transfer.Type = OpTypeTransfer
	transfer.Prev = ptr("cid")
	transfer.ControlCommitment = ptr(testCommitment(t, "did:dimo:buyer", 1))
	transfer.EffectiveAt = ptr(eraStart.Format(time.RFC3339))
	state := ResolveControlState("did:dimo:veh", []Operation{*head, transfer})

	revoke := transfer
	revoke.Type = OpTypeRevokeSince
	revoke.ControlCommitment = ptr(testCommitment(t, "did:dimo:buyer", 2))
	revoke.EffectiveAt = ptr(now.Format(time.RFC3339))
	revoke.RevokeSince = ptr(eraStart.Add(-time.Hour).Format(time.RFC3339))
	assert.ErrorContains(t, ValidateTransition(&transfer, state, &revoke, now), "current era")
}

func TestValidateTransition_TombstonedHeadRejectsEverything(t *testing.T) {
	head := &Operation{Type: OpTypeTombstone}
	op := controlledGenesis(t)
	assert.ErrorContains(t, ValidateTransition(head, &control.State{}, op, time.Now()), "deactivated")
}

func TestResolveControlState_Eras(t *testing.T) {
	t1 := time.Date(2026, 3, 1, 0, 0, 0, 0, time.UTC)
	t2 := time.Date(2026, 9, 1, 0, 0, 0, 0, time.UTC)
	genesis := controlledGenesis(t)

	transfer1 := *genesis
	transfer1.Type = OpTypeTransfer
	transfer1.ControlCommitment = ptr(testCommitment(t, "did:dimo:hertz", 1))
	transfer1.EffectiveAt = ptr(t1.Format(time.RFC3339))

	issued := t1.Add(96 * time.Hour)
	revoke := transfer1
	revoke.Type = OpTypeRevokeSince
	revoke.ControlCommitment = ptr(testCommitment(t, "did:dimo:hertz", 2))
	revoke.EffectiveAt = ptr(issued.Format(time.RFC3339))
	revoke.RevokeSince = ptr(t1.Add(72 * time.Hour).Format(time.RFC3339))

	transfer2 := transfer1
	transfer2.Type = OpTypeTransfer
	transfer2.ControlCommitment = ptr(testCommitment(t, "did:dimo:buyer", 3))
	transfer2.EffectiveAt = ptr(t2.Format(time.RFC3339))

	state := ResolveControlState("did:dimo:veh", []Operation{*genesis, transfer1, revoke, transfer2})
	require.Len(t, state.Eras, 4)

	assert.Nil(t, state.Eras[0].Start)
	assert.Equal(t, t1, *state.Eras[0].End)
	assert.Equal(t, *genesis.ControlCommitment, state.Eras[0].Commitment)

	// The revocation closes the era it was issued in and records the window.
	assert.Equal(t, t1, *state.Eras[1].Start)
	assert.Equal(t, issued, *state.Eras[1].End)
	require.Len(t, state.Eras[1].Revocations, 1)
	assert.True(t, state.Eras[1].Revoked(t1.Add(80*time.Hour)))
	assert.False(t, state.Eras[1].Revoked(t1.Add(time.Hour)), "delegations committed before the compromise are valid")

	// The new era starts where the window ends, under the same controller, and
	// carries the window forward: the window filters on commit time, so a
	// delegation committed inside it must stay void in the era that follows.
	assert.Equal(t, uint64(2), state.Eras[2].Number)
	assert.Equal(t, issued, *state.Eras[2].Start)
	assert.Equal(t, t2, *state.Eras[2].End)
	require.Len(t, state.Eras[2].Revocations, 1)
	assert.True(t, state.Eras[2].Revoked(t1.Add(80*time.Hour)))
	assert.False(t, state.Eras[2].Revoked(issued.Add(time.Second)), "grants after the revocation are valid")

	assert.Equal(t, uint64(3), state.Current().Number)
	assert.Nil(t, state.Current().End)
	assert.Empty(t, state.Current().Revocations)
	assert.False(t, state.Deactivated)
}

// A revocation window cannot be enforced against a timestamp the signer chooses.
// A stolen key backdates effectiveAt to before the window, or forward past it,
// and the SACD verifies either way — so ending the era is what has to revoke it.
func TestResolveControlState_RevokeSinceEndsTheEra(t *testing.T) {
	compromise := time.Date(2026, 9, 1, 0, 0, 0, 0, time.UTC)
	issued := compromise.Add(24 * time.Hour)
	genesis := controlledGenesis(t)

	revoke := *genesis
	revoke.Type = OpTypeRevokeSince
	revoke.ControlCommitment = ptr(testCommitment(t, "did:dimo:avis", 1))
	revoke.RevokeSince = ptr(compromise.Format(time.RFC3339))
	revoke.EffectiveAt = ptr(issued.Format(time.RFC3339))

	state := ResolveControlState("did:dimo:veh", []Operation{*genesis, revoke})

	require.Len(t, state.Eras, 2)
	assert.Equal(t, uint64(1), state.Current().Number)
	assert.Equal(t, *revoke.ControlCommitment, state.Current().Commitment)
	assert.Equal(t, issued, *state.Eras[0].End, "the revoked era is closed, not left open")
	assert.NotEqual(t, *genesis.ControlCommitment, state.Current().Commitment,
		"an opening for the revoked era must not open the new one")
}

func TestResolveControlState_TombstoneClosesTheEra(t *testing.T) {
	at := time.Date(2026, 9, 17, 12, 0, 0, 0, time.UTC)
	genesis := controlledGenesis(t)
	tomb := Operation{Type: OpTypeTombstone, Prev: ptr("cid"), EffectiveAt: ptr(at.Format(time.RFC3339)), Sig: "sig"}

	state := ResolveControlState("did:dimo:veh", []Operation{*genesis, tomb})

	assert.True(t, state.Deactivated)
	assert.Nil(t, state.Current(), "a deactivated DID has no controller of record")
	require.Len(t, state.Eras, 1)
	assert.Equal(t, at, *state.Eras[0].End, "the final era must not stay open")
}

func TestValidateTransition_TombstoneOfControlledDIDNeedsATimestamp(t *testing.T) {
	now := time.Date(2026, 9, 17, 12, 0, 0, 0, time.UTC)
	head := controlledGenesis(t)
	state := ResolveControlState("did:dimo:veh", []Operation{*head})

	bare := &Operation{Type: OpTypeTombstone, Prev: ptr("cid"), Sig: "sig"}
	assert.ErrorContains(t, ValidateTransition(head, state, bare, now), "requires effectiveAt")

	timed := *bare
	timed.EffectiveAt = ptr(now.Format(time.RFC3339))
	require.NoError(t, ValidateUpdate(&timed))
	assert.NoError(t, ValidateTransition(head, state, &timed, now))

	backdated := *bare
	backdated.EffectiveAt = ptr(now.Add(-time.Hour).Format(time.RFC3339))
	assert.ErrorContains(t, ValidateTransition(head, state, &backdated, now), "within")

	// An uncontrolled DID has no era to close, so it needs no timestamp.
	_, k := generateTestKey(t)
	person := &Operation{Type: OpTypeCreate, RotationKeys: []string{k}, VerificationMethods: map[string]string{"signing": k}}
	assert.NoError(t, ValidateTransition(person, ResolveControlState("did:dimo:person", []Operation{*person}), bare, now))
}

// Resolution runs over whatever the store holds. A hand-inserted row, a restore
// or a future relaxation of validation must not panic GET /:did, /:did/data,
// /:did/control and POST /:did, all of which resolve control state.
func TestResolveControlState_MalformedRowsDoNotPanic(t *testing.T) {
	genesis := controlledGenesis(t)
	at := ptr(time.Now().UTC().Format(time.RFC3339))

	transferNoCommitment := Operation{Type: OpTypeTransfer, EffectiveAt: at, Prev: ptr("cid")}
	revokeNoCommitment := Operation{
		Type:        OpTypeRevokeSince,
		EffectiveAt: at,
		RevokeSince: ptr(time.Now().UTC().Add(-time.Hour).Format(time.RFC3339)),
		Prev:        ptr("cid"),
	}
	unknown := Operation{Type: "dimo_something_new", Prev: ptr("cid")}

	assert.NotPanics(t, func() {
		state := ResolveControlState("did:dimo:veh", []Operation{
			*genesis, transferNoCommitment, revokeNoCommitment, unknown,
		})
		assert.Equal(t, uint64(0), state.Current().Number, "malformed rows are ignored, not applied")
	})
}

func TestResolveControlState_Uncontrolled(t *testing.T) {
	_, k := generateTestKey(t)
	ops := []Operation{{Type: OpTypeCreate, RotationKeys: []string{k}, VerificationMethods: map[string]string{"signing": k}}}
	state := ResolveControlState("did:dimo:person", ops)
	assert.Empty(t, state.Eras)
	assert.Nil(t, state.Current())
}

func TestGenerateDocument_ControlSummary(t *testing.T) {
	genesis := controlledGenesis(t)
	state := ResolveControlState("did:dimo:veh", []Operation{*genesis})

	doc, err := GenerateDocument("did:dimo:veh", genesis, state)
	require.NoError(t, err)
	require.NotNil(t, doc.DimoControl)
	assert.Equal(t, uint64(0), doc.DimoControl.Era)
	assert.Equal(t, *genesis.ControlCommitment, doc.DimoControl.ControlCommitment)
	assert.Empty(t, doc.VerificationMethod)

	data, err := json.Marshal(doc)
	require.NoError(t, err)
	assert.NotContains(t, string(data), "did:dimo:avis", "controller must not appear in the public document")
	assert.NotContains(t, string(data), "dimoSacdEpoch")
}

func TestGenerateDocument_UncontrolledHasNoControl(t *testing.T) {
	_, k := generateTestKey(t)
	op := &Operation{Type: OpTypeCreate, RotationKeys: []string{k}, VerificationMethods: map[string]string{"signing": k}}
	doc, err := GenerateDocument("did:dimo:person", op, ResolveControlState("did:dimo:person", []Operation{*op}))
	require.NoError(t, err)
	assert.Nil(t, doc.DimoControl)
}

func TestOperation_ToUnsigned_CarriesControlFields(t *testing.T) {
	op := controlledGenesis(t)
	op.EffectiveAt = ptr("2026-09-16T00:00:00Z")
	op.RevokeSince = ptr("2026-09-15T00:00:00Z")
	u := op.ToUnsigned()
	assert.Equal(t, op.ControlCommitment, u.ControlCommitment)
	assert.Equal(t, op.EffectiveAt, u.EffectiveAt)
	assert.Equal(t, op.RevokeSince, u.RevokeSince)
}
