package sacd

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"testing"
	"time"

	dimocrypto "github.com/DIMO-Network/did-directory/internal/crypto"
	"github.com/DIMO-Network/did-directory/pkg/control"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

var now = time.Date(2026, 9, 16, 12, 0, 0, 0, time.UTC)

type fixture struct {
	key    *ecdsa.PrivateKey
	didKey string
	asset  *control.State
	doc    *Document
}

func newFixture(t *testing.T) *fixture {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	didKey, err := dimocrypto.EncodeDIDKey(&key.PublicKey)
	require.NoError(t, err)

	salt, err := control.NewSalt()
	require.NoError(t, err)
	opening := control.Opening{Controller: "did:dimo:owner", Era: 0, Salt: salt}
	commitment, err := control.Commit(opening)
	require.NoError(t, err)

	f := &fixture{
		key:    key,
		didKey: didKey,
		asset:  &control.State{DID: "did:dimo:veh", Eras: []control.Era{{Number: 0, Commitment: commitment}}},
		doc: &Document{
			Type:         DocumentType,
			Grantor:      "did:dimo:owner",
			Grantee:      "did:dimo:dev",
			Asset:        "did:dimo:veh",
			Era:          0,
			Permissions:  []string{"telemetry:read"},
			EffectiveAt:  now.Add(-time.Hour).Format(time.RFC3339),
			ExpiresAt:    now.Add(time.Hour).Format(time.RFC3339),
			ControlProof: &opening,
		},
	}
	f.sign(t)
	return f
}

func (f *fixture) sign(t *testing.T) {
	t.Helper()
	f.doc.Signature = ""
	payload, err := f.doc.UnsignedPayload()
	require.NoError(t, err)
	sig, err := dimocrypto.SignOperation(f.key, payload)
	require.NoError(t, err)
	f.doc.Signature = sig
}

func TestVerify_ControllerGrant(t *testing.T) {
	f := newFixture(t)
	assert.NoError(t, f.doc.Verify([]string{f.didKey}, f.asset, now))
}

func TestVerify_VehicleCannotGrantItself(t *testing.T) {
	f := newFixture(t)
	f.doc.Grantor = "did:dimo:veh"
	f.sign(t)
	assert.ErrorContains(t, f.doc.Verify([]string{f.didKey}, f.asset, now), "cannot grant access to itself")
}

func TestVerify_NonControllerRejected(t *testing.T) {
	f := newFixture(t)
	f.doc.Grantor = "did:dimo:stranger"
	f.doc.ControlProof.Controller = "did:dimo:stranger"
	f.sign(t)
	assert.ErrorContains(t, f.doc.Verify([]string{f.didKey}, f.asset, now), "controller of record")
}

func TestVerify_MissingProof(t *testing.T) {
	f := newFixture(t)
	f.doc.ControlProof = nil
	f.sign(t)
	assert.ErrorContains(t, f.doc.Verify([]string{f.didKey}, f.asset, now), "controlProof is required")
}

func TestVerify_TransferInvalidates(t *testing.T) {
	f := newFixture(t)
	start := now.Add(-30 * time.Minute)
	f.asset.Eras[0].End = &start
	f.asset.Eras = append(f.asset.Eras, control.Era{Number: 1, Start: &start, Commitment: f.asset.Eras[0].Commitment})
	assert.ErrorContains(t, f.doc.Verify([]string{f.didKey}, f.asset, now), "era")
}

func TestVerify_RevocationWindow(t *testing.T) {
	f := newFixture(t)
	f.asset.Eras[0].Revocations = []control.Revocation{{From: now.Add(-2 * time.Hour), To: now.Add(-10 * time.Minute)}}
	assert.ErrorContains(t, f.doc.Verify([]string{f.didKey}, f.asset, now), "revocation window")

	f.doc.EffectiveAt = now.Add(-5 * time.Minute).Format(time.RFC3339)
	f.sign(t)
	assert.NoError(t, f.doc.Verify([]string{f.didKey}, f.asset, now), "re-grant after the revocation is valid")
}

// The revocation window is checked against effectiveAt, a timestamp the signer
// chooses. A stolen key can sit outside any window it likes — which is why
// dimo_revoke_since ends the era rather than relying on the window alone.
func TestVerify_RevocationWindowCannotBindAChosenTimestamp(t *testing.T) {
	window := control.Revocation{From: now.Add(-2 * time.Hour), To: now.Add(-10 * time.Minute)}

	backdated := newFixture(t)
	backdated.asset.Eras[0].Revocations = []control.Revocation{window}
	backdated.doc.EffectiveAt = now.Add(-3 * time.Hour).Format(time.RFC3339)
	backdated.sign(t)
	assert.NoError(t, backdated.doc.Verify([]string{backdated.didKey}, backdated.asset, now),
		"a backdated effectiveAt walks straight past the window: the window is not the mechanism")

	// Ending the era is. The thief's document names era 0; the directory has
	// moved to era 1, whose commitment the thief's opening does not open.
	ended := now.Add(-10 * time.Minute)
	backdated.asset.Eras[0].End = &ended
	backdated.asset.Eras = append(backdated.asset.Eras, control.Era{
		Number:      1,
		Start:       &ended,
		Commitment:  "sha256:" + "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
		Revocations: []control.Revocation{window},
	})
	assert.ErrorContains(t, backdated.doc.Verify([]string{backdated.didKey}, backdated.asset, now), "era")
}

// Deactivating a vehicle must stop its grants. Control state is what SACD
// verification reads, and it never looked at the tombstone.
func TestVerify_DeactivatedAsset(t *testing.T) {
	f := newFixture(t)
	require.NoError(t, f.doc.Verify([]string{f.didKey}, f.asset, now))

	f.asset.Deactivated = true
	assert.ErrorContains(t, f.doc.Verify([]string{f.didKey}, f.asset, now), "deactivated")
}

func TestVerify_SelfGrantForUncontrolledDID(t *testing.T) {
	f := newFixture(t)
	person := &control.State{DID: "did:dimo:owner"}
	f.doc.Asset = "did:dimo:owner"
	f.doc.ControlProof = nil
	f.sign(t)
	assert.NoError(t, f.doc.Verify([]string{f.didKey}, person, now))

	f.doc.Asset = "did:dimo:someone-else"
	f.sign(t)
	assert.ErrorContains(t, f.doc.Verify([]string{f.didKey}, person, now), "grantor must be the asset")
}

func TestVerify_AnyGrantorKey(t *testing.T) {
	f := newFixture(t)
	other, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	otherKey, err := dimocrypto.EncodeDIDKey(&other.PublicKey)
	require.NoError(t, err)
	assert.NoError(t, f.doc.Verify([]string{otherKey, f.didKey}, f.asset, now))
	assert.Error(t, f.doc.Verify([]string{otherKey}, f.asset, now))
}

func TestVerify_TamperedPermissions(t *testing.T) {
	f := newFixture(t)
	f.doc.Permissions = []string{"command:unlock"}
	assert.ErrorContains(t, f.doc.Verify([]string{f.didKey}, f.asset, now), "signature")
}

func TestVerify_TimeBounds(t *testing.T) {
	f := newFixture(t)
	assert.ErrorContains(t, f.doc.Verify([]string{f.didKey}, f.asset, now.Add(2*time.Hour)), "expired")
	assert.ErrorContains(t, f.doc.Verify([]string{f.didKey}, f.asset, now.Add(-2*time.Hour)), "not yet effective")
}
