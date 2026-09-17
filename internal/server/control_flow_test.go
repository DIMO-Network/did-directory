package server

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/DIMO-Network/did-directory/internal/config"
	dimocrypto "github.com/DIMO-Network/did-directory/internal/crypto"
	"github.com/DIMO-Network/did-directory/internal/did"
	"github.com/DIMO-Network/did-directory/internal/store"
	"github.com/DIMO-Network/did-directory/pkg/control"
	"github.com/gofiber/fiber/v2"
	"github.com/rs/zerolog"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type flow struct {
	t   *testing.T
	app *fiber.App
}

func newFlow(t *testing.T) *flow {
	cfg := &config.Settings{ExportPageSize: 100}
	return &flow{t: t, app: New(cfg, store.NewMemoryStore(), zerolog.Nop())}
}

func (f *flow) key() (*ecdsa.PrivateKey, string) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(f.t, err)
	didKey, err := dimocrypto.EncodeDIDKey(&key.PublicKey)
	require.NoError(f.t, err)
	return key, didKey
}

func (f *flow) commitment(controller string, era uint64) string {
	salt, err := control.NewSalt()
	require.NoError(f.t, err)
	c, err := control.Commit(control.Opening{Controller: controller, Era: era, Salt: salt})
	require.NoError(f.t, err)
	return c
}

func (f *flow) sign(key *ecdsa.PrivateKey, op *did.Operation) *did.Operation {
	data, err := json.Marshal(op.ToUnsigned())
	require.NoError(f.t, err)
	op.Sig, err = dimocrypto.SignOperation(key, data)
	require.NoError(f.t, err)
	return op
}

func (f *flow) submit(didStr string, op *did.Operation) (int, map[string]any) {
	body, err := json.Marshal(op)
	require.NoError(f.t, err)
	req := httptest.NewRequest(http.MethodPost, "/"+didStr, bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	resp, err := f.app.Test(req, -1)
	require.NoError(f.t, err)
	defer resp.Body.Close()
	var out map[string]any
	raw, _ := io.ReadAll(resp.Body)
	_ = json.Unmarshal(raw, &out)
	return resp.StatusCode, out
}

func (f *flow) get(path string, v any) int {
	resp, err := f.app.Test(httptest.NewRequest(http.MethodGet, path, nil), -1)
	require.NoError(f.t, err)
	defer resp.Body.Close()
	require.NoError(f.t, json.NewDecoder(resp.Body).Decode(v))
	return resp.StatusCode
}

func ptr[T any](v T) *T { return &v }

func TestControlFlow(t *testing.T) {
	f := newFlow(t)

	// Create a controlled vehicle DID: custody key only, commitment to Avis.
	custody, custodyDIDKey := f.key()
	genesis := f.sign(custody, &did.Operation{
		Type:              did.OpTypeCreate,
		RotationKeys:      []string{custodyDIDKey},
		AlsoKnownAs:       []string{},
		Services:          map[string]did.Service{},
		ControlCommitment: ptr(f.commitment("did:dimo:avis", 0)),
	})
	vehicle, err := did.DeriveFromGenesis(genesis)
	require.NoError(t, err)
	status, body := f.submit(vehicle, genesis)
	require.Equal(t, http.StatusOK, status, body)
	headCID := body["cid"].(string)

	var doc did.DIDDocument
	require.Equal(t, http.StatusOK, f.get("/"+vehicle, &doc))
	require.NotNil(t, doc.DimoControl)
	assert.Equal(t, uint64(0), doc.DimoControl.Era)
	assert.Empty(t, doc.VerificationMethod)

	// A plain update cannot swap the controller.
	sneaky := f.sign(custody, &did.Operation{
		Type:              did.OpTypeCreate,
		RotationKeys:      []string{custodyDIDKey},
		ControlCommitment: ptr(f.commitment("did:dimo:attacker", 0)),
		Prev:              &headCID,
	})
	status, body = f.submit(vehicle, sneaky)
	assert.Equal(t, http.StatusBadRequest, status)
	assert.Contains(t, body["error"], "dimo_transfer")

	// Sale: transfer to a buyer, signed by the current custody key.
	buyerCustody, buyerCustodyDIDKey := f.key()
	transferAt := time.Now().UTC().Truncate(time.Second)
	transfer := f.sign(custody, &did.Operation{
		Type:              did.OpTypeTransfer,
		RotationKeys:      []string{buyerCustodyDIDKey},
		ControlCommitment: ptr(f.commitment("did:dimo:buyer", 1)),
		EffectiveAt:       ptr(transferAt.Format(time.RFC3339)),
		Prev:              &headCID,
	})
	status, body = f.submit(vehicle, transfer)
	require.Equal(t, http.StatusOK, status, body)
	headCID = body["cid"].(string)

	// The old custody key has no authority any more.
	stale := f.sign(custody, &did.Operation{
		Type:              did.OpTypeCreate,
		RotationKeys:      []string{custodyDIDKey},
		ControlCommitment: transfer.ControlCommitment,
		Prev:              &headCID,
	})
	status, _ = f.submit(vehicle, stale)
	assert.Equal(t, http.StatusBadRequest, status)

	// Buyer's key is compromised: record a window and rotate custody.
	rotated, rotatedDIDKey := f.key()
	issued := time.Now().UTC().Truncate(time.Second).Add(time.Second)
	revoke := f.sign(buyerCustody, &did.Operation{
		Type:              did.OpTypeRevokeSince,
		RotationKeys:      []string{rotatedDIDKey},
		ControlCommitment: transfer.ControlCommitment,
		RevokeSince:       ptr(transferAt.Format(time.RFC3339)),
		EffectiveAt:       ptr(issued.Format(time.RFC3339)),
		Prev:              &headCID,
	})
	status, body = f.submit(vehicle, revoke)
	require.Equal(t, http.StatusOK, status, body)
	headCID = body["cid"].(string)

	var state control.State
	require.Equal(t, http.StatusOK, f.get("/"+vehicle+"/control", &state))
	require.Len(t, state.Eras, 2)
	assert.Equal(t, transferAt, *state.Eras[0].End)
	assert.Equal(t, transferAt, *state.Eras[1].Start)
	require.Len(t, state.Eras[1].Revocations, 1)
	assert.True(t, state.Eras[1].Revoked(transferAt))
	assert.False(t, state.Eras[1].Revoked(issued.Add(time.Second)))

	// Deactivation is terminal.
	tomb := f.sign(rotated, &did.Operation{Type: did.OpTypeTombstone, Prev: &headCID})
	status, body = f.submit(vehicle, tomb)
	require.Equal(t, http.StatusOK, status, body)
	after := f.sign(rotated, &did.Operation{
		Type:              did.OpTypeCreate,
		RotationKeys:      []string{rotatedDIDKey},
		ControlCommitment: transfer.ControlCommitment,
		Prev:              ptr(body["cid"].(string)),
	})
	status, body = f.submit(vehicle, after)
	assert.Equal(t, http.StatusBadRequest, status)
	assert.Contains(t, body["error"], "deactivated")
}

func TestUncontrolledDIDCannotTransfer(t *testing.T) {
	f := newFlow(t)
	key, didKey := f.key()
	genesis := f.sign(key, &did.Operation{
		Type:                did.OpTypeCreate,
		RotationKeys:        []string{didKey},
		VerificationMethods: map[string]string{"signing": didKey},
	})
	person, err := did.DeriveFromGenesis(genesis)
	require.NoError(t, err)
	status, body := f.submit(person, genesis)
	require.Equal(t, http.StatusOK, status, body)

	transfer := f.sign(key, &did.Operation{
		Type:              did.OpTypeTransfer,
		RotationKeys:      []string{didKey},
		ControlCommitment: ptr(f.commitment("did:dimo:someone", 1)),
		EffectiveAt:       ptr(time.Now().UTC().Format(time.RFC3339)),
		Prev:              ptr(body["cid"].(string)),
	})
	status, body = f.submit(person, transfer)
	assert.Equal(t, http.StatusBadRequest, status)
	assert.Contains(t, body["error"], "controlled DID")

	var state control.State
	require.Equal(t, http.StatusOK, f.get("/"+person+"/control", &state))
	assert.Empty(t, state.Eras)
}
