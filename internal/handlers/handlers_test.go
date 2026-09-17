package handlers

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	dimocrypto "github.com/DIMO-Network/did-directory/internal/crypto"
	"github.com/DIMO-Network/did-directory/internal/did"
	"github.com/DIMO-Network/did-directory/internal/store"
	"github.com/gofiber/fiber/v2"
	"github.com/rs/zerolog"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type fixture struct {
	t   *testing.T
	st  store.Store
	app *fiber.App
}

func newFixture(t *testing.T) *fixture {
	t.Helper()

	st := store.NewMemoryStore()
	log := zerolog.Nop()
	app := fiber.New(fiber.Config{DisableStartupMessage: true})
	app.Get("/export", NewExportHandler(st, 100, log).Handle)
	app.Post("/:did", NewSubmitHandler(st, log).Handle)
	resolve := NewResolveHandler(st, log)
	app.Get("/:did", resolve.HandleResolve)
	app.Get("/:did/data", resolve.HandleData)
	app.Get("/:did/control", resolve.HandleControl)
	app.Get("/:did/log/audit", NewAuditHandler(st, log).Handle)

	return &fixture{t: t, st: st, app: app}
}

func (f *fixture) do(req *http.Request) (int, []byte) {
	f.t.Helper()
	resp, err := f.app.Test(req, -1)
	require.NoError(f.t, err)
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	require.NoError(f.t, err)
	return resp.StatusCode, body
}

func (f *fixture) get(path string) (int, []byte) {
	return f.do(httptest.NewRequest(http.MethodGet, path, nil))
}

func (f *fixture) post(path string, body []byte) (int, []byte) {
	req := httptest.NewRequest(http.MethodPost, path, bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	return f.do(req)
}

// newDID submits a genesis operation and returns the DID and its head CID.
func (f *fixture) newDID() (string, string) {
	f.t.Helper()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(f.t, err)
	didKey, err := dimocrypto.EncodeDIDKey(&key.PublicKey)
	require.NoError(f.t, err)

	op := &did.Operation{
		Type:                did.OpTypeCreate,
		RotationKeys:        []string{didKey},
		VerificationMethods: map[string]string{"signing": didKey},
		AlsoKnownAs:         []string{"at://alice.dimo.zone"},
		Services:            map[string]did.Service{"storage": {Type: "DimoStorageNode", Endpoint: "https://node7.dimo.zone"}},
	}
	data, err := json.Marshal(op.ToUnsigned())
	require.NoError(f.t, err)
	op.Sig, err = dimocrypto.SignOperation(key, data)
	require.NoError(f.t, err)

	didStr, err := did.DeriveFromGenesis(op)
	require.NoError(f.t, err)

	raw, err := json.Marshal(op)
	require.NoError(f.t, err)
	status, body := f.post("/"+didStr, raw)
	require.Equal(f.t, http.StatusOK, status, string(body))

	var out map[string]string
	require.NoError(f.t, json.Unmarshal(body, &out))
	return didStr, out["cid"]
}

func TestResolve(t *testing.T) {
	f := newFixture(t)
	didStr, cid := f.newDID()

	status, body := f.get("/" + didStr)
	require.Equal(t, http.StatusOK, status, string(body))
	var doc did.DIDDocument
	require.NoError(t, json.Unmarshal(body, &doc))
	assert.Equal(t, didStr, doc.ID)
	require.Len(t, doc.VerificationMethod, 1)
	require.Len(t, doc.Service, 1)
	assert.Nil(t, doc.DimoControl, "an uncontrolled DID has no control summary")

	status, body = f.get("/did:dimo:aaaaaaaaaaaaaaaaaaaaaaaa")
	assert.Equal(t, http.StatusNotFound, status)
	assert.Contains(t, string(body), "DID not found")

	// Data.
	status, body = f.get("/" + didStr + "/data")
	require.Equal(t, http.StatusOK, status, string(body))
	var data map[string]any
	require.NoError(t, json.Unmarshal(body, &data))
	assert.Equal(t, didStr, data["did"])
	assert.Equal(t, cid, data["cid"])
	assert.Nil(t, data["controlCommitment"])
	assert.Empty(t, data["eras"])

	status, _ = f.get("/did:dimo:aaaaaaaaaaaaaaaaaaaaaaaa/data")
	assert.Equal(t, http.StatusNotFound, status)

	// Control.
	status, body = f.get("/" + didStr + "/control")
	require.Equal(t, http.StatusOK, status, string(body))
	assert.Contains(t, string(body), didStr)

	status, _ = f.get("/did:dimo:aaaaaaaaaaaaaaaaaaaaaaaa/control")
	assert.Equal(t, http.StatusNotFound, status)
}

func TestAudit(t *testing.T) {
	f := newFixture(t)
	didStr, cid := f.newDID()

	status, body := f.get("/" + didStr + "/log/audit")
	require.Equal(t, http.StatusOK, status, string(body))

	var entries []map[string]any
	require.NoError(t, json.Unmarshal(body, &entries))
	require.Len(t, entries, 1)
	assert.Equal(t, didStr, entries[0]["did"])
	assert.Equal(t, cid, entries[0]["cid"])
	assert.NotEmpty(t, entries[0]["createdAt"])

	status, body = f.get("/did:dimo:aaaaaaaaaaaaaaaaaaaaaaaa/log/audit")
	assert.Equal(t, http.StatusNotFound, status)
	assert.Contains(t, string(body), "DID not found")
}

func TestExport(t *testing.T) {
	f := newFixture(t)
	first, _ := f.newDID()
	second, _ := f.newDID()

	status, body := f.get("/export")
	require.Equal(t, http.StatusOK, status)

	lines := strings.Split(strings.TrimSpace(string(body)), "\n")
	require.Len(t, lines, 2)
	var rec store.ExportRecord
	require.NoError(t, json.Unmarshal([]byte(lines[0]), &rec))
	assert.Equal(t, first, rec.DID)
	assert.NotEmpty(t, rec.CreatedAt)

	// Cursor.
	status, body = f.get("/export?after=1")
	require.Equal(t, http.StatusOK, status)
	lines = strings.Split(strings.TrimSpace(string(body)), "\n")
	require.Len(t, lines, 1)
	require.NoError(t, json.Unmarshal([]byte(lines[0]), &rec))
	assert.Equal(t, second, rec.DID)

	// A limit past the page size falls back to the page size rather than failing.
	status, body = f.get("/export?limit=100000")
	assert.Equal(t, http.StatusOK, status)
	assert.Len(t, strings.Split(strings.TrimSpace(string(body)), "\n"), 2)

	status, body = f.get("/export?after=banana")
	assert.Equal(t, http.StatusBadRequest, status)
	assert.Contains(t, string(body), "invalid 'after' parameter")
}

func TestSubmit_Rejections(t *testing.T) {
	f := newFixture(t)
	didStr, cid := f.newDID()

	status, body := f.post("/did:dimo:aaaaaaaaaaaaaaaaaaaaaaaa", []byte("{not json"))
	assert.Equal(t, http.StatusBadRequest, status)
	assert.Contains(t, string(body), "invalid operation JSON")

	// Genesis whose derived DID is not the one in the URL.
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	didKey, err := dimocrypto.EncodeDIDKey(&key.PublicKey)
	require.NoError(t, err)
	op := &did.Operation{
		Type:                did.OpTypeCreate,
		RotationKeys:        []string{didKey},
		VerificationMethods: map[string]string{"signing": didKey},
	}
	data, err := json.Marshal(op.ToUnsigned())
	require.NoError(t, err)
	op.Sig, err = dimocrypto.SignOperation(key, data)
	require.NoError(t, err)
	raw, err := json.Marshal(op)
	require.NoError(t, err)
	status, body = f.post("/did:dimo:aaaaaaaaaaaaaaaaaaaaaaaa", raw)
	assert.Equal(t, http.StatusBadRequest, status)
	assert.Contains(t, string(body), "DID mismatch")

	// Unsigned genesis.
	unsigned := *op
	unsigned.Sig = ""
	raw, err = json.Marshal(&unsigned)
	require.NoError(t, err)
	status, body = f.post("/did:dimo:bbbbbbbbbbbbbbbbbbbbbbbb", raw)
	assert.Equal(t, http.StatusBadRequest, status)
	assert.Contains(t, string(body), "must be signed")

	// Update with a stale prev.
	stale := &did.Operation{
		Type:                did.OpTypeCreate,
		RotationKeys:        []string{didKey},
		VerificationMethods: map[string]string{"signing": didKey},
		Prev:                strPtr("bafyreiaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"),
	}
	data, err = json.Marshal(stale.ToUnsigned())
	require.NoError(t, err)
	stale.Sig, err = dimocrypto.SignOperation(key, data)
	require.NoError(t, err)
	raw, err = json.Marshal(stale)
	require.NoError(t, err)
	status, body = f.post("/"+didStr, raw)
	assert.Equal(t, http.StatusConflict, status)
	assert.Contains(t, string(body), cid)

	// Update signed by a key that is not a rotation key of the current state.
	intruderKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	intruder := *stale
	intruder.Prev = &cid
	data, err = json.Marshal(intruder.ToUnsigned())
	require.NoError(t, err)
	intruder.Sig, err = dimocrypto.SignOperation(intruderKey, data)
	require.NoError(t, err)
	raw, err = json.Marshal(&intruder)
	require.NoError(t, err)
	status, body = f.post("/"+didStr, raw)
	assert.Equal(t, http.StatusBadRequest, status)
	assert.Contains(t, string(body), "invalid signature")

	// Update with no prev at all.
	noPrev := *op
	noPrev.Prev = nil
	raw, err = json.Marshal(&noPrev)
	require.NoError(t, err)
	status, body = f.post("/"+didStr, raw)
	assert.Equal(t, http.StatusBadRequest, status)
	assert.Contains(t, string(body), "previous CID")
}

// A second genesis for a DID that already exists must not land, even if the
// existence check that routes it to handleCreate raced with the first write.
func TestSubmit_DuplicateGenesisIsRejected(t *testing.T) {
	f := newFixture(t)
	didStr, cid := f.newDID()

	log, err := f.st.GetLog(context.Background(), didStr)
	require.NoError(t, err)
	require.Len(t, log, 1)

	err = f.st.AppendAfter(context.Background(), didStr, "", "second-genesis", &log[0].Operation)
	assert.ErrorIs(t, err, store.ErrHeadChanged)

	log, err = f.st.GetLog(context.Background(), didStr)
	require.NoError(t, err)
	require.Len(t, log, 1)
	assert.Equal(t, cid, log[0].CID)
}

func strPtr(s string) *string { return &s }
