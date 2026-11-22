package main

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/DIMO-Network/did-directory/internal/did"
	"github.com/DIMO-Network/did-directory/pkg/client"
	"github.com/DIMO-Network/did-directory/pkg/control"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const carDID = "did:dimo:car1"

// carDirectory serves one controlled car at era 0 whose rotation key is
// rotationKey, and records submitted operations.
func carDirectory(t *testing.T, rotationKey string) (*client.Client, *[]*did.Operation) {
	t.Helper()
	_, commitment, err := newCommitment("did:dimo:fleet", 0)
	require.NoError(t, err)
	current := did.Operation{Type: did.OpTypeCreate, RotationKeys: []string{rotationKey}, ControlCommitment: &commitment}
	var ops []*did.Operation
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodGet && strings.HasSuffix(r.URL.Path, "/control"):
			_ = json.NewEncoder(w).Encode(control.State{DID: carDID, Eras: []control.Era{{Number: 0, Commitment: commitment}}})
		case r.Method == http.MethodGet && strings.HasSuffix(r.URL.Path, "/log/audit"):
			_ = json.NewEncoder(w).Encode([]map[string]any{{"cid": "bafyprev", "operation": current}})
		case r.Method == http.MethodPost:
			var op did.Operation
			require.NoError(t, json.NewDecoder(r.Body).Decode(&op))
			ops = append(ops, &op)
			_, _ = w.Write([]byte(`{"did":"` + carDID + `","cid":"bafynew"}`))
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(srv.Close)
	return client.New(srv.URL), &ops
}

func TestTransfer_TurnkeyNeedsTheNewControllersKey(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	f := newFakeTurnkey(t, 0)
	c, ops := carDirectory(t, f.didKeyAt(t, "m/44'/60'/0'/0/0"))

	err := executeTransfer(context.Background(), c, tkFlags(f, false), carDID, "did:dimo:buyer", "", &bytes.Buffer{})
	require.Error(t, err)
	assert.Equal(t, "a Turnkey transfer needs --new-custody-key from the new controller", err.Error())
	assert.Empty(t, *ops)
	assert.Empty(t, f.created)
}

func TestTransfer_TurnkeyUsesTheGivenKeyAndCreatesNoAccount(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	f := newFakeTurnkey(t, 0)
	old := f.didKeyAt(t, "m/44'/60'/0'/0/0")
	c, ops := carDirectory(t, old)
	buyerKey := newSecpDIDKey(t)

	require.NoError(t, executeTransfer(context.Background(), c, tkFlags(f, false), carDID, "did:dimo:buyer", buyerKey, &bytes.Buffer{}))
	require.Len(t, *ops, 1)
	op := (*ops)[0]
	assert.Equal(t, []string{buyerKey}, op.RotationKeys)
	assert.Equal(t, did.OpTypeTransfer, op.Type)
	assert.Empty(t, f.created, "no account is created in the sending org's wallet")
	verifyOp(t, old, op)
}

func TestTransfer_FilePathStillGeneratesAKeyAndAcceptsAGivenOne(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	cur, err := newFileSignerNew()
	require.NoError(t, err)
	require.NoError(t, SaveKey(carDID, cur.key))
	c, ops := carDirectory(t, cur.DIDKey())

	require.NoError(t, executeTransfer(context.Background(), c, &turnkeyFlags{}, carDID, "did:dimo:buyer", "", &bytes.Buffer{}))
	generated := (*ops)[0].RotationKeys[0]
	assert.NotEqual(t, cur.DIDKey(), generated)
	saved, err := LoadKey(carDID)
	require.NoError(t, err)
	got, _ := newFileSigner(saved)
	assert.Equal(t, generated, got.DIDKey(), "the generated key is the one in the keystore now")

	// Given a key, the file path uses it and keeps its own keystore entry.
	cur2, _ := newFileSignerNew()
	require.NoError(t, SaveKey(carDID, cur2.key))
	c, ops = carDirectory(t, cur2.DIDKey())
	buyer := newSecpDIDKey(t)
	require.NoError(t, executeTransfer(context.Background(), c, &turnkeyFlags{}, carDID, "did:dimo:buyer", buyer, &bytes.Buffer{}))
	assert.Equal(t, []string{buyer}, (*ops)[0].RotationKeys)
}
