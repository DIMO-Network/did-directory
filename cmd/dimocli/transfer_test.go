package main

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"

	dimocrypto "github.com/DIMO-Network/did-directory/internal/crypto"
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
		case r.Method == http.MethodGet && (r.URL.Path == "/did:dimo:buyer" || r.URL.Path == "/did:dimo:fleet"):
			_ = json.NewEncoder(w).Encode(did.DIDDocument{ID: strings.TrimPrefix(r.URL.Path, "/"), AlsoKnownAs: []string{}})
		case r.Method == http.MethodGet && r.URL.Path == "/did:dimo:gone":
			http.Error(w, `{"error":"deactivated"}`, http.StatusGone)
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

	err := executeTransfer(context.Background(), c, tkFlags(f, false), carDID, "did:dimo:buyer", "", "", &bytes.Buffer{})
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
	buyer, err := newFileSignerK1()
	require.NoError(t, err)
	buyerKey := buyer.DIDKey()
	proof := custodyProofBy(t, buyer, carDID, "did:dimo:buyer", 1)

	require.NoError(t, executeTransfer(context.Background(), c, tkFlags(f, false), carDID, "did:dimo:buyer", buyerKey, proof, &bytes.Buffer{}))
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

	require.NoError(t, executeTransfer(context.Background(), c, &turnkeyFlags{}, carDID, "did:dimo:buyer", "", "", &bytes.Buffer{}))
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
	buyer, err := newFileSignerNew()
	require.NoError(t, err)
	require.NoError(t, executeTransfer(context.Background(), c, &turnkeyFlags{}, carDID, "did:dimo:buyer", buyer.DIDKey(),
		custodyProofBy(t, buyer, carDID, "did:dimo:buyer", 1), &bytes.Buffer{}))
	assert.Equal(t, []string{buyer.DIDKey()}, (*ops)[0].RotationKeys)
}

// custodyProofBy is the buyer's acceptance of custody: their new key's
// signature over the car, the new controller and the next era.
func custodyProofBy(t *testing.T, s opSigner, car, to string, era uint64) string {
	t.Helper()
	proof, err := s.Sign(context.Background(), custodyAcceptance(car, to, era))
	require.NoError(t, err)
	return proof
}

// The text a custody proof signs is fixed: a header naming what it is, then
// the car, the new controller and the era the transfer starts.
func TestCustodyAcceptance_Text(t *testing.T) {
	assert.Equal(t, "DIMO custody acceptance v1\nCar: did:dimo:car1\nTo: did:dimo:buyer\nEra: 7",
		string(custodyAcceptance("did:dimo:car1", "did:dimo:buyer", 7)))
}

// R3-F3: the new custody key becomes the only key that can ever sign for the
// car again, so a given key must come with proof that its holder accepts this
// transfer: a signature by it over the car, --to and the next era. A typo, a
// shifted CSV column, a proof for another car, controller or era, or a key
// nobody proved all stop before anything is signed.
func TestTransfer_NewCustodyKeyNeedsItsHoldersProof(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	cur, err := newFileSignerNew()
	require.NoError(t, err)
	require.NoError(t, SaveKey(carDID, cur.key))
	buyer, err := newFileSignerK1()
	require.NoError(t, err)
	other, err := newFileSignerK1()
	require.NoError(t, err)
	good := custodyProofBy(t, buyer, carDID, "did:dimo:buyer", 1)

	// A one-character typo that still decodes as a did:key.
	typo := ""
	for i := len(buyer.DIDKey()) - 1; i > len("did:key:z"); i-- {
		for _, ch := range "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz" {
			k := buyer.DIDKey()[:i] + string(ch) + buyer.DIDKey()[i+1:]
			if k == buyer.DIDKey() {
				continue
			}
			if _, err := dimocrypto.DecodeDIDKey(k); err == nil {
				typo = k
				break
			}
		}
		if typo != "" {
			break
		}
	}
	require.NotEmpty(t, typo)

	for name, tc := range map[string]struct{ key, proof, want string }{
		"no proof":        {buyer.DIDKey(), "", "--new-custody-proof"},
		"typo in the key": {typo, good, "custody proof"},
		"another's proof": {buyer.DIDKey(), custodyProofBy(t, other, carDID, "did:dimo:buyer", 1), "custody proof"},
		"another car":     {buyer.DIDKey(), custodyProofBy(t, buyer, "did:dimo:car2", "did:dimo:buyer", 1), "custody proof"},
		"another to":      {buyer.DIDKey(), custodyProofBy(t, buyer, carDID, "did:dimo:fleet", 1), "custody proof"},
		"another era":     {buyer.DIDKey(), custodyProofBy(t, buyer, carDID, "did:dimo:buyer", 2), "custody proof"},
		"garbage":         {buyer.DIDKey(), "not-a-signature", "custody proof"},
	} {
		c, ops := carDirectory(t, cur.DIDKey())
		err := executeTransfer(context.Background(), c, &turnkeyFlags{}, carDID, "did:dimo:buyer", tc.key, tc.proof, &bytes.Buffer{})
		require.Error(t, err, name)
		assert.Contains(t, err.Error(), tc.want, name)
		assert.Empty(t, *ops, "%s: nothing submitted", name)
	}

	// Through Turnkey too, and before Turnkey signs anything.
	f := newFakeTurnkey(t, 0)
	c, ops := carDirectory(t, f.didKeyAt(t, "m/44'/60'/0'/0/0"))
	err = executeTransfer(context.Background(), c, tkFlags(f, false), carDID, "did:dimo:buyer", buyer.DIDKey(), "", &bytes.Buffer{})
	require.Error(t, err)
	assert.Empty(t, *ops)
	assert.Zero(t, f.signed, "the custody key never signed")
}

// R3-F3: --to must be a DID the directory holds, live.
func TestTransfer_ResolvesTo(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	cur, err := newFileSignerNew()
	require.NoError(t, err)
	require.NoError(t, SaveKey(carDID, cur.key))
	for to, want := range map[string]string{
		"did:dimo:nobody": "not in the directory",
		"did:dimo:gone":   "deactivated",
	} {
		c, ops := carDirectory(t, cur.DIDKey())
		err := executeTransfer(context.Background(), c, &turnkeyFlags{}, carDID, to, "", "", &bytes.Buffer{})
		require.Error(t, err, to)
		assert.Contains(t, err.Error(), want, to)
		assert.Empty(t, *ops, to)
	}
}

// dimocli custody-proof is how the buyer makes the proof from a key file,
// P-256 or secp256k1; --generate makes the file (0600) and refuses to
// overwrite one.
func TestCustodyProof_FromAKeyFile(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	dir := t.TempDir()
	path := dir + "/custody.json"
	key, proof, err := executeCustodyProof(path, true, carDID, "did:dimo:buyer", 1)
	require.NoError(t, err)
	require.NoError(t, verifyCustodyProof(key, proof, carDID, "did:dimo:buyer", 1))
	fi, err := os.Stat(path)
	require.NoError(t, err)
	assert.Equal(t, os.FileMode(0o600), fi.Mode().Perm())

	_, _, err = executeCustodyProof(path, true, carDID, "did:dimo:buyer", 1)
	assert.Error(t, err, "--generate never overwrites a key")

	again, proof2, err := executeCustodyProof(path, false, carDID, "did:dimo:fleet", 3)
	require.NoError(t, err)
	assert.Equal(t, key, again, "the same key file, the same key")
	require.NoError(t, verifyCustodyProof(key, proof2, carDID, "did:dimo:fleet", 3))

	// A secp256k1 key file, as the keystore writes for an org root.
	k1, err := newFileSignerK1()
	require.NoError(t, err)
	k1Path := dir + "/k1.json"
	require.NoError(t, writeK1Key(k1Path, "did:dimo:buyer", k1.k1))
	got, proof3, err := executeCustodyProof(k1Path, false, carDID, "did:dimo:buyer", 1)
	require.NoError(t, err)
	assert.Equal(t, k1.DIDKey(), got)
	require.NoError(t, verifyCustodyProof(got, proof3, carDID, "did:dimo:buyer", 1))

	// The seller's transfer takes what the buyer printed.
	cur, err := newFileSignerNew()
	require.NoError(t, err)
	require.NoError(t, SaveKey(carDID, cur.key))
	c, ops := carDirectory(t, cur.DIDKey())
	require.NoError(t, executeTransfer(context.Background(), c, &turnkeyFlags{}, carDID, "did:dimo:buyer", got, proof3, &bytes.Buffer{}))
	assert.Equal(t, []string{got}, (*ops)[0].RotationKeys)
}
