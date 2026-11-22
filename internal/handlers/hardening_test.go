package handlers

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"testing"

	dimocrypto "github.com/DIMO-Network/did-directory/internal/crypto"
	"github.com/DIMO-Network/did-directory/internal/did"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// signedGenesis builds a signed genesis with the given rotation key and
// #signing method, signed by key.
func signedGenesis(t *testing.T, key *ecdsa.PrivateKey, rotationKey, signingKey string) (*did.Operation, string) {
	t.Helper()
	op := &did.Operation{
		Type:                did.OpTypeCreate,
		RotationKeys:        []string{rotationKey},
		VerificationMethods: map[string]string{"signing": signingKey},
		AlsoKnownAs:         []string{},
		Services:            map[string]did.Service{},
	}
	data, err := json.Marshal(op.ToUnsigned())
	require.NoError(t, err)
	op.Sig, err = dimocrypto.SignOperation(key, data)
	require.NoError(t, err)
	didStr, err := did.DeriveFromGenesis(op)
	require.NoError(t, err)
	return op, didStr
}

// R3-F5: a genesis naming its key in a non-canonical form (hex multibase, or
// a padded multicodec varint) is refused, so a stored key has one string.
func TestSubmit_RefusesNonCanonicalDIDKeys(t *testing.T) {
	f := newFixture(t)
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	pub, err := dimocrypto.FromECDSA(&key.PublicKey)
	require.NoError(t, err)
	hexForm := "did:key:f" + hex.EncodeToString(append([]byte{0x80, 0x24}, pub.Compressed()...))
	paddedForm := "did:key:f" + hex.EncodeToString(append([]byte{0x80, 0xa4, 0x00}, pub.Compressed()...))

	for name, keys := range map[string][2]string{
		"hex rotation key":    {hexForm, pub.DIDKey()},
		"padded rotation key": {paddedForm, pub.DIDKey()},
		"hex signing key":     {pub.DIDKey(), hexForm},
	} {
		t.Run(name, func(t *testing.T) {
			op, didStr := signedGenesis(t, key, keys[0], keys[1])
			raw, err := json.Marshal(op)
			require.NoError(t, err)
			status, body := f.post("/"+didStr, raw)
			assert.Equal(t, http.StatusBadRequest, status, string(body))
			assert.Contains(t, string(body), "invalid")
		})
	}

	// The canonical form of the same key is accepted.
	op, didStr := signedGenesis(t, key, pub.DIDKey(), pub.DIDKey())
	raw, err := json.Marshal(op)
	require.NoError(t, err)
	status, body := f.post("/"+didStr, raw)
	assert.Equal(t, http.StatusOK, status, string(body))
}

// owned is a DID created through the API with the key that controls it.
type owned struct {
	did  string
	head string
	key  *ecdsa.PrivateKey
	dk   string
}

func (f *fixture) ownedDID() *owned {
	f.t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(f.t, err)
	dk, err := dimocrypto.EncodeDIDKey(&key.PublicKey)
	require.NoError(f.t, err)
	op, didStr := signedGenesis(f.t, key, dk, dk)
	raw, err := json.Marshal(op)
	require.NoError(f.t, err)
	status, body := f.post("/"+didStr, raw)
	require.Equal(f.t, http.StatusOK, status, string(body))
	var out map[string]string
	require.NoError(f.t, json.Unmarshal(body, &out))
	return &owned{did: didStr, head: out["cid"], key: key, dk: dk}
}

// submit signs op with the DID's key, chains it to the head and posts it.
func (o *owned) submit(f *fixture, op *did.Operation) (int, []byte) {
	f.t.Helper()
	op.Prev = &o.head
	data, err := json.Marshal(op.ToUnsigned())
	require.NoError(f.t, err)
	op.Sig, err = dimocrypto.SignOperation(o.key, data)
	require.NoError(f.t, err)
	raw, err := json.Marshal(op)
	require.NoError(f.t, err)
	status, body := f.post("/"+o.did, raw)
	if status == http.StatusOK {
		var out map[string]string
		require.NoError(f.t, json.Unmarshal(body, &out))
		o.head = out["cid"]
	}
	return status, body
}

// R3-F4: a signed update whose rotation key is not a did:key is refused, so
// the owner cannot freeze the DID with a typo.
func TestSubmit_UpdateWithBadKeyRefused(t *testing.T) {
	f := newFixture(t)
	o := f.ownedDID()
	before := o.head

	status, body := o.submit(f, &did.Operation{Type: did.OpTypeCreate, RotationKeys: []string{"did:key:zNotAKey"},
		VerificationMethods: map[string]string{"signing": o.dk}, AlsoKnownAs: []string{}, Services: map[string]did.Service{}})
	assert.Equal(t, http.StatusBadRequest, status, string(body))
	assert.Contains(t, string(body), "invalid rotation key")

	status, body = o.submit(f, &did.Operation{Type: did.OpTypeCreate, RotationKeys: []string{o.dk},
		VerificationMethods: map[string]string{"signing": "did:key:zNotAKey"}, AlsoKnownAs: []string{}, Services: map[string]did.Service{}})
	assert.Equal(t, http.StatusBadRequest, status, string(body))
	assert.Contains(t, string(body), "invalid verification method")

	assert.Equal(t, before, o.head)
	status, _ = f.get("/" + o.did)
	assert.Equal(t, http.StatusOK, status)
}

// R3-F4: a head whose verification method does not decode (a row stored
// before updates were checked) is unusable, 422, not deactivated, 410.
func TestResolve_UndecodableHeadIs422(t *testing.T) {
	f := newFixture(t)
	o := f.ownedDID()
	bad := &did.Operation{Type: did.OpTypeCreate, RotationKeys: []string{o.dk},
		VerificationMethods: map[string]string{"signing": "did:key:zNotAKey"}, Prev: &o.head, Sig: "legacy"}
	require.NoError(t, f.st.AppendAfter(context.Background(), o.did, o.head, "bafy-legacy", bad))

	status, body := f.get("/" + o.did)
	assert.Equal(t, http.StatusUnprocessableEntity, status, string(body))
	assert.NotContains(t, string(body), "deactivated")
}

// R3-F4: a tombstoned DID answers 410 on /data as it does on resolve, rather
// than 200 with the tombstone's fields and no sign it is deactivated.
func TestData_TombstoneIs410(t *testing.T) {
	f := newFixture(t)
	o := f.ownedDID()
	status, body := o.submit(f, &did.Operation{Type: did.OpTypeTombstone})
	require.Equal(t, http.StatusOK, status, string(body))

	status, body = f.get("/" + o.did)
	assert.Equal(t, http.StatusGone, status, string(body))
	status, body = f.get("/" + o.did + "/data")
	assert.Equal(t, http.StatusGone, status, string(body))
	assert.Contains(t, string(body), "deactivated")
}
