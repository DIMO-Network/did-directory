package main

import (
	"bytes"
	"context"
	"encoding/json"
	"testing"
	"time"

	"github.com/DIMO-Network/did-directory/internal/did"
	"github.com/DIMO-Network/did-directory/pkg/didkey"
	"github.com/DIMO-Network/did-directory/pkg/dpop"
	"github.com/multiformats/go-multicodec"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// R7-F4: every operation dimocli signs carries alsoKnownAs as an array, never
// null, which the SDK's verified reads refuse.
func TestSignOp_AlsoKnownAsIsNeverNull(t *testing.T) {
	sg, err := newFileSignerNew()
	require.NoError(t, err)
	op, err := signOpWith(context.Background(), sg, &did.UnsignedOperation{
		Type: did.OpTypeCreate, RotationKeys: []string{sg.DIDKey()},
		VerificationMethods: map[string]string{"signing": sg.DIDKey()}, Services: map[string]did.Service{},
	})
	require.NoError(t, err)
	raw, err := json.Marshal(op)
	require.NoError(t, err)
	assert.Contains(t, string(raw), `"alsoKnownAs":[]`)
	assert.NotContains(t, string(raw), `"alsoKnownAs":null`)
	verifyOp(t, sg.DIDKey(), op)

	// A create with no --alias, through the directory.
	t.Setenv("HOME", t.TempDir())
	c, ops := directoryStub(t)
	_, err = executeCreate(context.Background(), c, createOptions{}, sg, &bytes.Buffer{})
	require.NoError(t, err)
	require.Len(t, *ops, 1)
	assert.NotNil(t, (*ops)[0].AlsoKnownAs, "submitted as [] and decoded as an empty slice, not null")
}

// R7-F4: an org created with a local key gets a secp256k1 root, the type of a
// Turnkey org root, so the SDK can extend it; and every later command that
// signs with it (update, rotate, signin, pubkey) works with that key.
func TestCreateOrg_LocalRootIsSecp256k1(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	sg, err := localRootFor(createOptions{Org: true})
	require.NoError(t, err)
	pub, err := didkey.Decode(sg.DIDKey())
	require.NoError(t, err)
	assert.Equal(t, multicodec.Secp256k1Pub, pub.Codec(), "an org root is secp256k1")

	person, err := localRootFor(createOptions{})
	require.NoError(t, err)
	pp, err := didkey.Decode(person.DIDKey())
	require.NoError(t, err)
	assert.Equal(t, multicodec.P256Pub, pp.Codec(), "a person's root stays P-256")
	car, err := localRootFor(createOptions{Controller: "did:dimo:fleet"})
	require.NoError(t, err)
	cp, err := didkey.Decode(car.DIDKey())
	require.NoError(t, err)
	assert.Equal(t, multicodec.P256Pub, cp.Codec())

	c, ops := directoryStub(t)
	derived, err := executeCreate(context.Background(), c, createOptions{Org: true}, sg, &bytes.Buffer{})
	require.NoError(t, err)
	op := (*ops)[0]
	assert.Equal(t, []string{sg.DIDKey()}, op.RotationKeys)
	assert.Equal(t, sg.DIDKey(), op.VerificationMethods["signing"])
	verifyOp(t, sg.DIDKey(), op)
	require.NoError(t, did.ValidateCreate(op))

	// The keystore keeps it, and the commands that sign with it load it back.
	loaded, err := resolveSigner(context.Background(), &turnkeyFlags{}, derived, op, purposeUpdate)
	require.NoError(t, err)
	assert.Equal(t, sg.DIDKey(), loaded.DIDKey())
	update, err := buildUpdate(op, "bafyfake", updateOptions{OrgHost: "https://orghost.test"})
	require.NoError(t, err)
	signed, err := signOpWith(context.Background(), loaded, update.Op)
	require.NoError(t, err)
	verifyOp(t, sg.DIDKey(), signed)
	k, err := pubkeyOf(derived, false)
	require.NoError(t, err)
	assert.Equal(t, sg.DIDKey(), k)

	// Rotating keeps the curve, so the org stays extensible.
	next, _, err := newCustodyLike(context.Background(), &turnkeyFlags{}, sg.DIDKey())
	require.NoError(t, err)
	np, err := didkey.Decode(next)
	require.NoError(t, err)
	assert.Equal(t, multicodec.Secp256k1Pub, np.Codec())
}

// A secp256k1 root cannot make DPoP proofs (ES256 is P-256), so signin binds
// the token to a fresh P-256 key kept beside it, as for a Turnkey root.
func TestSignin_LocalSecp256k1Root(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	sg, err := newFileSignerK1()
	require.NoError(t, err)
	require.NoError(t, saveSigner(orgDID, sg))
	pub, err := didkey.Decode(sg.DIDKey())
	require.NoError(t, err)
	dauth := fakeDauth(t, pub)

	token, _, err := executeSignin(context.Background(), dauth, orgDID, "signing", nil, "read", &turnkeyFlags{}, nil)
	require.NoError(t, err)
	proof, err := makeDPoPProof(orgDID, token, "GET", "https://org.test/x", time.Now())
	require.NoError(t, err)
	_, err = dpop.NewVerifier().Verify(proof, "GET", "https://org.test/x", token)
	require.NoError(t, err)
	_, err = LoadDPoPKey(orgDID)
	assert.NoError(t, err, "the DPoP key is kept for dimocli dpop")

	// A second sign-in (another scope) binds to the same key, so the first
	// token still takes proofs from dimocli dpop.
	second, _, err := executeSignin(context.Background(), dauth, orgDID, "signing", nil, "read write", &turnkeyFlags{}, nil)
	require.NoError(t, err)
	for _, tok := range []string{token, second} {
		proof, err := makeDPoPProof(orgDID, tok, "GET", "https://org.test/x", time.Now())
		require.NoError(t, err)
		_, err = dpop.NewVerifier().Verify(proof, "GET", "https://org.test/x", tok)
		require.NoError(t, err)
		claims, err := jwtClaims(tok)
		require.NoError(t, err)
		var c struct{ Cnf struct{ Jkt string } }
		require.NoError(t, json.Unmarshal(claims, &c))
		k, err := LoadDPoPKey(orgDID)
		require.NoError(t, err)
		jwk, err := publicJWK(&k.PublicKey)
		require.NoError(t, err)
		assert.Equal(t, c.Cnf.Jkt, jwkThumbprint(jwk), "every token is bound to the stored key")
	}
}
