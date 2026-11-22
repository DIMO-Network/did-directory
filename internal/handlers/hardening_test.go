package handlers

import (
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
