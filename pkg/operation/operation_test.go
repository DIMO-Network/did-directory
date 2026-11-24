package operation_test

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/DIMO-Network/did-directory/pkg/didkey"
	"github.com/DIMO-Network/did-directory/pkg/operation"
)

func TestSign_GenesisDerivesADIDAndVerifies(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	didKey, err := didkey.Encode(&key.PublicKey)
	require.NoError(t, err)

	u := &operation.Unsigned{
		Type:                operation.TypeCreate,
		RotationKeys:        []string{didKey},
		VerificationMethods: map[string]string{"signing": didKey},
		Services:            map[string]operation.Service{},
	}
	op, err := operation.Sign(key, u)
	require.NoError(t, err)

	id, err := operation.DID(op)
	require.NoError(t, err)
	assert.True(t, operation.ValidDID(id), id)

	cid, err := operation.CID(op)
	require.NoError(t, err)
	assert.NotEmpty(t, cid)

	data, err := json.Marshal(op.ToUnsigned())
	require.NoError(t, err)
	pub, err := didkey.Decode(didKey)
	require.NoError(t, err)
	assert.NoError(t, pub.Verify(data, op.Sig), "the rotation key's signature covers the unsigned operation")
}
