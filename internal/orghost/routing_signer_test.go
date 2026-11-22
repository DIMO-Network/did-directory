package orghost

import (
	"context"
	"testing"

	dimocrypto "github.com/DIMO-Network/did-directory/internal/crypto"
	"github.com/DIMO-Network/did-directory/internal/orghost/store"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestRoutingSigner(t *testing.T) {
	ctx := context.Background()
	st := store.NewMemoryStore()
	sealer, err := NewEphemeralSealer()
	require.NoError(t, err)
	local := NewLocalSigner(st, sealer)

	// An org registered while the host ran ORG_SIGNER=local.
	const oldOrg = "did:dimo:old"
	oldKey, err := local.Register(ctx, oldOrg, nil)
	require.NoError(t, err)

	// The host now runs ORG_SIGNER=kms.
	api := newFakeKMS(t)
	kmsSigner := NewKMSSigner(st, api, "alias/dimo-org/")
	rs := NewRoutingSigner(st, local, kmsSigner, kmsSigner)

	t.Run("a local org keeps signing locally", func(t *testing.T) {
		pub, err := rs.PublicKey(ctx, oldOrg)
		require.NoError(t, err)
		assert.Equal(t, oldKey, pub)
		sig, err := rs.Sign(ctx, oldOrg, []byte("d"))
		require.NoError(t, err)
		require.NoError(t, dimocrypto.VerifyWithDIDKey(oldKey, []byte("d"), sig))
		assert.Zero(t, api.signCalls)
	})

	t.Run("a new org registers with the configured backend and signs through KMS", func(t *testing.T) {
		reg, ok := rs.(Registrar)
		require.True(t, ok)
		const newOrg = "did:dimo:new"
		newKey, err := reg.Register(ctx, newOrg, nil)
		require.NoError(t, err)
		row, err := st.GetOrg(ctx, newOrg)
		require.NoError(t, err)
		assert.NotEmpty(t, row.KeyRef)
		sig, err := rs.Sign(ctx, newOrg, []byte("d"))
		require.NoError(t, err)
		require.NoError(t, dimocrypto.VerifyWithDIDKey(newKey, []byte("d"), sig))
		assert.Equal(t, 1, api.signCalls)
	})

	t.Run("an unknown org is not found", func(t *testing.T) {
		_, err := rs.Sign(ctx, "did:dimo:nobody", []byte("d"))
		assert.True(t, store.IsNotFound(err))
	})
}

func TestRoutingSigner_MissingBackend(t *testing.T) {
	ctx := context.Background()
	st := store.NewMemoryStore()
	sealer, err := NewEphemeralSealer()
	require.NoError(t, err)
	local := NewLocalSigner(st, sealer)
	_, err = local.Register(ctx, "did:dimo:old", nil)
	require.NoError(t, err)

	rs := NewRoutingSigner(st, nil, nil, local)
	_, err = rs.Sign(ctx, "did:dimo:old", []byte("d"))
	assert.ErrorContains(t, err, "local")
}

func TestRepositoryRegisterDispatchesThroughRegistrar(t *testing.T) {
	st := store.NewMemoryStore()
	api := newFakeKMS(t)
	k := NewKMSSigner(st, api, "alias/dimo-org/")
	r := &Repository{Store: st, Signer: k}
	_, err := r.Register(context.Background(), "did:dimo:org1", nil)
	require.NoError(t, err)
	assert.Len(t, api.created, 1)
}
