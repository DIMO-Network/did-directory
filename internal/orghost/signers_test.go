package orghost

import (
	"context"
	"errors"
	"testing"

	dimocrypto "github.com/DIMO-Network/did-directory/internal/crypto"
	"github.com/DIMO-Network/did-directory/internal/orghost/store"
	"github.com/aws/aws-sdk-go-v2/service/kms"
	kmstypes "github.com/aws/aws-sdk-go-v2/service/kms/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// probeKMS fails DescribeKey or GetPublicKey, as bad credentials, a wrong
// region or a missing permission would.
type probeKMS struct {
	*fakeKMS
	describeErr, pubErr error
	describes            []string
}

func (p *probeKMS) DescribeKey(ctx context.Context, in *kms.DescribeKeyInput, o ...func(*kms.Options)) (*kms.DescribeKeyOutput, error) {
	p.describes = append(p.describes, *in.KeyId)
	if p.describeErr != nil {
		return nil, p.describeErr
	}
	return p.fakeKMS.DescribeKey(ctx, in, o...)
}

func (p *probeKMS) GetPublicKey(ctx context.Context, in *kms.GetPublicKeyInput, o ...func(*kms.Options)) (*kms.GetPublicKeyOutput, error) {
	if p.pubErr != nil {
		return nil, p.pubErr
	}
	return p.fakeKMS.GetPublicKey(ctx, in, o...)
}

// kmsOrg registers org under api, as a host running ORG_SIGNER=kms would
// have, and returns the store holding it.
func kmsOrg(t *testing.T, api KMSAPI, org string) store.Store {
	t.Helper()
	st := store.NewMemoryStore()
	_, err := NewKMSSigner(st, api, "alias/dimo-org/").Register(t.Context(), org, nil)
	require.NoError(t, err)
	return st
}

func newKMSFunc(api KMSAPI, calls *int) func(context.Context) (KMSAPI, error) {
	return func(context.Context) (KMSAPI, error) {
		*calls++
		return api, nil
	}
}

// R4-F5: rolling ORG_SIGNER back to local must not strand the orgs whose keys
// are in KMS. The KMS signer is built whenever the store holds such an org;
// only new orgs register locally.
func TestBuildSigners_LocalKeepsKMSForKMSOrgs(t *testing.T) {
	api := newFakeKMS(t)
	st := kmsOrg(t, api, "did:dimo:kmsorg")
	sealer, err := NewEphemeralSealer()
	require.NoError(t, err)
	calls := 0
	signers, err := BuildSigners(t.Context(), st, sealer, SignerConfig{Signer: "local", AliasPrefix: "alias/dimo-org/"}, newKMSFunc(api, &calls))
	require.NoError(t, err)
	require.NotNil(t, signers.KMS, "the KMS orgs still need it")
	assert.Equal(t, 1, calls)

	sig, err := signers.Signer.Sign(t.Context(), "did:dimo:kmsorg", []byte("commit"))
	require.NoError(t, err)
	want, err := dimocrypto.EncodeDIDKey(&api.key.PublicKey)
	require.NoError(t, err)
	require.NoError(t, dimocrypto.VerifyWithDIDKey(want, []byte("commit"), sig))

	created := len(api.created)
	_, err = signers.Signer.(Registrar).Register(t.Context(), "did:dimo:neworg", nil)
	require.NoError(t, err)
	row, err := st.GetOrg(t.Context(), "did:dimo:neworg")
	require.NoError(t, err)
	assert.NotEmpty(t, row.KeyEnc, "new orgs register with the local signer")
	assert.Len(t, api.created, created)
}

func TestBuildSigners_LocalWithoutKMSOrgsMakesNoClient(t *testing.T) {
	sealer, err := NewEphemeralSealer()
	require.NoError(t, err)
	calls := 0
	signers, err := BuildSigners(t.Context(), store.NewMemoryStore(), sealer, SignerConfig{Signer: "local"}, newKMSFunc(newFakeKMS(t), &calls))
	require.NoError(t, err)
	assert.Nil(t, signers.KMS)
	assert.Zero(t, calls)
}

// R4-F5: a broken KMS setup (credentials, region, permissions) fails at
// startup, not as a 500 on every register and every KMS org's write.
func TestBuildSigners_ProbesKMSAtStartup(t *testing.T) {
	ctx := context.Background()
	sealer, err := NewEphemeralSealer()
	require.NoError(t, err)

	t.Run("an org's key must answer", func(t *testing.T) {
		base := newFakeKMS(t)
		st := kmsOrg(t, base, "did:dimo:kmsorg")
		api := &probeKMS{fakeKMS: base, pubErr: errors.New("AccessDeniedException: not authorized to perform kms:GetPublicKey")}
		calls := 0
		_, err := BuildSigners(ctx, st, sealer, SignerConfig{Signer: "kms", AliasPrefix: "alias/dimo-org/"}, newKMSFunc(api, &calls))
		require.Error(t, err)
		assert.Contains(t, err.Error(), "KMS probe")
		_, err = BuildSigners(ctx, st, sealer, SignerConfig{Signer: "local", AliasPrefix: "alias/dimo-org/"}, newKMSFunc(api, &calls))
		require.Error(t, err, "under ORG_SIGNER=local too: the KMS orgs still sign through it")
	})
	t.Run("no orgs yet: KMS must be reachable with these credentials", func(t *testing.T) {
		api := &probeKMS{fakeKMS: newFakeKMS(t), describeErr: errors.New("UnrecognizedClientException: The security token included in the request is invalid")}
		calls := 0
		_, err := BuildSigners(ctx, store.NewMemoryStore(), nil, SignerConfig{Signer: "kms", AliasPrefix: "alias/dimo-org/"}, newKMSFunc(api, &calls))
		require.Error(t, err)
		assert.Contains(t, err.Error(), "KMS probe")
	})
	t.Run("no orgs yet: a missing probe alias is a working KMS", func(t *testing.T) {
		api := &probeKMS{fakeKMS: newFakeKMS(t)}
		calls := 0
		signers, err := BuildSigners(ctx, store.NewMemoryStore(), nil, SignerConfig{Signer: "kms", AliasPrefix: "alias/dimo-org/"}, newKMSFunc(api, &calls))
		require.NoError(t, err)
		require.NotNil(t, signers.KMS)
		assert.NotEmpty(t, api.describes, "the probe reached KMS")
		var nf *kmstypes.NotFoundException
		assert.False(t, errors.As(err, &nf))
	})
	t.Run("the client cannot be built", func(t *testing.T) {
		st := kmsOrg(t, newFakeKMS(t), "did:dimo:kmsorg")
		_, err := BuildSigners(ctx, st, sealer, SignerConfig{Signer: "local", AliasPrefix: "alias/dimo-org/"},
			func(context.Context) (KMSAPI, error) { return nil, errors.New("no region") })
		require.Error(t, err)
	})
}
