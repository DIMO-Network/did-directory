package orghost

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/asn1"
	"encoding/base64"
	"encoding/hex"
	"math/big"
	"sync"
	"testing"

	dimocrypto "github.com/DIMO-Network/did-directory/internal/crypto"
	"github.com/DIMO-Network/did-directory/internal/orghost/store"
	"github.com/aws/aws-sdk-go-v2/service/kms"
	kmstypes "github.com/aws/aws-sdk-go-v2/service/kms/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const fakeKeyARN = "arn:aws:kms:us-east-1:111122223333:key/11111111-2222-3333-4444-555555555555"

// fakeKMS is a kmsAPI backed by one real P-256 key, so signatures it returns
// verify against the public key it hands out.
type fakeKMS struct {
	mu  sync.Mutex
	key *ecdsa.PrivateKey

	created   []*kms.CreateKeyInput
	aliases   []*kms.CreateAliasInput
	signed    []*kms.SignInput
	pubCalls  int
	shortR    bool // sign until r fits in 31 bytes
	highS     bool // return s as n-s when it is the low one
	signCalls int
}

func newFakeKMS(t *testing.T) *fakeKMS {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	return &fakeKMS{key: key}
}

func (f *fakeKMS) CreateKey(_ context.Context, in *kms.CreateKeyInput, _ ...func(*kms.Options)) (*kms.CreateKeyOutput, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.created = append(f.created, in)
	return &kms.CreateKeyOutput{KeyMetadata: &kmstypes.KeyMetadata{Arn: ptr(fakeKeyARN), KeyId: ptr("11111111-2222-3333-4444-555555555555")}}, nil
}

func (f *fakeKMS) CreateAlias(_ context.Context, in *kms.CreateAliasInput, _ ...func(*kms.Options)) (*kms.CreateAliasOutput, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.aliases = append(f.aliases, in)
	return &kms.CreateAliasOutput{}, nil
}

func (f *fakeKMS) Sign(_ context.Context, in *kms.SignInput, _ ...func(*kms.Options)) (*kms.SignOutput, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.signed = append(f.signed, in)
	f.signCalls++
	for {
		r, s, err := ecdsa.Sign(rand.Reader, f.key, in.Message)
		if err != nil {
			return nil, err
		}
		if f.shortR && r.BitLen() > 248 {
			continue
		}
		if f.highS {
			half := new(big.Int).Rsh(f.key.Curve.Params().N, 1)
			if s.Cmp(half) <= 0 {
				s = new(big.Int).Sub(f.key.Curve.Params().N, s)
			}
		}
		der, err := asn1.Marshal(struct{ R, S *big.Int }{r, s})
		if err != nil {
			return nil, err
		}
		return &kms.SignOutput{Signature: der}, nil
	}
}

func (f *fakeKMS) GetPublicKey(_ context.Context, _ *kms.GetPublicKeyInput, _ ...func(*kms.Options)) (*kms.GetPublicKeyOutput, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.pubCalls++
	der, err := x509.MarshalPKIXPublicKey(&f.key.PublicKey)
	if err != nil {
		return nil, err
	}
	return &kms.GetPublicKeyOutput{PublicKey: der}, nil
}

func TestKMSSigner_RegisterCreatesKey(t *testing.T) {
	ctx := context.Background()
	st := store.NewMemoryStore()
	api := newFakeKMS(t)
	s := NewKMSSigner(st, api, "alias/dimo-org/")
	const org = "did:dimo:org1"

	didKey, err := s.Register(ctx, org, nil)
	require.NoError(t, err)
	want, err := dimocrypto.EncodeDIDKey(&api.key.PublicKey)
	require.NoError(t, err)
	assert.Equal(t, want, didKey)

	require.Len(t, api.created, 1)
	in := api.created[0]
	assert.Equal(t, kmstypes.KeySpecEccNistP256, in.KeySpec)
	assert.Equal(t, kmstypes.KeyUsageTypeSignVerify, in.KeyUsage)
	require.Len(t, in.Tags, 1)
	assert.Equal(t, "org", *in.Tags[0].TagKey)
	assert.Equal(t, org, *in.Tags[0].TagValue)

	sum := sha256.Sum256([]byte(org))
	require.Len(t, api.aliases, 1)
	assert.Equal(t, "alias/dimo-org/"+hex.EncodeToString(sum[:])[:16], *api.aliases[0].AliasName)
	assert.Equal(t, fakeKeyARN, *api.aliases[0].TargetKeyId)

	row, err := st.GetOrg(ctx, org)
	require.NoError(t, err)
	assert.Equal(t, fakeKeyARN, row.KeyRef)
	assert.Empty(t, row.KeyEnc)

	_, err = s.Register(ctx, org, nil)
	assert.ErrorIs(t, err, store.ErrOrgExists)
	assert.Len(t, api.created, 1, "a second register must not mint another key")
}

func TestKMSSigner_RegisterRefusesProvidedKey(t *testing.T) {
	st := store.NewMemoryStore()
	api := newFakeKMS(t)
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	_, err = NewKMSSigner(st, api, "alias/dimo-org/").Register(context.Background(), "did:dimo:org1", key)
	assert.ErrorIs(t, err, ErrPrivateKeyNotAccepted)
	assert.Empty(t, api.created)
}

func TestKMSSigner_SignVerifies(t *testing.T) {
	ctx := context.Background()
	st := store.NewMemoryStore()
	api := newFakeKMS(t)
	api.shortR = true
	s := NewKMSSigner(st, api, "alias/dimo-org/")
	const org = "did:dimo:org1"
	didKey, err := s.Register(ctx, org, nil)
	require.NoError(t, err)

	data := []byte("commit bytes")
	sig, err := s.Sign(ctx, org, data)
	require.NoError(t, err)
	raw, err := base64.RawURLEncoding.DecodeString(sig)
	require.NoError(t, err)
	assert.Len(t, raw, 64, "an r that DER encodes in 31 bytes must still pad to 32")
	require.NoError(t, dimocrypto.VerifyWithDIDKey(didKey, data, sig))
	assert.Error(t, dimocrypto.VerifyWithDIDKey(didKey, []byte("other"), sig))

	// Same encoding as SignOperation: both are 64-byte unpadded base64url.
	local, err := dimocrypto.SignOperation(api.key, data)
	require.NoError(t, err)
	assert.Len(t, sig, len(local))
}

func TestKMSSigner_SignSendsDigest(t *testing.T) {
	ctx := context.Background()
	st := store.NewMemoryStore()
	api := newFakeKMS(t)
	s := NewKMSSigner(st, api, "alias/dimo-org/")
	_, err := s.Register(ctx, "did:dimo:org1", nil)
	require.NoError(t, err)

	data := []byte("commit bytes")
	_, err = s.Sign(ctx, "did:dimo:org1", data)
	require.NoError(t, err)
	require.Len(t, api.signed, 1)
	in := api.signed[0]
	sum := sha256.Sum256(data)
	assert.Equal(t, kmstypes.MessageTypeDigest, in.MessageType)
	assert.Equal(t, kmstypes.SigningAlgorithmSpecEcdsaSha256, in.SigningAlgorithm)
	assert.Equal(t, sum[:], in.Message)
	assert.Equal(t, fakeKeyARN, *in.KeyId)
}

// did-directory's verifier is a plain ecdsa.Verify, so a high-S signature is
// valid and the signer does not normalise s.
func TestKMSSigner_HighSStillVerifies(t *testing.T) {
	ctx := context.Background()
	st := store.NewMemoryStore()
	api := newFakeKMS(t)
	api.highS = true
	s := NewKMSSigner(st, api, "alias/dimo-org/")
	didKey, err := s.Register(ctx, "did:dimo:org1", nil)
	require.NoError(t, err)
	sig, err := s.Sign(ctx, "did:dimo:org1", []byte("x"))
	require.NoError(t, err)
	require.NoError(t, dimocrypto.VerifyWithDIDKey(didKey, []byte("x"), sig))
}

func TestKMSSigner_PublicKeyCached(t *testing.T) {
	ctx := context.Background()
	st := store.NewMemoryStore()
	api := newFakeKMS(t)
	s := NewKMSSigner(st, api, "alias/dimo-org/")
	_, err := s.Register(ctx, "did:dimo:org1", nil)
	require.NoError(t, err)

	// A fresh signer has an empty cache and must hit KMS once, then not again.
	api.pubCalls = 0
	fresh := NewKMSSigner(st, api, "alias/dimo-org/")
	a, err := fresh.PublicKey(ctx, "did:dimo:org1")
	require.NoError(t, err)
	b, err := fresh.PublicKey(ctx, "did:dimo:org1")
	require.NoError(t, err)
	assert.Equal(t, a, b)
	assert.Equal(t, 1, api.pubCalls)
}

func TestKMSSigner_UnknownOrg(t *testing.T) {
	s := NewKMSSigner(store.NewMemoryStore(), newFakeKMS(t), "alias/dimo-org/")
	_, err := s.Sign(context.Background(), "did:dimo:nobody", []byte("x"))
	assert.True(t, store.IsNotFound(err))
}

func TestRegisterHandler_KMSRefusesPrivateKey(t *testing.T) {
	st := store.NewMemoryStore()
	h := newHost(t, st)
	api := newFakeKMS(t)
	h.repo.Signer = NewKMSSigner(st, api, "alias/dimo-org/")
	org := newOrgDID()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	der, err := x509.MarshalPKCS8PrivateKey(key)
	require.NoError(t, err)
	status, body := h.do("POST", "/orgs/"+org, org, map[string]string{"privateKey": base64.StdEncoding.EncodeToString(der)})
	assert.Equal(t, 400, status, body)
	assert.Equal(t, "privateKey is not accepted with the KMS signer", body["error"])
	assert.Empty(t, api.created)

	status, body = h.do("POST", "/orgs/"+org, org, nil)
	require.Equal(t, 201, status, body)
	assert.NotEmpty(t, body["key"])
}
