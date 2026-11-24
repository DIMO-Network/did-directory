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
	"errors"
	"fmt"
	"math/big"
	"sync"
	"testing"
	"time"

	dimocrypto "github.com/DIMO-Network/did-directory/internal/crypto"
	"github.com/DIMO-Network/did-directory/internal/orghost/store"
	"github.com/aws/aws-sdk-go-v2/service/kms"
	kmstypes "github.com/aws/aws-sdk-go-v2/service/kms/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const fakeKeyARN = "arn:aws:kms:us-east-1:111122223333:key/11111111-2222-3333-4444-555555555555"

// fakeKMS is a KMSAPI backed by one real P-256 key, so signatures it returns
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

	tags      map[string][]kmstypes.Tag // key ARN -> tags
	aliasTo   map[string]string         // alias -> key ARN
	deleted   []*kms.ScheduleKeyDeletionInput
	raceAlias bool // the next CreateAlias loses to a concurrent register
	raceOrg   string
	lostReply bool // the next CreateAlias succeeds but answers AlreadyExists, as a retried call does
	state     map[string]kmstypes.KeyState
	// spec and usage override what DescribeKey reports for a key; algs
	// overrides the signing algorithms GetPublicKey reports.
	spec  map[string]kmstypes.KeySpec
	usage map[string]kmstypes.KeyUsageType
	algs  []kmstypes.SigningAlgorithmSpec
}

func newFakeKMS(t *testing.T) *fakeKMS {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	return &fakeKMS{key: key, state: map[string]kmstypes.KeyState{}, tags: map[string][]kmstypes.Tag{}, aliasTo: map[string]string{},
		spec: map[string]kmstypes.KeySpec{}, usage: map[string]kmstypes.KeyUsageType{}}
}

func (f *fakeKMS) CreateKey(_ context.Context, in *kms.CreateKeyInput, _ ...func(*kms.Options)) (*kms.CreateKeyOutput, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.created = append(f.created, in)
	arn := f.newKeyLocked(in.Tags)
	return &kms.CreateKeyOutput{KeyMetadata: &kmstypes.KeyMetadata{Arn: &arn}}, nil
}

func (f *fakeKMS) newKeyLocked(tags []kmstypes.Tag) string {
	arn := fakeKeyARN
	if n := len(f.tags); n > 0 {
		arn = fmt.Sprintf("%s-%d", fakeKeyARN, n)
	}
	f.tags[arn] = tags
	return arn
}

func (f *fakeKMS) DescribeKey(_ context.Context, in *kms.DescribeKeyInput, _ ...func(*kms.Options)) (*kms.DescribeKeyOutput, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	arn, ok := f.aliasTo[*in.KeyId]
	if !ok {
		return nil, &kmstypes.NotFoundException{}
	}
	st, ok := f.state[arn]
	if !ok {
		st = kmstypes.KeyStateEnabled
	}
	spec, ok := f.spec[arn]
	if !ok {
		spec = kmstypes.KeySpecEccNistP256
	}
	usage, ok := f.usage[arn]
	if !ok {
		usage = kmstypes.KeyUsageTypeSignVerify
	}
	return &kms.DescribeKeyOutput{KeyMetadata: &kmstypes.KeyMetadata{Arn: &arn, KeyState: st, KeySpec: spec, KeyUsage: usage}}, nil
}

func (f *fakeKMS) ListResourceTags(_ context.Context, in *kms.ListResourceTagsInput, _ ...func(*kms.Options)) (*kms.ListResourceTagsOutput, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return &kms.ListResourceTagsOutput{Tags: f.tags[*in.KeyId]}, nil
}

func (f *fakeKMS) ScheduleKeyDeletion(_ context.Context, in *kms.ScheduleKeyDeletionInput, _ ...func(*kms.Options)) (*kms.ScheduleKeyDeletionOutput, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.deleted = append(f.deleted, in)
	return &kms.ScheduleKeyDeletionOutput{}, nil
}

func (f *fakeKMS) CreateAlias(_ context.Context, in *kms.CreateAliasInput, _ ...func(*kms.Options)) (*kms.CreateAliasOutput, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.lostReply {
		f.lostReply = false
		f.aliasTo[*in.AliasName] = *in.TargetKeyId
		return nil, &kmstypes.AlreadyExistsException{}
	}
	if f.raceAlias {
		f.raceAlias = false
		winner := f.newKeyLocked([]kmstypes.Tag{{TagKey: ptr("org"), TagValue: ptr(f.raceOrg)}})
		f.aliasTo[*in.AliasName] = winner
		return nil, &kmstypes.AlreadyExistsException{}
	}
	f.aliases = append(f.aliases, in)
	f.aliasTo[*in.AliasName] = *in.TargetKeyId
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
	algs := f.algs
	if algs == nil {
		algs = []kmstypes.SigningAlgorithmSpec{kmstypes.SigningAlgorithmSpecEcdsaSha256}
	}
	return &kms.GetPublicKeyOutput{PublicKey: der, SigningAlgorithms: algs,
		KeySpec: kmstypes.KeySpecEccNistP256, KeyUsage: kmstypes.KeyUsageTypeSignVerify}, nil
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
	assert.Equal(t, "alias/dimo-org/"+hex.EncodeToString(sum[:]), *api.aliases[0].AliasName, "all 256 bits of the DID's hash, not 64")
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
	h.publish(org)
	status, body := h.do("POST", "/orgs/"+org, org, map[string]string{"privateKey": base64.StdEncoding.EncodeToString(der)})
	assert.Equal(t, 400, status, body)
	assert.Equal(t, "privateKey is not accepted with the KMS signer", body["error"])
	assert.Empty(t, api.created)

	status, body = h.do("POST", "/orgs/"+org, org, nil)
	require.Equal(t, 201, status, body)
	assert.NotEmpty(t, body["key"])
}

// failingCreateStore fails CreateOrg once, as a database blip would.
type failingCreateStore struct {
	store.Store
	failed bool
}

func (f *failingCreateStore) CreateOrg(ctx context.Context, o store.Org) error {
	if !f.failed {
		f.failed = true
		return errors.New("db down")
	}
	return f.Store.CreateOrg(ctx, o)
}

func TestKMSSigner_RegisterRetryReusesKey(t *testing.T) {
	ctx := context.Background()
	base := store.NewMemoryStore()
	st := &failingCreateStore{Store: base}
	api := newFakeKMS(t)
	s := NewKMSSigner(st, api, "alias/dimo-org/")

	_, err := s.Register(ctx, "did:dimo:org1", nil)
	require.Error(t, err)
	didKey, err := s.Register(ctx, "did:dimo:org1", nil)
	require.NoError(t, err)
	want, _ := dimocrypto.EncodeDIDKey(&api.key.PublicKey)
	assert.Equal(t, want, didKey)
	assert.Len(t, api.created, 1, "the retry must reuse the key the first attempt made")
	assert.Empty(t, api.deleted)
	row, err := base.GetOrg(ctx, "did:dimo:org1")
	require.NoError(t, err)
	assert.Equal(t, fakeKeyARN, row.KeyRef)
}

func TestKMSSigner_RegisterConcurrentLoserSchedulesDeletion(t *testing.T) {
	ctx := context.Background()
	st := store.NewMemoryStore()
	api := newFakeKMS(t)
	api.raceAlias, api.raceOrg = true, "did:dimo:org1"
	s := NewKMSSigner(st, api, "alias/dimo-org/")

	didKey, err := s.Register(ctx, "did:dimo:org1", nil)
	require.NoError(t, err)
	want, _ := dimocrypto.EncodeDIDKey(&api.key.PublicKey)
	assert.Equal(t, want, didKey)

	require.Len(t, api.created, 1)
	require.Len(t, api.deleted, 1)
	assert.Equal(t, fakeKeyARN, *api.deleted[0].KeyId, "the loser's own key is scheduled for deletion")
	assert.EqualValues(t, 7, *api.deleted[0].PendingWindowInDays)
	row, err := st.GetOrg(ctx, "did:dimo:org1")
	require.NoError(t, err)
	assert.Equal(t, fakeKeyARN+"-1", row.KeyRef, "the winner's key is the one recorded")
}

func TestKMSSigner_RegisterConcurrentStoreWinnerSameKey(t *testing.T) {
	ctx := context.Background()
	st := store.NewMemoryStore()
	api := newFakeKMS(t)
	s := NewKMSSigner(st, api, "alias/dimo-org/")
	// The winner already wrote its row for the key the alias names.
	arn := api.newKeyLocked([]kmstypes.Tag{{TagKey: ptr("org"), TagValue: ptr("did:dimo:org1")}})
	api.aliasTo[s.alias("did:dimo:org1")] = arn
	require.NoError(t, st.CreateOrg(ctx, store.Org{DID: "did:dimo:org1", KeyRef: arn}))
	// A register that passed its row check before the winner's insert lands here.
	got, err := s.finish(ctx, "did:dimo:org1", arn)
	require.NoError(t, err)
	assert.NotEmpty(t, got)
	_, err = s.finish(ctx, "did:dimo:org1", "arn:other")
	assert.ErrorIs(t, err, store.ErrOrgExists)
}

func TestKMSSigner_RegisterRefusesAliasTaggedForAnotherOrg(t *testing.T) {
	ctx := context.Background()
	for name, tags := range map[string][]kmstypes.Tag{
		"another org": {{TagKey: ptr("org"), TagValue: ptr("did:dimo:other")}},
		"no tag":      nil,
	} {
		t.Run(name, func(t *testing.T) {
			st := store.NewMemoryStore()
			api := newFakeKMS(t)
			s := NewKMSSigner(st, api, "alias/dimo-org/")
			arn := api.newKeyLocked(tags)
			api.aliasTo[s.alias("did:dimo:org1")] = arn

			_, err := s.Register(ctx, "did:dimo:org1", nil)
			require.Error(t, err)
			assert.Empty(t, api.created)
			_, err = st.GetOrg(ctx, "did:dimo:org1")
			assert.True(t, store.IsNotFound(err))
		})
	}
}

// A retried CreateAlias whose first attempt landed answers AlreadyExists for an
// alias that already names our own key. Deleting that key would destroy the
// org's live key.
func TestKMSSigner_RegisterAliasAlreadyOursKeepsKey(t *testing.T) {
	ctx := context.Background()
	st := store.NewMemoryStore()
	api := newFakeKMS(t)
	api.lostReply = true
	s := NewKMSSigner(st, api, "alias/dimo-org/")

	_, err := s.Register(ctx, "did:dimo:org1", nil)
	require.NoError(t, err)
	assert.Empty(t, api.deleted, "the key behind the alias must never be scheduled for deletion")
	row, err := st.GetOrg(ctx, "did:dimo:org1")
	require.NoError(t, err)
	assert.Equal(t, fakeKeyARN, row.KeyRef)
}

func TestKMSSigner_RegisterRefusesKeyThatIsNotEnabled(t *testing.T) {
	ctx := context.Background()
	st := store.NewMemoryStore()
	api := newFakeKMS(t)
	s := NewKMSSigner(st, api, "alias/dimo-org/")
	arn := api.newKeyLocked([]kmstypes.Tag{{TagKey: ptr("org"), TagValue: ptr("did:dimo:org1")}})
	api.aliasTo[s.alias("did:dimo:org1")] = arn
	api.state[arn] = kmstypes.KeyStateDisabled

	_, err := s.Register(ctx, "did:dimo:org1", nil)
	assert.EqualError(t, err, "KMS key for did:dimo:org1 is Disabled; an operator must re-enable it")
	assert.Empty(t, api.created)
}

// R4-F12: a key found through the alias must be one this host could have
// made: a P-256 signing key. A P-256 KEY_AGREEMENT key, or an RSA one, would
// register and then fail every Sign.
func TestKMSSigner_RegisterRefusesAliasedKeyOfAnotherKind(t *testing.T) {
	ctx := context.Background()
	for name, set := range map[string]func(f *fakeKMS, arn string){
		"key agreement": func(f *fakeKMS, arn string) { f.usage[arn] = kmstypes.KeyUsageTypeKeyAgreement },
		"rsa":           func(f *fakeKMS, arn string) { f.spec[arn] = kmstypes.KeySpecRsa2048 },
		"secp256k1":     func(f *fakeKMS, arn string) { f.spec[arn] = kmstypes.KeySpecEccSecgP256k1 },
	} {
		t.Run(name, func(t *testing.T) {
			st := store.NewMemoryStore()
			api := newFakeKMS(t)
			s := NewKMSSigner(st, api, "alias/dimo-org/")
			arn := api.newKeyLocked([]kmstypes.Tag{{TagKey: ptr("org"), TagValue: ptr("did:dimo:org1")}})
			api.aliasTo[s.alias("did:dimo:org1")] = arn
			set(api, arn)

			_, err := s.Register(ctx, "did:dimo:org1", nil)
			require.Error(t, err)
			assert.Contains(t, err.Error(), "not a P-256 signing key")
			assert.Empty(t, api.created)
			_, err = st.GetOrg(ctx, "did:dimo:org1")
			assert.True(t, store.IsNotFound(err))
		})
	}
}

func TestKMSSigner_PublicKeyNeedsECDSASHA256(t *testing.T) {
	st := store.NewMemoryStore()
	api := newFakeKMS(t)
	api.algs = []kmstypes.SigningAlgorithmSpec{kmstypes.SigningAlgorithmSpecEcdsaSha384}
	_, err := NewKMSSigner(st, api, "alias/dimo-org/").Register(context.Background(), "did:dimo:org1", nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "ECDSA_SHA_256")
	_, err = st.GetOrg(context.Background(), "did:dimo:org1")
	assert.True(t, store.IsNotFound(err), "no row for a key that cannot sign commits")
}

// deadlineKMS records the deadline each call's context carries, and blocks
// Sign until its context ends when stall is set.
type deadlineKMS struct {
	*fakeKMS
	mu        sync.Mutex
	deadlines map[string][]time.Duration // call -> time left when it arrived
	stall     bool
}

func (d *deadlineKMS) note(ctx context.Context, call string) {
	d.mu.Lock()
	defer d.mu.Unlock()
	left := time.Duration(-1)
	if dl, ok := ctx.Deadline(); ok {
		left = time.Until(dl)
	}
	d.deadlines[call] = append(d.deadlines[call], left)
}

func (d *deadlineKMS) CreateKey(ctx context.Context, in *kms.CreateKeyInput, o ...func(*kms.Options)) (*kms.CreateKeyOutput, error) {
	d.note(ctx, "CreateKey")
	return d.fakeKMS.CreateKey(ctx, in, o...)
}

func (d *deadlineKMS) CreateAlias(ctx context.Context, in *kms.CreateAliasInput, o ...func(*kms.Options)) (*kms.CreateAliasOutput, error) {
	d.note(ctx, "CreateAlias")
	return d.fakeKMS.CreateAlias(ctx, in, o...)
}

func (d *deadlineKMS) DescribeKey(ctx context.Context, in *kms.DescribeKeyInput, o ...func(*kms.Options)) (*kms.DescribeKeyOutput, error) {
	d.note(ctx, "DescribeKey")
	return d.fakeKMS.DescribeKey(ctx, in, o...)
}

func (d *deadlineKMS) ListResourceTags(ctx context.Context, in *kms.ListResourceTagsInput, o ...func(*kms.Options)) (*kms.ListResourceTagsOutput, error) {
	d.note(ctx, "ListResourceTags")
	return d.fakeKMS.ListResourceTags(ctx, in, o...)
}

func (d *deadlineKMS) GetPublicKey(ctx context.Context, in *kms.GetPublicKeyInput, o ...func(*kms.Options)) (*kms.GetPublicKeyOutput, error) {
	d.note(ctx, "GetPublicKey")
	return d.fakeKMS.GetPublicKey(ctx, in, o...)
}

func (d *deadlineKMS) Sign(ctx context.Context, in *kms.SignInput, o ...func(*kms.Options)) (*kms.SignOutput, error) {
	d.note(ctx, "Sign")
	if d.stall {
		<-ctx.Done()
		return nil, ctx.Err()
	}
	return d.fakeKMS.Sign(ctx, in, o...)
}

// R4-F2: every KMS call carries its own deadline, whatever the caller's
// context: the Fiber request context never expires and the AWS SDK sets no
// read timeout, so a stalled call would hold the org's write lock for good.
func TestKMSSigner_EveryCallHasADeadline(t *testing.T) {
	ctx := context.Background() // no deadline of its own, like fasthttp's
	api := &deadlineKMS{fakeKMS: newFakeKMS(t), deadlines: map[string][]time.Duration{}}
	st := store.NewMemoryStore()
	s := NewKMSSigner(st, api, "alias/dimo-org/")
	_, err := s.Register(ctx, "did:dimo:org1", nil)
	require.NoError(t, err)
	_, err = s.Sign(ctx, "did:dimo:org1", []byte("x"))
	require.NoError(t, err)
	_, err = NewKMSSigner(st, api, "alias/dimo-org/").PublicKey(ctx, "did:dimo:org1")
	require.NoError(t, err)

	within := func(call string, limit time.Duration) {
		t.Helper()
		got := api.deadlines[call]
		require.NotEmpty(t, got, call)
		for _, left := range got {
			assert.Greater(t, left, time.Duration(0), "%s has a deadline", call)
			assert.LessOrEqual(t, left, limit, call)
		}
	}
	for _, call := range []string{"DescribeKey", "CreateKey", "CreateAlias"} {
		within(call, 15*time.Second)
	}
	within("GetPublicKey", 5*time.Second)
	within("Sign", 5*time.Second)
}

// R4-F2, reviewer 4's P5: a stalled Sign gives up at its deadline, so the
// write that was waiting on the org's lock runs.
func TestKMSSigner_StalledSignGivesUp(t *testing.T) {
	st := store.NewMemoryStore()
	api := &deadlineKMS{fakeKMS: newFakeKMS(t), deadlines: map[string][]time.Duration{}}
	s := NewKMSSigner(st, api, "alias/dimo-org/")
	s.callTimeout = 100 * time.Millisecond
	_, err := s.Register(context.Background(), "did:dimo:org1", nil)
	require.NoError(t, err)

	api.stall = true
	start := time.Now()
	_, err = s.Sign(context.Background(), "did:dimo:org1", []byte("x"))
	require.Error(t, err)
	assert.ErrorIs(t, err, context.DeadlineExceeded)
	assert.Less(t, time.Since(start), 2*time.Second)
}

// lagKMS answers NotFound for the alias once right after CreateAlias, as
// KMS's eventually consistent alias reads may.
type lagKMS struct {
	*fakeKMS
	mu        sync.Mutex
	aliasMade bool
	lagged    bool
}

func (l *lagKMS) CreateAlias(ctx context.Context, in *kms.CreateAliasInput, o ...func(*kms.Options)) (*kms.CreateAliasOutput, error) {
	out, err := l.fakeKMS.CreateAlias(ctx, in, o...)
	l.mu.Lock()
	l.aliasMade = true
	l.mu.Unlock()
	return out, err
}

func (l *lagKMS) DescribeKey(ctx context.Context, in *kms.DescribeKeyInput, o ...func(*kms.Options)) (*kms.DescribeKeyOutput, error) {
	l.mu.Lock()
	lag := l.aliasMade && !l.lagged
	if lag {
		l.lagged = true
	}
	l.mu.Unlock()
	if lag {
		return nil, &kmstypes.NotFoundException{}
	}
	return l.fakeKMS.DescribeKey(ctx, in, o...)
}

// R4-F3, reviewer 4's P2: CreateAlias landed but its reply was lost, the SDK's
// retry answers AlreadyExists, and the alias read lags once. The alias may
// well name our key, so nothing is deleted: the register asks for a retry,
// and the retry finds the key through the alias.
func TestKMSSigner_AliasLagAfterAlreadyExistsDeletesNothing(t *testing.T) {
	st := store.NewMemoryStore()
	base := newFakeKMS(t)
	base.lostReply = true
	api := &lagKMS{fakeKMS: base}
	s := NewKMSSigner(st, api, "alias/dimo-org/")

	_, err := s.Register(t.Context(), "did:dimo:org1", nil)
	require.Error(t, err)
	assert.ErrorIs(t, err, ErrRetryLater)
	assert.Empty(t, base.deleted, "the key the alias may name is never scheduled for deletion")

	didKey, err := s.Register(t.Context(), "did:dimo:org1", nil)
	require.NoError(t, err)
	assert.NotEmpty(t, didKey)
	assert.Len(t, base.created, 1, "the retry reuses the aliased key")
	row, err := st.GetOrg(t.Context(), "did:dimo:org1")
	require.NoError(t, err)
	assert.Equal(t, base.aliasTo[s.alias("did:dimo:org1")], row.KeyRef)
}

// The handler answers a register that should be retried 503, not 500.
func TestRegisterHandler_RetryLaterIs503(t *testing.T) {
	st := store.NewMemoryStore()
	h := newHost(t, st)
	base := newFakeKMS(t)
	base.lostReply = true
	h.repo.Signer = NewKMSSigner(st, &lagKMS{fakeKMS: base}, "alias/dimo-org/")
	org := newOrgDID()
	h.publish(org)

	status, body := h.do("POST", "/orgs/"+org, org, nil)
	assert.Equal(t, 503, status, body)
	assert.Equal(t, "temporarily_unavailable", body["code"])
	status, body = h.do("POST", "/orgs/"+org, org, nil)
	assert.Equal(t, 201, status, body)
}
