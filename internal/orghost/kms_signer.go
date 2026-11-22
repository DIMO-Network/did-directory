package orghost

import (
	"context"
	"crypto/ecdsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/asn1"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"math/big"
	"sync"

	dimocrypto "github.com/DIMO-Network/did-directory/internal/crypto"
	"github.com/DIMO-Network/did-directory/internal/orghost/store"
	"github.com/aws/aws-sdk-go-v2/service/kms"
	kmstypes "github.com/aws/aws-sdk-go-v2/service/kms/types"
)

// ErrPrivateKeyNotAccepted is returned by KMSSigner.Register when the caller
// brings a key: a KMS key is born in KMS and never leaves it.
var ErrPrivateKeyNotAccepted = errors.New("privateKey is not accepted with the KMS signer")

// kmsAPI is the part of the KMS client the signer uses; *kms.Client satisfies it.
type kmsAPI interface {
	CreateKey(ctx context.Context, in *kms.CreateKeyInput, optFns ...func(*kms.Options)) (*kms.CreateKeyOutput, error)
	CreateAlias(ctx context.Context, in *kms.CreateAliasInput, optFns ...func(*kms.Options)) (*kms.CreateAliasOutput, error)
	Sign(ctx context.Context, in *kms.SignInput, optFns ...func(*kms.Options)) (*kms.SignOutput, error)
	GetPublicKey(ctx context.Context, in *kms.GetPublicKeyInput, optFns ...func(*kms.Options)) (*kms.GetPublicKeyOutput, error)
}

// KMSSigner is a repo.Signer whose org keys are P-256 keys in AWS KMS: the host
// asks KMS to sign and never holds key material. Commits come out in the same
// base64url r||s form LocalSigner produces, so verifiers cannot tell the two
// apart.
type KMSSigner struct {
	store       store.Store
	api         kmsAPI
	aliasPrefix string

	mu   sync.RWMutex
	refs map[string]string // org DID -> key ARN
	pubs map[string]string // org DID -> did:key
}

// NewKMSSigner creates a signer over api. Each org's key gets the alias
// aliasPrefix + hex(sha256(org DID))[:16].
func NewKMSSigner(st store.Store, api kmsAPI, aliasPrefix string) *KMSSigner {
	return &KMSSigner{store: st, api: api, aliasPrefix: aliasPrefix, refs: map[string]string{}, pubs: map[string]string{}}
}

// Register creates org's key in KMS and the org in the store, and returns the
// did:key to publish as #dimo_org. A key the caller brings is refused.
func (s *KMSSigner) Register(ctx context.Context, org string, key *ecdsa.PrivateKey) (string, error) {
	if key != nil {
		return "", ErrPrivateKeyNotAccepted
	}
	// Check before minting a key, so a repeat register does not leave an
	// unreferenced one behind.
	if _, err := s.store.GetOrg(ctx, org); err == nil {
		return "", store.ErrOrgExists
	} else if !store.IsNotFound(err) {
		return "", err
	}
	created, err := s.api.CreateKey(ctx, &kms.CreateKeyInput{
		KeySpec:  kmstypes.KeySpecEccNistP256,
		KeyUsage: kmstypes.KeyUsageTypeSignVerify,
		Tags:     []kmstypes.Tag{{TagKey: ptr("org"), TagValue: ptr(org)}},
	})
	if err != nil {
		return "", fmt.Errorf("create kms key: %w", err)
	}
	if created.KeyMetadata == nil || created.KeyMetadata.Arn == nil {
		return "", errors.New("create kms key: no key ARN returned")
	}
	arn := *created.KeyMetadata.Arn
	if _, err := s.api.CreateAlias(ctx, &kms.CreateAliasInput{AliasName: ptr(s.alias(org)), TargetKeyId: &arn}); err != nil {
		return "", fmt.Errorf("create kms alias: %w", err)
	}
	didKey, err := s.fetchPublicKey(ctx, arn)
	if err != nil {
		return "", err
	}
	if err := s.store.CreateOrg(ctx, store.Org{DID: org, KeyRef: arn}); err != nil {
		return "", err
	}
	s.mu.Lock()
	s.refs[org] = arn
	s.pubs[org] = didKey
	s.mu.Unlock()
	return didKey, nil
}

func (s *KMSSigner) alias(org string) string {
	sum := sha256.Sum256([]byte(org))
	return s.aliasPrefix + hex.EncodeToString(sum[:])[:16]
}

func (s *KMSSigner) keyRef(ctx context.Context, org string) (string, error) {
	s.mu.RLock()
	ref, ok := s.refs[org]
	s.mu.RUnlock()
	if ok {
		return ref, nil
	}
	o, err := s.store.GetOrg(ctx, org)
	if err != nil {
		return "", err
	}
	if o.KeyRef == "" {
		return "", fmt.Errorf("org %s has no KMS key", org)
	}
	s.mu.Lock()
	s.refs[org] = o.KeyRef
	s.mu.Unlock()
	return o.KeyRef, nil
}

func (s *KMSSigner) fetchPublicKey(ctx context.Context, ref string) (string, error) {
	out, err := s.api.GetPublicKey(ctx, &kms.GetPublicKeyInput{KeyId: &ref})
	if err != nil {
		return "", fmt.Errorf("get kms public key: %w", err)
	}
	parsed, err := x509.ParsePKIXPublicKey(out.PublicKey)
	if err != nil {
		return "", fmt.Errorf("parse kms public key: %w", err)
	}
	pub, ok := parsed.(*ecdsa.PublicKey)
	if !ok {
		return "", errors.New("kms key is not ECDSA")
	}
	return dimocrypto.EncodeDIDKey(pub)
}

// PublicKey implements repo.Signer. The key never changes, so it is fetched
// from KMS once per org.
func (s *KMSSigner) PublicKey(ctx context.Context, org string) (string, error) {
	s.mu.RLock()
	didKey, ok := s.pubs[org]
	s.mu.RUnlock()
	if ok {
		return didKey, nil
	}
	ref, err := s.keyRef(ctx, org)
	if err != nil {
		return "", err
	}
	didKey, err = s.fetchPublicKey(ctx, ref)
	if err != nil {
		return "", err
	}
	s.mu.Lock()
	s.pubs[org] = didKey
	s.mu.Unlock()
	return didKey, nil
}

// Sign implements repo.Signer: KMS signs the SHA-256 of data, which is what
// dimocrypto.SignOperation signs, and the DER result is re-encoded as
// base64url r||s with each half left-padded to 32 bytes. KMS may return either
// S of a pair; the verifier is a plain ecdsa.Verify, which takes both, so s is
// not normalised.
func (s *KMSSigner) Sign(ctx context.Context, org string, data []byte) (string, error) {
	ref, err := s.keyRef(ctx, org)
	if err != nil {
		return "", err
	}
	digest := sha256.Sum256(data)
	out, err := s.api.Sign(ctx, &kms.SignInput{
		KeyId:            &ref,
		Message:          digest[:],
		MessageType:      kmstypes.MessageTypeDigest,
		SigningAlgorithm: kmstypes.SigningAlgorithmSpecEcdsaSha256,
	})
	if err != nil {
		return "", fmt.Errorf("kms sign: %w", err)
	}
	var sig struct{ R, S *big.Int }
	if rest, err := asn1.Unmarshal(out.Signature, &sig); err != nil || len(rest) != 0 || sig.R == nil || sig.S == nil {
		return "", errors.New("kms sign: malformed DER signature")
	}
	if sig.R.Sign() <= 0 || sig.S.Sign() <= 0 || sig.R.BitLen() > 256 || sig.S.BitLen() > 256 {
		return "", errors.New("kms sign: signature component out of range")
	}
	raw := make([]byte, 64)
	sig.R.FillBytes(raw[:32])
	sig.S.FillBytes(raw[32:])
	return base64.RawURLEncoding.EncodeToString(raw), nil
}

func ptr[T any](v T) *T { return &v }
