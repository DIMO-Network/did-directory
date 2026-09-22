package orghost

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"errors"
	"fmt"
	"sync"

	dimocrypto "github.com/DIMO-Network/did-directory/internal/crypto"
	"github.com/DIMO-Network/did-directory/internal/orghost/store"
)

// MasterKeyLen is the length of the host master key that seals org signing
// keys at rest.
const MasterKeyLen = 32

// Sealer encrypts org signing keys for storage. AES-256-GCM under the host
// master key, with the org DID as associated data so a sealed key cannot be
// moved from one org's row to another's.
type Sealer struct {
	aead cipher.AEAD
}

// NewSealer builds a Sealer from a 32-byte master key.
func NewSealer(masterKey []byte) (*Sealer, error) {
	if len(masterKey) != MasterKeyLen {
		return nil, fmt.Errorf("master key must be %d bytes, got %d", MasterKeyLen, len(masterKey))
	}
	block, err := aes.NewCipher(masterKey)
	if err != nil {
		return nil, err
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	return &Sealer{aead: aead}, nil
}

// NewEphemeralSealer builds a Sealer under a random key that lives only in this
// process. It is what the in-memory store runs with, since nothing it seals
// outlives the process anyway.
func NewEphemeralSealer() (*Sealer, error) {
	key := make([]byte, MasterKeyLen)
	if _, err := rand.Read(key); err != nil {
		return nil, err
	}
	return NewSealer(key)
}

// Seal encrypts key for org.
func (s *Sealer) Seal(org string, key *ecdsa.PrivateKey) ([]byte, error) {
	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return nil, fmt.Errorf("marshal key: %w", err)
	}
	nonce := make([]byte, s.aead.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return nil, err
	}
	return s.aead.Seal(nonce, nonce, der, []byte(org)), nil
}

// Open decrypts a key sealed for org.
func (s *Sealer) Open(org string, sealed []byte) (*ecdsa.PrivateKey, error) {
	n := s.aead.NonceSize()
	if len(sealed) < n {
		return nil, errors.New("sealed key is too short")
	}
	der, err := s.aead.Open(nil, sealed[:n], sealed[n:], []byte(org))
	if err != nil {
		return nil, fmt.Errorf("unseal key: %w", err)
	}
	parsed, err := x509.ParsePKCS8PrivateKey(der)
	if err != nil {
		return nil, fmt.Errorf("parse key: %w", err)
	}
	key, ok := parsed.(*ecdsa.PrivateKey)
	if !ok {
		return nil, errors.New("org key is not ECDSA")
	}
	return key, nil
}

// LocalSigner is the v1 repo.Signer: it holds every org's #dimo_org key,
// sealed in the store and unsealed into a process cache on first use (plan §1
// decision C). Swapping in a remote signer later changes nothing the commits
// or their verifiers see.
type LocalSigner struct {
	store  store.Store
	sealer *Sealer

	mu   sync.RWMutex
	keys map[string]*ecdsa.PrivateKey
}

// NewLocalSigner creates a signer over the store's sealed keys.
func NewLocalSigner(st store.Store, sealer *Sealer) *LocalSigner {
	return &LocalSigner{store: st, sealer: sealer, keys: map[string]*ecdsa.PrivateKey{}}
}

// Register generates a P-256 key for org, or takes the one given, seals it and
// creates the org in the store. It returns the did:key to publish as #dimo_org.
func (s *LocalSigner) Register(ctx context.Context, org string, key *ecdsa.PrivateKey) (string, error) {
	if key == nil {
		var err error
		key, err = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			return "", fmt.Errorf("generate org key: %w", err)
		}
	}
	didKey, err := dimocrypto.EncodeDIDKey(&key.PublicKey)
	if err != nil {
		return "", fmt.Errorf("encode org key: %w", err)
	}
	sealed, err := s.sealer.Seal(org, key)
	if err != nil {
		return "", err
	}
	if err := s.store.CreateOrg(ctx, store.Org{DID: org, KeyEnc: sealed}); err != nil {
		return "", err
	}
	s.mu.Lock()
	s.keys[org] = key
	s.mu.Unlock()
	return didKey, nil
}

func (s *LocalSigner) key(ctx context.Context, org string) (*ecdsa.PrivateKey, error) {
	s.mu.RLock()
	key, ok := s.keys[org]
	s.mu.RUnlock()
	if ok {
		return key, nil
	}
	o, err := s.store.GetOrg(ctx, org)
	if err != nil {
		return nil, err
	}
	key, err = s.sealer.Open(org, o.KeyEnc)
	if err != nil {
		return nil, fmt.Errorf("org %s: %w", org, err)
	}
	s.mu.Lock()
	s.keys[org] = key
	s.mu.Unlock()
	return key, nil
}

// Sign implements repo.Signer.
func (s *LocalSigner) Sign(ctx context.Context, org string, data []byte) (string, error) {
	key, err := s.key(ctx, org)
	if err != nil {
		return "", err
	}
	return dimocrypto.SignOperation(key, data)
}

// PublicKey implements repo.Signer.
func (s *LocalSigner) PublicKey(ctx context.Context, org string) (string, error) {
	key, err := s.key(ctx, org)
	if err != nil {
		return "", err
	}
	return dimocrypto.EncodeDIDKey(&key.PublicKey)
}
