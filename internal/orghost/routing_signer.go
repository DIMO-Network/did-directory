package orghost

import (
	"context"
	"crypto/ecdsa"
	"errors"
	"fmt"
	"sync"

	"github.com/DIMO-Network/did-directory/internal/orghost/store"
	"github.com/DIMO-Network/did-directory/pkg/repo"
)

// Registrar creates an org on this host and returns the did:key to publish as
// its #dimo_org. key is the org's own key when it brought one, nil to have the
// backend generate it.
type Registrar interface {
	Register(ctx context.Context, org string, key *ecdsa.PrivateKey) (string, error)
}

// routingSigner signs with whichever backend an org's row names, so a host can
// switch the backend new orgs register with while the orgs already on it keep
// the keys they have.
type routingSigner struct {
	store        store.Store
	local        *LocalSigner
	kms          *KMSSigner
	registerWith Registrar

	mu     sync.RWMutex
	routes map[string]repo.Signer
}

// NewRoutingSigner routes each org to the backend its row names: KeyRef set
// means kms, KeyEnc set means local. Either backend may be nil when the host
// has none; an org that needs it then fails to sign. New orgs register with
// registerWith. The result is also a Registrar.
func NewRoutingSigner(st store.Store, local *LocalSigner, kms *KMSSigner, registerWith Registrar) repo.Signer {
	return &routingSigner{store: st, local: local, kms: kms, registerWith: registerWith, routes: map[string]repo.Signer{}}
}

// Register implements Registrar.
func (r *routingSigner) Register(ctx context.Context, org string, key *ecdsa.PrivateKey) (string, error) {
	if r.registerWith == nil {
		return "", errors.New("no signer is configured to register orgs")
	}
	return r.registerWith.Register(ctx, org, key)
}

func (r *routingSigner) route(ctx context.Context, org string) (repo.Signer, error) {
	r.mu.RLock()
	s, ok := r.routes[org]
	r.mu.RUnlock()
	if ok {
		return s, nil
	}
	o, err := r.store.GetOrg(ctx, org)
	if err != nil {
		return nil, err
	}
	switch {
	case o.KeyRef != "":
		if r.kms == nil {
			return nil, fmt.Errorf("org %s has a KMS key but this host has no KMS signer (set ORG_SIGNER=kms)", org)
		}
		s = r.kms
	case len(o.KeyEnc) > 0:
		if r.local == nil {
			return nil, fmt.Errorf("org %s has a local key but this host has no local signer (set MASTER_KEY)", org)
		}
		s = r.local
	default:
		return nil, fmt.Errorf("org %s has no signing key", org)
	}
	r.mu.Lock()
	r.routes[org] = s
	r.mu.Unlock()
	return s, nil
}

// Sign implements repo.Signer.
func (r *routingSigner) Sign(ctx context.Context, org string, data []byte) (string, error) {
	s, err := r.route(ctx, org)
	if err != nil {
		return "", err
	}
	return s.Sign(ctx, org, data)
}

// PublicKey implements repo.Signer.
func (r *routingSigner) PublicKey(ctx context.Context, org string) (string, error) {
	s, err := r.route(ctx, org)
	if err != nil {
		return "", err
	}
	return s.PublicKey(ctx, org)
}
