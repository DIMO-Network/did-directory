package orghost

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/DIMO-Network/did-directory/internal/orghost/store"
	"github.com/DIMO-Network/did-directory/pkg/repo"
)

// SignerConfig is what BuildSigners reads from the host's settings.
type SignerConfig struct {
	// Signer is ORG_SIGNER: where new orgs' keys are made, "local" or "kms".
	Signer string
	// AliasPrefix is KMS_ALIAS_PREFIX.
	AliasPrefix string
}

// Signers is what a host signs and registers with.
type Signers struct {
	// Local signs for orgs sealed under the master key; nil without one.
	Local *LocalSigner
	// KMS signs for orgs whose key is in KMS; nil when the host has none.
	KMS *KMSSigner
	// Signer routes each org to the backend its row names, and registers new
	// orgs with the backend cfg.Signer picks.
	Signer repo.Signer
}

// BuildSigners builds the host's signing backends. sealer is nil when the host
// has no master key. newKMS makes the KMS client; it is called only when the
// host needs one.
func BuildSigners(ctx context.Context, st store.Store, sealer *Sealer, cfg SignerConfig, newKMS func(context.Context) (KMSAPI, error)) (*Signers, error) {
	if cfg.Signer != "local" && cfg.Signer != "kms" {
		return nil, fmt.Errorf("ORG_SIGNER must be local or kms, not %q", cfg.Signer)
	}
	out := &Signers{}
	var registerWith Registrar
	if sealer != nil {
		out.Local = NewLocalSigner(st, sealer)
		registerWith = out.Local
	}
	// The KMS client is needed to register under kms, and also whenever an org
	// on this host has its key in KMS: rolling ORG_SIGNER back to local must not
	// strand those orgs, it only stops new keys being made there.
	kmsRef, err := st.AnyKMSKeyRef(ctx)
	if err != nil {
		return nil, err
	}
	if cfg.Signer == "kms" || kmsRef != "" {
		if !strings.HasPrefix(cfg.AliasPrefix, "alias/") {
			return nil, fmt.Errorf("KMS_ALIAS_PREFIX must start with alias/, not %q", cfg.AliasPrefix)
		}
		api, err := newKMS(ctx)
		if err != nil {
			return nil, fmt.Errorf("build the KMS client: %w", err)
		}
		out.KMS = NewKMSSigner(st, api, cfg.AliasPrefix)
		if err := out.KMS.Probe(ctx, kmsRef); err != nil {
			return nil, err
		}
		if cfg.Signer == "kms" {
			registerWith = out.KMS
		}
	}
	if out.Local == nil && out.KMS == nil {
		return nil, errors.New("no signer: set MASTER_KEY or ORG_SIGNER=kms")
	}
	out.Signer = NewRoutingSigner(st, out.Local, out.KMS, registerWith)
	return out, nil
}
