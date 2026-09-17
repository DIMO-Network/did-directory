package auth

import (
	"context"
	"fmt"
	"time"

	"github.com/DIMO-Network/did-directory/pkg/client"
	"github.com/DIMO-Network/did-directory/pkg/sacd"
)

// ValidateSACD verifies an SACD document against the directory.
// It resolves the grantor's keys and the asset's control state, then checks
// control, era, revocation windows, time bounds and the signature.
func ValidateSACD(ctx context.Context, c *client.Client, doc *sacd.Document) error {
	grantorDoc, err := c.Resolve(ctx, doc.Grantor)
	if err != nil {
		return fmt.Errorf("resolve grantor DID %s: %w", doc.Grantor, err)
	}

	keys := make([]string, 0, len(grantorDoc.VerificationMethod))
	for _, vm := range grantorDoc.VerificationMethod {
		keys = append(keys, "did:key:"+vm.PublicKeyMultibase)
	}

	assetState, err := c.Control(ctx, doc.Asset)
	if err != nil {
		return fmt.Errorf("resolve asset control state %s: %w", doc.Asset, err)
	}

	if err := doc.Verify(keys, assetState, time.Now().UTC()); err != nil {
		return fmt.Errorf("sacd verification failed: %w", err)
	}

	return nil
}

// StorageFromDoc extracts the storage endpoint from a DID document's services.
func StorageFromDoc(ctx context.Context, c *client.Client, did string) string {
	doc, err := c.Resolve(ctx, did)
	if err != nil {
		return ""
	}

	for _, svc := range doc.Service {
		if svc.Type == "StorageNode" || svc.Type == "storage" || svc.Type == "DimoStorageNode" {
			return svc.ServiceEndpoint
		}
	}
	return ""
}
