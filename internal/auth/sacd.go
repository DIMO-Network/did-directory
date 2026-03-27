package auth

import (
	"context"
	"fmt"

	"github.com/DIMO-Network/did-directory/pkg/client"
	"github.com/DIMO-Network/did-directory/pkg/sacd"
)

// ValidateSACD verifies an SACD document against the directory.
// It resolves the grantor DID, verifies the signature, checks the epoch, and checks time bounds.
func ValidateSACD(ctx context.Context, c *client.Client, doc *sacd.Document) error {
	// Resolve the grantor DID.
	grantorDoc, err := c.Resolve(ctx, doc.Grantor)
	if err != nil {
		return fmt.Errorf("resolve grantor DID %s: %w", doc.Grantor, err)
	}

	if len(grantorDoc.VerificationMethod) == 0 {
		return fmt.Errorf("grantor DID %s has no verification methods", doc.Grantor)
	}

	// Use the first verification method's key.
	grantorDIDKey := "did:key:" + grantorDoc.VerificationMethod[0].PublicKeyMultibase

	// Verify the SACD using the shared package.
	if err := doc.Verify(grantorDIDKey, grantorDoc.DimoSacdEpoch); err != nil {
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
		if svc.Type == "StorageNode" || svc.Type == "storage" {
			return svc.ServiceEndpoint
		}
	}
	return ""
}
