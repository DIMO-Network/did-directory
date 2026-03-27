package sacd

import (
	"encoding/json"
	"fmt"
	"time"

	dimocrypto "github.com/DIMO-Network/did-directory/internal/crypto"
)

// Document represents an SACD (Self-Authorized Credential Document).
type Document struct {
	Type        string   `json:"type"`
	Grantor     string   `json:"grantor"`
	Grantee     string   `json:"grantee"`
	Asset       string   `json:"asset"`
	SacdEpoch   uint64   `json:"sacdEpoch"`
	Permissions []string `json:"permissions"`
	EffectiveAt string   `json:"effectiveAt"`
	ExpiresAt   string   `json:"expiresAt"`
	Signature   string   `json:"signature"`
}

// UnsignedPayload returns the JSON bytes of the document with the signature
// field set to empty, suitable for signing and verification.
func (d *Document) UnsignedPayload() ([]byte, error) {
	cp := *d
	cp.Signature = ""
	return json.Marshal(cp)
}

// Verify checks the SACD document's signature against the given did:key,
// validates the epoch, and checks time bounds.
func (d *Document) Verify(grantorDIDKey string, currentEpoch uint64) error {
	// Check epoch.
	if d.SacdEpoch < currentEpoch {
		return fmt.Errorf("sacd epoch %d is less than grantor's current epoch %d", d.SacdEpoch, currentEpoch)
	}

	// Check time bounds.
	now := time.Now().UTC()

	effectiveAt, err := time.Parse(time.RFC3339, d.EffectiveAt)
	if err != nil {
		return fmt.Errorf("parse effectiveAt: %w", err)
	}
	if now.Before(effectiveAt) {
		return fmt.Errorf("sacd not yet effective (effective at %s)", d.EffectiveAt)
	}

	expiresAt, err := time.Parse(time.RFC3339, d.ExpiresAt)
	if err != nil {
		return fmt.Errorf("parse expiresAt: %w", err)
	}
	if now.After(expiresAt) {
		return fmt.Errorf("sacd expired (expired at %s)", d.ExpiresAt)
	}

	// Verify signature.
	payload, err := d.UnsignedPayload()
	if err != nil {
		return fmt.Errorf("marshal unsigned sacd: %w", err)
	}

	if err := dimocrypto.VerifyWithDIDKey(grantorDIDKey, payload, d.Signature); err != nil {
		return fmt.Errorf("signature verification failed: %w", err)
	}

	return nil
}
