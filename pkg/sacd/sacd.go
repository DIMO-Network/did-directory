// Package sacd implements single-asset grant documents (SACDs).
//
// An SACD is signed by the controller of record of an asset, never by the asset
// itself. For fleets, tags and multi-hop sharing use pkg/delegation; SACDs remain
// the simple consumer path (one owner, one vehicle, one grantee).
package sacd

import (
	"encoding/json"
	"errors"
	"fmt"
	"time"

	dimocrypto "github.com/DIMO-Network/did-directory/internal/crypto"
	"github.com/DIMO-Network/did-directory/pkg/control"
)

// DocumentType is the current SACD document type.
const DocumentType = "dimo.sacd.v3"

// Document represents an SACD (Self-Authorized Credential Document).
type Document struct {
	Type        string   `json:"type"`
	Grantor     string   `json:"grantor"`
	Grantee     string   `json:"grantee"`
	Asset       string   `json:"asset"`
	Era         uint64   `json:"era"`
	Permissions []string `json:"permissions"`
	EffectiveAt string   `json:"effectiveAt"`
	ExpiresAt   string   `json:"expiresAt"`
	// ControlProof opens the asset's control commitment for the grantor. Required
	// when the asset is a controlled DID; absent for self-grants.
	ControlProof *control.Opening `json:"controlProof,omitempty"`
	Signature    string           `json:"signature"`
}

// UnsignedPayload returns the JSON bytes of the document with the signature
// field set to empty, suitable for signing and verification.
func (d *Document) UnsignedPayload() ([]byte, error) {
	cp := *d
	cp.Signature = ""
	return json.Marshal(cp)
}

// Verify checks the SACD against the grantor's keys and the asset's control
// state at time now.
//
//   - Controlled asset: the grantor must be the controller of record for the
//     asset's current era (proven by ControlProof), the SACD must be issued in
//     that era, and it must not have become effective inside a revocation window.
//     A transfer starts a new era and therefore invalidates the SACD.
//   - Uncontrolled asset (a person or org sharing its own resources): the grantor
//     must be the asset.
func (d *Document) Verify(grantorKeys []string, asset *control.State, now time.Time) error {
	if d.Type != DocumentType {
		return fmt.Errorf("unsupported sacd type %q (want %s)", d.Type, DocumentType)
	}

	effectiveAt, err := time.Parse(time.RFC3339, d.EffectiveAt)
	if err != nil {
		return fmt.Errorf("parse effectiveAt: %w", err)
	}
	expiresAt, err := time.Parse(time.RFC3339, d.ExpiresAt)
	if err != nil {
		return fmt.Errorf("parse expiresAt: %w", err)
	}

	if cur := asset.Current(); cur != nil {
		if d.Grantor == d.Asset {
			return errors.New("a controlled asset cannot grant access to itself; its controller must sign")
		}
		if d.Era != cur.Number {
			return fmt.Errorf("sacd era %d does not match asset's current era %d", d.Era, cur.Number)
		}
		if d.ControlProof == nil {
			return errors.New("controlProof is required for a controlled asset")
		}
		if d.ControlProof.Controller != d.Grantor || d.ControlProof.Era != cur.Number {
			return errors.New("controlProof does not name the grantor for the current era")
		}
		if err := control.Verify(cur.Commitment, *d.ControlProof); err != nil {
			return fmt.Errorf("grantor is not the asset's controller of record: %w", err)
		}
		if cur.Start != nil && effectiveAt.Before(*cur.Start) {
			return errors.New("sacd became effective before the current control era")
		}
		if cur.Revoked(effectiveAt) {
			return errors.New("sacd was issued inside a revocation window")
		}
	} else if d.Grantor != d.Asset {
		return errors.New("grantor must be the asset for an uncontrolled DID")
	}

	if now.Before(effectiveAt) {
		return fmt.Errorf("sacd not yet effective (effective at %s)", d.EffectiveAt)
	}
	if now.After(expiresAt) {
		return fmt.Errorf("sacd expired (expired at %s)", d.ExpiresAt)
	}

	payload, err := d.UnsignedPayload()
	if err != nil {
		return fmt.Errorf("marshal unsigned sacd: %w", err)
	}

	var lastErr error
	for _, key := range grantorKeys {
		if err := dimocrypto.VerifyWithDIDKey(key, payload, d.Signature); err == nil {
			return nil
		} else {
			lastErr = err
		}
	}
	if lastErr == nil {
		return errors.New("grantor has no verification keys")
	}
	return fmt.Errorf("signature verification failed: %w", lastErr)
}
