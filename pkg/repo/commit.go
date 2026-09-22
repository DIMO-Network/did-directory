// Package repo defines the org repository commit log: the signed, hash-chained
// commits an org host writes, and the offline verifier anyone holding a slice of
// that log can run against the org's #dimo_org key.
//
// The chain is the v1 stand-in for an MST (spec §6.2). Every commit carries the
// CID of the one before it and a signature by the org key over everything else,
// so a verifier who holds the key and the commits can check that nothing was
// dropped, reordered or altered, without the host.
//
// Design: docs/superpowers/specs/2026-09-16-dimo-orgs-fleets-delegation-design.md
// Plan:   docs/superpowers/plans/2026-09-22-org-host-plan.md
package repo

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	dimocrypto "github.com/DIMO-Network/did-directory/internal/crypto"
	"github.com/multiformats/go-multihash"
)

// Commit operations.
const (
	OpCreate    = "create"
	OpUpdate    = "update"
	OpTombstone = "tombstone"
)

// Commit is one entry in an org's repository log.
//
// Everything except Sig is signed. Seq and Prev are inside the signature so a
// commit cannot be moved to another position in the log, and DID is inside it
// so a commit cannot be replayed into another org's repository even if two orgs
// were ever published under the same key.
type Commit struct {
	// DID is the org whose repository this commit belongs to.
	DID string `json:"did"`
	// Seq is the commit's position in the log, starting at 1.
	Seq int64 `json:"seq"`
	// Prev is the CID of the previous commit, "" for the first.
	Prev string `json:"prev"`
	// Rev is a TID minted for the commit; it is what a record's "rev" means.
	Rev        string `json:"rev"`
	Op         string `json:"op"`
	Collection string `json:"collection"`
	RKey       string `json:"rkey"`
	// Record is the record body in canonical JSON. It is absent on a tombstone.
	Record json.RawMessage `json:"record,omitempty"`
	// CommittedBy is the member DID the host authenticated for the write, or ""
	// when the org's own service DID wrote it (plan §3.2).
	CommittedBy string `json:"committedBy"`
	// ApprovedBy lists members who approved the write beyond its author.
	ApprovedBy []string `json:"approvedBy,omitempty"`
	// CommittedAt is the host clock at commit time, UTC, microsecond precision so
	// it survives a timestamptz column unchanged.
	CommittedAt time.Time `json:"committedAt"`
	// Sig is a base64url r||s signature by the org's #dimo_org key over the
	// canonical JSON of the commit without this field.
	Sig string `json:"sig,omitempty"`
}

// Committed is a commit together with its CID, which is how a host serves its
// log. The CID is derived from the commit and is not part of what is signed.
type Committed struct {
	Commit
	CID string `json:"cid"`
}

// URI returns the at:// URI of the record the commit touches.
func (c *Commit) URI() string {
	return "at://" + c.DID + "/" + c.Collection + "/" + c.RKey
}

// SigningBytes returns the canonical bytes the org key signs: the commit with
// Sig cleared.
func (c *Commit) SigningBytes() ([]byte, error) {
	unsigned := *c
	unsigned.Sig = ""
	return Canonical(unsigned)
}

// CID returns the commit's content identifier: a base58 sha2-256 multihash of
// the canonical JSON of the signed commit, in the same form the DID directory
// uses for operations.
func (c *Commit) CID() (string, error) {
	data, err := Canonical(c)
	if err != nil {
		return "", err
	}
	mh, err := multihash.Sum(data, multihash.SHA2_256, -1)
	if err != nil {
		return "", fmt.Errorf("multihash: %w", err)
	}
	return mh.B58String(), nil
}

// Signer produces signatures by an org's #dimo_org key. A host-held key is the
// v1 implementation; a remote signer such as Turnkey is a swap behind this
// interface (plan §1 decision C).
type Signer interface {
	// Sign returns a base64url r||s signature over data by org's key.
	Sign(ctx context.Context, org string, data []byte) (string, error)
	// PublicKey returns org's #dimo_org public key as a did:key.
	PublicKey(ctx context.Context, org string) (string, error)
}

// Sign fills in c.Sig using signer.
func Sign(ctx context.Context, signer Signer, c *Commit) error {
	data, err := c.SigningBytes()
	if err != nil {
		return err
	}
	sig, err := signer.Sign(ctx, c.DID, data)
	if err != nil {
		return err
	}
	c.Sig = sig
	return nil
}

// Verify checks c.Sig against pub.
func Verify(c *Commit, pub *ecdsa.PublicKey) error {
	if c.Sig == "" {
		return errors.New("commit is not signed")
	}
	data, err := c.SigningBytes()
	if err != nil {
		return err
	}
	return dimocrypto.VerifySignature(pub, data, c.Sig)
}

// Canonical returns v as canonical JSON: keys sorted bytewise, no insignificant
// whitespace, no HTML escaping, numbers as they were written. The output is a
// fixed point, so canonicalising stored canonical bytes returns them unchanged,
// which is what lets a signature made over a record survive a trip through a
// database and back out to an offline verifier.
//
// Numbers are kept as their literal text rather than parsed to float64, so a
// duration in nanoseconds does not lose precision on the way through.
func Canonical(v any) ([]byte, error) {
	raw, err := json.Marshal(v)
	if err != nil {
		return nil, fmt.Errorf("marshal: %w", err)
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	var parsed any
	if err := dec.Decode(&parsed); err != nil {
		return nil, fmt.Errorf("parse: %w", err)
	}
	if dec.More() {
		return nil, errors.New("trailing data after JSON value")
	}
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(parsed); err != nil {
		return nil, fmt.Errorf("encode: %w", err)
	}
	return bytes.TrimSuffix(buf.Bytes(), []byte("\n")), nil
}

// CanonicalRecord canonicalises a record body supplied as JSON. It refuses
// anything that is not a JSON object, since every record in a repository is one.
func CanonicalRecord(body []byte) (json.RawMessage, error) {
	dec := json.NewDecoder(bytes.NewReader(body))
	dec.UseNumber()
	var parsed map[string]any
	if err := dec.Decode(&parsed); err != nil {
		return nil, fmt.Errorf("record must be a JSON object: %w", err)
	}
	if dec.More() {
		return nil, errors.New("record must be a single JSON object")
	}
	if parsed == nil {
		return nil, errors.New("record must be a JSON object, not null")
	}
	return Canonical(parsed)
}
