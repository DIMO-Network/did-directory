package repo

import (
	"crypto/ecdsa"
	"fmt"

	"github.com/DIMO-Network/did-directory/pkg/delegation"
)

// Head is the current state of one record key after replaying a log.
type Head struct {
	// Seq is the commit that last created or updated the record.
	Seq int64
	// Live is false once the record has been tombstoned.
	Live bool
	// TombstoneSeq is the tombstone commit, when Live is false.
	TombstoneSeq int64
}

// VerifyLog checks an org's whole commit log offline: every signature verifies
// against pub, every commit hashes to the CID the next one names, the sequence
// is unbroken from 1, every record key is addressable, every record is in
// canonical form, and the operations replay without contradiction (a create
// only where nothing is live, an update or tombstone only over something live).
// It returns the state of every record key touched.
func VerifyLog(did string, log []Committed, pub *ecdsa.PublicKey) (map[string]Head, error) {
	heads := map[string]Head{}
	var seq int64
	var prev string
	for i := range log {
		c := &log[i]
		if c.DID != did {
			return nil, fmt.Errorf("seq %d: commit belongs to %s, not %s", c.Seq, c.DID, did)
		}
		if c.Seq != seq+1 {
			return nil, fmt.Errorf("seq %d follows seq %d", c.Seq, seq)
		}
		if c.Prev != prev {
			return nil, fmt.Errorf("seq %d: prev is %q, want %q", c.Seq, c.Prev, prev)
		}
		if err := ValidateTID(c.Rev); err != nil {
			return nil, fmt.Errorf("seq %d: %w", c.Seq, err)
		}
		if c.Collection == "" {
			return nil, fmt.Errorf("seq %d: collection is empty", c.Seq)
		}
		if err := delegation.ValidateRKey(c.RKey); err != nil {
			return nil, fmt.Errorf("seq %d: %w", c.Seq, err)
		}
		if err := Verify(&c.Commit, pub); err != nil {
			return nil, fmt.Errorf("seq %d: %w", c.Seq, err)
		}
		cid, err := c.Commit.CID()
		if err != nil {
			return nil, fmt.Errorf("seq %d: %w", c.Seq, err)
		}
		if c.CID != "" && c.CID != cid {
			return nil, fmt.Errorf("seq %d: served CID %s does not match content %s", c.Seq, c.CID, cid)
		}

		key := c.Collection + "/" + c.RKey
		head, exists := heads[key]
		switch c.Op {
		case OpCreate:
			if exists && head.Live {
				return nil, fmt.Errorf("seq %d: create over live record %s", c.Seq, key)
			}
			if len(c.Record) == 0 {
				return nil, fmt.Errorf("seq %d: create without a record", c.Seq)
			}
			heads[key] = Head{Seq: c.Seq, Live: true}
		case OpUpdate:
			if !exists || !head.Live {
				return nil, fmt.Errorf("seq %d: update of %s, which is not live", c.Seq, key)
			}
			if len(c.Record) == 0 {
				return nil, fmt.Errorf("seq %d: update without a record", c.Seq)
			}
			heads[key] = Head{Seq: c.Seq, Live: true}
		case OpTombstone:
			if !exists || !head.Live {
				return nil, fmt.Errorf("seq %d: tombstone of %s, which is not live", c.Seq, key)
			}
			if len(c.Record) != 0 {
				return nil, fmt.Errorf("seq %d: tombstone carries a record", c.Seq)
			}
			heads[key] = Head{Seq: head.Seq, Live: false, TombstoneSeq: c.Seq}
		default:
			return nil, fmt.Errorf("seq %d: unknown op %q", c.Seq, c.Op)
		}
		if len(c.Record) != 0 {
			canon, err := Canonical(c.Record)
			if err != nil {
				return nil, fmt.Errorf("seq %d: record: %w", c.Seq, err)
			}
			if string(canon) != string(c.Record) {
				return nil, fmt.Errorf("seq %d: record is not in canonical form", c.Seq)
			}
		}
		seq, prev = c.Seq, cid
	}
	return heads, nil
}
