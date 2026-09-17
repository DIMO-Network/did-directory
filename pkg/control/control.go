// Package control implements controller-of-record commitments and control eras
// for DIDs that represent controlled assets (vehicles).
//
// A controlled DID never names its controller publicly. Its document carries a
// commitment H(controller ‖ era ‖ salt); the controller keeps the salt privately
// and discloses an Opening only to parties that must verify control.
//
// The commitment does not bind the subject DID: a did:dimo identifier is derived
// from its genesis operation, which already contains the commitment. The salt is
// unique per subject, and an opening is only meaningful against the commitment in
// that subject's own operation log. Copying a commitment into another DID gives
// the copier nothing, because authority flows from the committed controller.
package control

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"fmt"
	"strings"
	"time"
)

const (
	// CommitmentPrefix prefixes every encoded commitment.
	CommitmentPrefix = "sha256:"

	// SaltLen is the required salt length in bytes.
	SaltLen = 32

	domainSeparator = "dimo-control-commitment-v1"
)

var b64 = base64.RawURLEncoding

// Opening is the private data that opens a commitment. Controllers store it in
// their org repository (network.dimo.org.vehicleControl) and include it in
// coverage proofs.
type Opening struct {
	Controller string `json:"controller"`
	Era        uint64 `json:"era"`
	Salt       string `json:"salt"` // base64url, no padding
}

// Era is one control interval of a controlled DID. Start is nil for the genesis
// era (unbounded past); End is nil for the current era.
type Era struct {
	Number      uint64       `json:"number"`
	Start       *time.Time   `json:"start"`
	End         *time.Time   `json:"end"`
	Commitment  string       `json:"controlCommitment"`
	Revocations []Revocation `json:"revocations,omitempty"`
}

// Revocation is a compromise window within an era: every grant or delegation
// rooted in this era's control and committed in [From, To] is invalid. To is the
// time the revocation was issued; the window is closed so that a grant racing the
// revocation within the same timestamp fails closed. Later grants are valid.
type Revocation struct {
	From time.Time `json:"from"`
	To   time.Time `json:"to"`
}

// Revoked reports whether something committed at t falls in a revocation window.
func (e *Era) Revoked(t time.Time) bool {
	for _, r := range e.Revocations {
		if !t.Before(r.From) && !t.After(r.To) {
			return true
		}
	}
	return false
}

// State is the resolved control history of a DID, oldest era first.
type State struct {
	DID  string `json:"did"`
	Eras []Era  `json:"eras"`
}

// Current returns the current era, or nil if the DID is not controlled.
func (s *State) Current() *Era {
	if s == nil || len(s.Eras) == 0 {
		return nil
	}
	return &s.Eras[len(s.Eras)-1]
}

// EraAt returns the era in effect at t, or nil if none.
func (s *State) EraAt(t time.Time) *Era {
	if s == nil {
		return nil
	}
	for i := range s.Eras {
		e := &s.Eras[i]
		if e.Start != nil && t.Before(*e.Start) {
			continue
		}
		if e.End != nil && !t.Before(*e.End) {
			continue
		}
		return e
	}
	return nil
}

// NewSalt returns a random salt encoded for use in an Opening.
func NewSalt() (string, error) {
	buf := make([]byte, SaltLen)
	if _, err := rand.Read(buf); err != nil {
		return "", fmt.Errorf("read random salt: %w", err)
	}
	return b64.EncodeToString(buf), nil
}

// Commit computes the commitment for an opening.
//
// digest = sha256(domain ‖ len32(controller) ‖ controller ‖ u64be(era) ‖ salt)
func Commit(o Opening) (string, error) {
	if o.Controller == "" {
		return "", errors.New("controller is required")
	}
	salt, err := b64.DecodeString(o.Salt)
	if err != nil {
		return "", fmt.Errorf("decode salt: %w", err)
	}
	if len(salt) != SaltLen {
		return "", fmt.Errorf("salt must be %d bytes, got %d", SaltLen, len(salt))
	}

	h := sha256.New()
	h.Write([]byte(domainSeparator))
	writeLenPrefixed(h, o.Controller)
	var era [8]byte
	binary.BigEndian.PutUint64(era[:], o.Era)
	h.Write(era[:])
	h.Write(salt)

	return CommitmentPrefix + b64.EncodeToString(h.Sum(nil)), nil
}

// Verify reports whether the opening matches the commitment.
func Verify(commitment string, o Opening) error {
	if err := ValidateFormat(commitment); err != nil {
		return err
	}
	expected, err := Commit(o)
	if err != nil {
		return err
	}
	if subtle.ConstantTimeCompare([]byte(expected), []byte(commitment)) != 1 {
		return errors.New("opening does not match control commitment")
	}
	return nil
}

// ValidateFormat checks that s is a well-formed commitment string.
func ValidateFormat(s string) error {
	if !strings.HasPrefix(s, CommitmentPrefix) {
		return fmt.Errorf("control commitment must start with %q", CommitmentPrefix)
	}
	raw, err := b64.DecodeString(strings.TrimPrefix(s, CommitmentPrefix))
	if err != nil {
		return fmt.Errorf("decode control commitment: %w", err)
	}
	if len(raw) != sha256.Size {
		return fmt.Errorf("control commitment must be %d bytes, got %d", sha256.Size, len(raw))
	}
	return nil
}

func writeLenPrefixed(h interface{ Write([]byte) (int, error) }, s string) {
	var n [4]byte
	binary.BigEndian.PutUint32(n[:], uint32(len(s)))
	h.Write(n[:])
	h.Write([]byte(s))
}
