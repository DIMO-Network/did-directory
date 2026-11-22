package did

import (
	"encoding/json"
	"errors"
	"fmt"
	"maps"
	"slices"
	"time"

	dimocrypto "github.com/DIMO-Network/did-directory/internal/crypto"
	"github.com/DIMO-Network/did-directory/pkg/control"
	"github.com/DIMO-Network/did-directory/pkg/didkey"
)

// Operation types.
const (
	OpTypeCreate    = "plc_operation"
	OpTypeTombstone = "plc_tombstone"

	// OpTypeTransfer changes the controller of record of a controlled DID and
	// starts a new control era at EffectiveAt.
	OpTypeTransfer = "dimo_transfer"

	// OpTypeRevokeSince records a compromise window [RevokeSince, EffectiveAt] and
	// closes the current era: every delegation rooted in this era's control and
	// committed inside the window is invalid, and any proof bound to the closed
	// era's commitment stops verifying.
	//
	// It ends the era so that the compromise cannot be argued about: a window
	// filters on commit time, and ending the era invalidates the old opening
	// itself, so nothing that opened the old commitment can be replayed.
	// Delegations carry a witnessed CommittedAt and keep their pre-window history
	// through the era intervals they already resolve.
	//
	// The operation re-commits control for the next era under the same controller
	// and may rotate the custody keys at the same time; nothing else about the DID
	// state may change.
	OpTypeRevokeSince = "dimo_revoke_since"
)

// MaxClockSkew bounds how far signed timestamps (effectiveAt, revokeSince) may
// differ from the directory's clock. It prevents backdating a transfer to strip
// grantees of history they were entitled to.
const MaxClockSkew = 5 * time.Minute

// Limits on a submitted operation. The directory takes operations from anyone,
// and ValidateCreate and ValidateUpdate check these before any key is decoded
// or any signature tried, so an anonymous request cannot buy CPU with a long
// key list or a long key.
const (
	// MaxRotationKeys bounds rotationKeys.
	MaxRotationKeys = 5
	// MaxVerificationMethods bounds verificationMethods.
	MaxVerificationMethods = 32
	// MaxDIDKeyBytes bounds each did:key string, rotation key or verification
	// method. A did:key of either supported curve is 57 bytes.
	MaxDIDKeyBytes = didkey.MaxLength
)

// Service represents a DID service endpoint.
type Service struct {
	Type     string `json:"type"`
	Endpoint string `json:"endpoint"`
}

// Operation represents a signed DID operation in the operation log.
type Operation struct {
	Type                string             `json:"type"`
	RotationKeys        []string           `json:"rotationKeys"`
	VerificationMethods map[string]string  `json:"verificationMethods"`
	AlsoKnownAs         []string           `json:"alsoKnownAs"`
	Services            map[string]Service `json:"services"`
	ControlCommitment   *string            `json:"controlCommitment,omitempty"`
	EffectiveAt         *string            `json:"effectiveAt,omitempty"`
	RevokeSince         *string            `json:"revokeSince,omitempty"`
	Prev                *string            `json:"prev"`
	Sig                 string             `json:"sig"`
}

// UnsignedOperation is an operation without a signature, used for signing.
type UnsignedOperation struct {
	Type                string             `json:"type"`
	RotationKeys        []string           `json:"rotationKeys"`
	VerificationMethods map[string]string  `json:"verificationMethods"`
	AlsoKnownAs         []string           `json:"alsoKnownAs"`
	Services            map[string]Service `json:"services"`
	ControlCommitment   *string            `json:"controlCommitment,omitempty"`
	EffectiveAt         *string            `json:"effectiveAt,omitempty"`
	RevokeSince         *string            `json:"revokeSince,omitempty"`
	Prev                *string            `json:"prev"`
}

// ToUnsigned strips the signature from an operation for verification.
func (o *Operation) ToUnsigned() *UnsignedOperation {
	return &UnsignedOperation{
		Type:                o.Type,
		RotationKeys:        o.RotationKeys,
		VerificationMethods: o.VerificationMethods,
		AlsoKnownAs:         o.AlsoKnownAs,
		Services:            o.Services,
		ControlCommitment:   o.ControlCommitment,
		EffectiveAt:         o.EffectiveAt,
		RevokeSince:         o.RevokeSince,
		Prev:                o.Prev,
	}
}

// IsGenesis returns true if this operation is a genesis (create) operation.
func (o *Operation) IsGenesis() bool {
	return o.Prev == nil && o.Type == OpTypeCreate
}

// IsTombstone returns true if this is a deactivation operation.
func (o *Operation) IsTombstone() bool {
	return o.Type == OpTypeTombstone
}

// IsControlled returns true if the DID state produced by this operation is a
// controlled asset (carries a control commitment).
func (o *Operation) IsControlled() bool {
	return o.ControlCommitment != nil
}

// ValidateCreate checks that a genesis operation has all required fields.
func ValidateCreate(op *Operation) error {
	if err := validateLimits(op); err != nil {
		return err
	}
	if op.Type != OpTypeCreate {
		return errors.New("genesis operation must have type plc_operation")
	}
	if op.Prev != nil {
		return errors.New("genesis operation must have nil prev")
	}
	if len(op.RotationKeys) == 0 {
		return errors.New("genesis operation must have at least one rotation key")
	}
	if op.Sig == "" {
		return errors.New("operation must be signed")
	}
	if op.EffectiveAt != nil || op.RevokeSince != nil {
		return errors.New("genesis operation must not set effectiveAt or revokeSince")
	}
	if err := validateStateShape(op); err != nil {
		return err
	}

	// Validate all keys are valid did:key format.
	for i, rk := range op.RotationKeys {
		if _, err := dimocrypto.DecodeDIDKey(rk); err != nil {
			return fmt.Errorf("invalid rotation key [%d]: %w", i, err)
		}
	}
	for id, vk := range op.VerificationMethods {
		if _, err := dimocrypto.DecodeDIDKey(vk); err != nil {
			return fmt.Errorf("invalid verification method %q: %w", id, err)
		}
	}

	return nil
}

// validateLimits checks the key counts and the length of every did:key. It
// decodes nothing, so it runs first.
func validateLimits(op *Operation) error {
	if n := len(op.RotationKeys); n > MaxRotationKeys {
		return fmt.Errorf("at most %d rotation keys, got %d", MaxRotationKeys, n)
	}
	if n := len(op.VerificationMethods); n > MaxVerificationMethods {
		return fmt.Errorf("at most %d verification methods, got %d", MaxVerificationMethods, n)
	}
	for i, rk := range op.RotationKeys {
		if len(rk) > MaxDIDKeyBytes {
			return fmt.Errorf("rotation key [%d] is longer than %d bytes", i, MaxDIDKeyBytes)
		}
	}
	for _, id := range slices.Sorted(maps.Keys(op.VerificationMethods)) {
		if len(op.VerificationMethods[id]) > MaxDIDKeyBytes {
			return fmt.Errorf("verification method %q is longer than %d bytes", id, MaxDIDKeyBytes)
		}
	}
	return nil
}

// validateStateShape enforces the controlled/uncontrolled invariants on a
// state-carrying operation.
func validateStateShape(op *Operation) error {
	if op.ControlCommitment == nil {
		if len(op.VerificationMethods) == 0 {
			return errors.New("operation must have at least one verification method")
		}
		return nil
	}
	if err := control.ValidateFormat(*op.ControlCommitment); err != nil {
		return fmt.Errorf("invalid controlCommitment: %w", err)
	}
	// A controlled asset never signs grants or data; its controller acts for it.
	if len(op.VerificationMethods) != 0 {
		return errors.New("controlled DIDs must not have verification methods")
	}
	return nil
}

// ValidateUpdate checks that an update operation is well-formed on its own.
// Use ValidateTransition to check it against the current state.
func ValidateUpdate(op *Operation) error {
	if err := validateLimits(op); err != nil {
		return err
	}
	if op.Prev == nil {
		return errors.New("update operation must reference a previous CID")
	}
	if op.Sig == "" {
		return errors.New("operation must be signed")
	}

	switch op.Type {
	case OpTypeCreate:
		if op.EffectiveAt != nil || op.RevokeSince != nil {
			return errors.New("plc_operation must not set effectiveAt or revokeSince")
		}
		if len(op.RotationKeys) == 0 {
			return errors.New("update operation must have at least one rotation key")
		}
		return validateStateShape(op)
	case OpTypeTransfer:
		if len(op.RotationKeys) == 0 {
			return errors.New("transfer must set the new controller's rotation keys")
		}
		if op.ControlCommitment == nil {
			return errors.New("transfer must set a new controlCommitment")
		}
		if op.RevokeSince != nil {
			return errors.New("transfer must not set revokeSince")
		}
		if _, err := parseTimestamp(op.EffectiveAt, "effectiveAt"); err != nil {
			return err
		}
		return validateStateShape(op)
	case OpTypeRevokeSince:
		if len(op.RotationKeys) == 0 {
			return errors.New("revoke_since must keep at least one rotation key")
		}
		if op.ControlCommitment == nil {
			return errors.New("revoke_since must set a new controlCommitment: it starts a new era")
		}
		since, err := parseTimestamp(op.RevokeSince, "revokeSince")
		if err != nil {
			return err
		}
		issued, err := parseTimestamp(op.EffectiveAt, "effectiveAt")
		if err != nil {
			return err
		}
		if !since.Before(issued) {
			return errors.New("revokeSince must be before effectiveAt")
		}
		return validateStateShape(op)
	case OpTypeTombstone:
		if op.RevokeSince != nil {
			return errors.New("tombstone must not set revokeSince")
		}
		if op.EffectiveAt != nil {
			if _, err := parseTimestamp(op.EffectiveAt, "effectiveAt"); err != nil {
				return err
			}
		}
		return nil
	default:
		return fmt.Errorf("unknown operation type %q", op.Type)
	}
}

// ValidateTransition checks that op is a legal successor of head given the
// resolved control state. now is the directory's clock.
func ValidateTransition(head *Operation, state *control.State, op *Operation, now time.Time) error {
	if head.IsTombstone() {
		return errors.New("DID has been deactivated")
	}

	switch op.Type {
	case OpTypeCreate:
		if !equalCommitment(head.ControlCommitment, op.ControlCommitment) {
			return errors.New("controlCommitment can only change through dimo_transfer")
		}
		return nil

	case OpTypeTransfer:
		cur := state.Current()
		if cur == nil || !head.IsControlled() {
			return errors.New("transfer requires a controlled DID")
		}
		if *op.ControlCommitment == *head.ControlCommitment {
			return errors.New("transfer must set a different controlCommitment")
		}
		at, _ := parseTimestamp(op.EffectiveAt, "effectiveAt")
		if err := withinSkew(at, now, "effectiveAt"); err != nil {
			return err
		}
		if cur.Start != nil && !at.After(*cur.Start) {
			return fmt.Errorf("effectiveAt must be after the current era start %s", cur.Start.Format(time.RFC3339))
		}
		return nil

	case OpTypeRevokeSince:
		cur := state.Current()
		if cur == nil || !head.IsControlled() {
			return errors.New("revoke_since requires a controlled DID")
		}
		if !sameStateExceptCustody(head, op) {
			return errors.New("revoke_since may only rotate rotationKeys and re-commit control")
		}
		if *op.ControlCommitment == *head.ControlCommitment {
			return errors.New("revoke_since must set a different controlCommitment: it starts a new era")
		}
		issued, _ := parseTimestamp(op.EffectiveAt, "effectiveAt")
		if err := withinSkew(issued, now, "effectiveAt"); err != nil {
			return err
		}
		since, _ := parseTimestamp(op.RevokeSince, "revokeSince")
		if cur.Start != nil && since.Before(*cur.Start) {
			return fmt.Errorf("revokeSince must be within the current era (starts %s)", cur.Start.Format(time.RFC3339))
		}
		return nil

	case OpTypeTombstone:
		// A controlled DID must timestamp its deactivation, so that resolution can
		// close the final era. Without an end the era reads as live forever, and
		// grants over a scrapped or stolen asset keep verifying.
		if head.IsControlled() {
			at, err := parseTimestamp(op.EffectiveAt, "effectiveAt")
			if err != nil {
				return fmt.Errorf("deactivating a controlled DID requires effectiveAt: %w", err)
			}
			if err := withinSkew(at, now, "effectiveAt"); err != nil {
				return err
			}
			cur := state.Current()
			if cur != nil && cur.Start != nil && at.Before(*cur.Start) {
				return fmt.Errorf("effectiveAt must be within the current era (starts %s)", cur.Start.Format(time.RFC3339))
			}
		}
		return nil

	default:
		return fmt.Errorf("unknown operation type %q", op.Type)
	}
}

// ResolveControlState derives the control era history from an operation log.
// Operations are assumed to have been validated on submission.
func ResolveControlState(didStr string, ops []Operation) *control.State {
	state := &control.State{DID: didStr, Eras: []control.Era{}}
	for i := range ops {
		op := &ops[i]
		switch op.Type {
		case OpTypeCreate:
			if op.IsGenesis() && op.ControlCommitment != nil {
				state.Eras = append(state.Eras, control.Era{Number: 0, Commitment: *op.ControlCommitment})
			}
		case OpTypeTransfer:
			cur := state.Current()
			at, err := parseTimestamp(op.EffectiveAt, "effectiveAt")
			// Submission validation requires a commitment, but resolution runs over
			// whatever the store holds: a hand-inserted row or a restore must not
			// panic every read of this DID.
			if cur == nil || err != nil || op.ControlCommitment == nil {
				continue
			}
			cur.End = &at
			state.Eras = append(state.Eras, control.Era{
				Number:     cur.Number + 1,
				Start:      &at,
				Commitment: *op.ControlCommitment,
			})
		case OpTypeRevokeSince:
			cur := state.Current()
			since, err1 := parseTimestamp(op.RevokeSince, "revokeSince")
			issued, err2 := parseTimestamp(op.EffectiveAt, "effectiveAt")
			if cur == nil || err1 != nil || err2 != nil || op.ControlCommitment == nil {
				continue
			}
			cur.Revocations = append(cur.Revocations, control.Revocation{From: since, To: issued})
			cur.End = &issued
			// The window travels into the new era as well. It filters on commit
			// time, not on which era a record names, so a delegation committed
			// inside the window must stay void even though the controller has
			// published an opening for the era that follows it.
			state.Eras = append(state.Eras, control.Era{
				Number:      cur.Number + 1,
				Start:       &issued,
				Commitment:  *op.ControlCommitment,
				Revocations: slices.Clone(cur.Revocations),
			})
		case OpTypeTombstone:
			// Deactivation is terminal: close the final era so nothing reads as
			// live, and mark the state so State.Current reports no controller.
			if cur := state.Current(); cur != nil && cur.End == nil {
				if at, err := parseTimestamp(op.EffectiveAt, "effectiveAt"); err == nil {
					cur.End = &at
				}
			}
			state.Deactivated = true
		default:
			// Unknown types never reach the store: ValidateCreate and ValidateUpdate
			// reject them on submission. Ignoring one here keeps resolution total.
		}
	}
	return state
}

// VerifyOperationSignature verifies that the operation's signature is valid
// against one of the provided authorized keys (rotation keys from the current state).
func VerifyOperationSignature(op *Operation, authorizedKeys []string) error {
	unsigned := op.ToUnsigned()

	data, err := json.Marshal(unsigned)
	if err != nil {
		return fmt.Errorf("marshal unsigned operation: %w", err)
	}

	// Try each authorized key until one verifies.
	var lastErr error
	for _, key := range authorizedKeys {
		if err := dimocrypto.VerifyWithDIDKey(key, data, op.Sig); err == nil {
			return nil
		} else {
			lastErr = err
		}
	}

	if lastErr != nil {
		return fmt.Errorf("no authorized key verified the signature: %w", lastErr)
	}
	return errors.New("no authorized keys provided")
}

func parseTimestamp(s *string, field string) (time.Time, error) {
	if s == nil {
		return time.Time{}, fmt.Errorf("%s is required", field)
	}
	t, err := time.Parse(time.RFC3339, *s)
	if err != nil {
		return time.Time{}, fmt.Errorf("invalid %s: %w", field, err)
	}
	return t.UTC(), nil
}

func withinSkew(t, now time.Time, field string) error {
	if d := t.Sub(now); d > MaxClockSkew || d < -MaxClockSkew {
		return fmt.Errorf("%s must be within %s of the directory clock", field, MaxClockSkew)
	}
	return nil
}

func equalCommitment(a, b *string) bool {
	if a == nil || b == nil {
		return a == b
	}
	return *a == *b
}

// sameStateExceptCustody reports whether two operations describe the same DID
// state apart from the custody material — the rotation keys and the control
// commitment — which dimo_revoke_since is allowed to replace.
func sameStateExceptCustody(a, b *Operation) bool {
	return maps.Equal(a.VerificationMethods, b.VerificationMethods) &&
		slices.Equal(a.AlsoKnownAs, b.AlsoKnownAs) &&
		maps.Equal(a.Services, b.Services) &&
		(a.ControlCommitment == nil) == (b.ControlCommitment == nil)
}
