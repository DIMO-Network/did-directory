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
)

// Operation types.
const (
	OpTypeCreate    = "plc_operation"
	OpTypeTombstone = "plc_tombstone"

	// OpTypeTransfer changes the controller of record of a controlled DID and
	// starts a new control era at EffectiveAt.
	OpTypeTransfer = "dimo_transfer"

	// OpTypeRevokeSince records a compromise window [RevokeSince, EffectiveAt] in
	// the current era: every grant or delegation rooted in this era's control and
	// committed inside the window is invalid. It may rotate the custody keys in the
	// same operation; nothing else about the DID state may change.
	OpTypeRevokeSince = "dimo_revoke_since"
)

// MaxClockSkew bounds how far signed timestamps (effectiveAt, revokeSince) may
// differ from the directory's clock. It prevents backdating a transfer to strip
// grantees of history they were entitled to.
const MaxClockSkew = 5 * time.Minute

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
		if !sameStateExceptRotationKeys(head, op) {
			return errors.New("revoke_since may only rotate rotationKeys")
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
			if cur == nil || err != nil {
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
			if cur == nil || err1 != nil || err2 != nil {
				continue
			}
			cur.Revocations = append(cur.Revocations, control.Revocation{From: since, To: issued})
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

func sameStateExceptRotationKeys(a, b *Operation) bool {
	return maps.Equal(a.VerificationMethods, b.VerificationMethods) &&
		slices.Equal(a.AlsoKnownAs, b.AlsoKnownAs) &&
		maps.Equal(a.Services, b.Services) &&
		equalCommitment(a.ControlCommitment, b.ControlCommitment)
}
