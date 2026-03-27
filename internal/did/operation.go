package did

import (
	"encoding/json"
	"errors"
	"fmt"

	dimocrypto "github.com/DIMO-Network/did-directory/internal/crypto"
)

// Operation types.
const (
	OpTypeCreate    = "plc_operation"
	OpTypeTombstone = "plc_tombstone"
)

// Service represents a DID service endpoint.
type Service struct {
	Type     string `json:"type"`
	Endpoint string `json:"endpoint"`
}

// Operation represents a signed DID operation in the operation log.
type Operation struct {
	Type                string            `json:"type"`
	RotationKeys        []string          `json:"rotationKeys"`
	VerificationMethods map[string]string `json:"verificationMethods"`
	AlsoKnownAs         []string          `json:"alsoKnownAs"`
	Services            map[string]Service `json:"services"`
	SacdEpoch           *uint64           `json:"sacdEpoch,omitempty"`
	Prev                *string           `json:"prev"`
	Sig                 string            `json:"sig"`
}

// UnsignedOperation is an operation without a signature, used for signing.
type UnsignedOperation struct {
	Type                string            `json:"type"`
	RotationKeys        []string          `json:"rotationKeys"`
	VerificationMethods map[string]string `json:"verificationMethods"`
	AlsoKnownAs         []string          `json:"alsoKnownAs"`
	Services            map[string]Service `json:"services"`
	SacdEpoch           *uint64           `json:"sacdEpoch,omitempty"`
	Prev                *string           `json:"prev"`
}

// ToUnsigned strips the signature from an operation for verification.
func (o *Operation) ToUnsigned() *UnsignedOperation {
	return &UnsignedOperation{
		Type:                o.Type,
		RotationKeys:        o.RotationKeys,
		VerificationMethods: o.VerificationMethods,
		AlsoKnownAs:         o.AlsoKnownAs,
		Services:            o.Services,
		SacdEpoch:           o.SacdEpoch,
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
	if len(op.VerificationMethods) == 0 {
		return errors.New("genesis operation must have at least one verification method")
	}
	if op.Sig == "" {
		return errors.New("operation must be signed")
	}
	if op.SacdEpoch != nil {
		return errors.New("genesis operation must not set sacdEpoch (always starts at 0)")
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

// ValidateUpdate checks that an update operation is well-formed.
func ValidateUpdate(op *Operation) error {
	if op.Prev == nil {
		return errors.New("update operation must reference a previous CID")
	}
	if op.Sig == "" {
		return errors.New("operation must be signed")
	}

	if op.Type == OpTypeCreate {
		if len(op.RotationKeys) == 0 {
			return errors.New("update operation must have at least one rotation key")
		}
	}

	return nil
}

// ValidateSacdEpoch checks that a new sacdEpoch (if present) is strictly greater
// than the current epoch. Returns an error if the epoch would decrease or stay the same.
func ValidateSacdEpoch(op *Operation, currentEpoch uint64) error {
	if op.SacdEpoch == nil {
		return nil
	}
	if *op.SacdEpoch <= currentEpoch {
		return fmt.Errorf("sacdEpoch must be greater than current epoch %d, got %d", currentEpoch, *op.SacdEpoch)
	}
	return nil
}

// ResolveSacdEpoch returns the effective sacdEpoch for a DID given its operation log.
// Genesis operations start at 0; subsequent operations may bump the epoch.
func ResolveSacdEpoch(ops []Operation) uint64 {
	var epoch uint64
	for _, op := range ops {
		if op.SacdEpoch != nil {
			epoch = *op.SacdEpoch
		}
	}
	return epoch
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
