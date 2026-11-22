package handlers

import (
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/DIMO-Network/did-directory/internal/config"
	"github.com/DIMO-Network/did-directory/internal/did"
	"github.com/DIMO-Network/did-directory/internal/store"
	"github.com/gofiber/fiber/v2"
	"github.com/rs/zerolog"
)

// SubmitHandler handles POST /:did for submitting new operations.
type SubmitHandler struct {
	store  store.Store
	maxOps int
	log    zerolog.Logger
}

// NewSubmitHandler creates a new SubmitHandler. maxOps is the most operations
// one DID's log may hold (MAX_OPERATIONS_PER_DID); zero or less means
// config.DefaultMaxOperationsPerDID.
func NewSubmitHandler(s store.Store, maxOps int, log zerolog.Logger) *SubmitHandler {
	if maxOps <= 0 {
		maxOps = config.DefaultMaxOperationsPerDID
	}
	return &SubmitHandler{
		store:  s,
		maxOps: maxOps,
		log:    log.With().Str("handler", "submit").Logger(),
	}
}

// invalid answers an operation that failed validation: 413 when it is over
// the size cap, 400 otherwise.
func invalid(c *fiber.Ctx, kind string, err error) error {
	status := fiber.StatusBadRequest
	if errors.Is(err, did.ErrOperationTooLarge) {
		status = fiber.StatusRequestEntityTooLarge
	}
	return c.Status(status).JSON(fiber.Map{
		"error": fmt.Sprintf("invalid %s operation: %v", kind, err),
	})
}

// Handle processes a submitted DID operation (create or update).
func (h *SubmitHandler) Handle(c *fiber.Ctx) error {
	didParam := c.Params("did")

	var op did.Operation
	if err := json.Unmarshal(c.Body(), &op); err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"error": fmt.Sprintf("invalid operation JSON: %v", err),
		})
	}

	ctx := c.Context()

	// Check if DID already exists.
	exists, err := h.store.Exists(ctx, didParam)
	if err != nil {
		h.log.Error().Err(err).Str("did", didParam).Msg("Failed to check DID existence")
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
			"error": "internal error",
		})
	}

	if !exists {
		// This is a create operation.
		return h.handleCreate(c, didParam, &op)
	}

	// This is an update operation.
	return h.handleUpdate(c, didParam, &op)
}

func (h *SubmitHandler) handleCreate(c *fiber.Ctx, didParam string, op *did.Operation) error {
	if err := did.ValidateCreate(op); err != nil {
		return invalid(c, "create", err)
	}

	// Derive the DID from the genesis operation and verify it matches the URL.
	derivedDID, err := did.DeriveFromGenesis(op)
	if err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"error": fmt.Sprintf("failed to derive DID: %v", err),
		})
	}

	if derivedDID != didParam {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"error":    "DID mismatch: derived DID does not match URL",
			"derived":  derivedDID,
			"provided": didParam,
		})
	}

	// Verify the signature against the rotation keys declared in this operation.
	if err := did.VerifyOperationSignature(op, op.RotationKeys); err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"error": fmt.Sprintf("invalid signature: %v", err),
		})
	}

	// Compute CID.
	cid, err := did.ComputeCID(op)
	if err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
			"error": "failed to compute CID",
		})
	}

	// Store the genesis operation, but only while the log is still empty.
	if err := h.store.AppendAfter(c.Context(), didParam, "", cid, op); err != nil {
		if store.IsHeadChanged(err) {
			return c.Status(fiber.StatusConflict).JSON(fiber.Map{
				"error": "DID already exists",
			})
		}
		h.log.Error().Err(err).Str("did", didParam).Msg("Failed to store genesis operation")
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
			"error": "failed to store operation",
		})
	}

	h.log.Info().Str("did", didParam).Str("cid", cid).Msg("DID created")

	return c.Status(fiber.StatusOK).JSON(fiber.Map{
		"did": didParam,
		"cid": cid,
	})
}

func (h *SubmitHandler) handleUpdate(c *fiber.Ctx, didParam string, op *did.Operation) error {
	if err := did.ValidateUpdate(op); err != nil {
		return invalid(c, "update", err)
	}

	// The head alone decides every check an unauthenticated caller can reach:
	// deactivation, prev and the signature. The whole log is read only for an
	// operation the DID's current rotation key signed.
	head, err := h.store.GetLatest(c.Context(), didParam)
	if err != nil {
		h.log.Error().Err(err).Str("did", didParam).Msg("Failed to get the operation log head")
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
			"error": "internal error",
		})
	}

	if head.Operation.IsTombstone() {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"error": "invalid transition: DID has been deactivated",
		})
	}

	// The prev field must reference the CID of the current latest operation.
	if op.Prev == nil || *op.Prev != head.CID {
		return c.Status(fiber.StatusConflict).JSON(fiber.Map{
			"error":    "prev CID does not match current head",
			"expected": head.CID,
		})
	}

	// Verify signature against the current rotation keys.
	if err := did.VerifyOperationSignature(op, head.Operation.RotationKeys); err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"error": fmt.Sprintf("invalid signature: %v", err),
		})
	}

	// The full log resolves the control eras and counts the operations.
	records, err := h.store.GetLog(c.Context(), didParam)
	if err != nil {
		h.log.Error().Err(err).Str("did", didParam).Msg("Failed to get operation log")
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
			"error": "internal error",
		})
	}
	if len(records) == 0 {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
			"error": "internal error",
		})
	}

	current := records[len(records)-1]
	if current.CID != head.CID {
		// Another writer appended between the two reads.
		return c.Status(fiber.StatusConflict).JSON(fiber.Map{
			"error":    "prev CID does not match current head",
			"expected": current.CID,
		})
	}

	// MAX_OPERATIONS_PER_DID. A tombstone is still accepted on a full log, so
	// a DID can always be deactivated: it is terminal, so the log ends at most
	// one past the cap. The count is race-free, since the append below only
	// lands while current is still the head.
	if !op.IsTombstone() && len(records) >= h.maxOps {
		return c.Status(fiber.StatusUnprocessableEntity).JSON(fiber.Map{
			"error": fmt.Sprintf("operation log is full: a DID holds at most %d operations", h.maxOps),
		})
	}

	// Validate the operation against the current state and control eras.
	ops := make([]did.Operation, len(records))
	for i, r := range records {
		ops[i] = r.Operation
	}
	state := did.ResolveControlState(didParam, ops)

	if err := did.ValidateTransition(&current.Operation, state, op, time.Now().UTC()); err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"error": fmt.Sprintf("invalid transition: %v", err),
		})
	}

	// Compute CID for this new operation.
	cid, err := did.ComputeCID(op)
	if err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
			"error": "failed to compute CID",
		})
	}

	// Store the operation, but only if the head is still the one validated
	// against. Everything above — the prev check, the signature, the transition —
	// was decided from `current`, and a concurrent writer may have moved on since.
	if err := h.store.AppendAfter(c.Context(), didParam, current.CID, cid, op); err != nil {
		if store.IsHeadChanged(err) {
			return c.Status(fiber.StatusConflict).JSON(fiber.Map{
				"error":    "prev CID does not match current head",
				"expected": current.CID,
			})
		}
		h.log.Error().Err(err).Str("did", didParam).Msg("Failed to store update operation")
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
			"error": "failed to store operation",
		})
	}

	h.log.Info().
		Str("did", didParam).
		Str("cid", cid).
		Str("type", op.Type).
		Msg("DID updated")

	return c.Status(fiber.StatusOK).JSON(fiber.Map{
		"did": didParam,
		"cid": cid,
	})
}
