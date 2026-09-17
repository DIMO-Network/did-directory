package handlers

import (
	"encoding/json"
	"fmt"
	"time"

	"github.com/DIMO-Network/did-directory/internal/did"
	"github.com/DIMO-Network/did-directory/internal/store"
	"github.com/gofiber/fiber/v2"
	"github.com/rs/zerolog"
)

// SubmitHandler handles POST /:did for submitting new operations.
type SubmitHandler struct {
	store store.Store
	log   zerolog.Logger
}

// NewSubmitHandler creates a new SubmitHandler.
func NewSubmitHandler(s store.Store, log zerolog.Logger) *SubmitHandler {
	return &SubmitHandler{
		store: s,
		log:   log.With().Str("handler", "submit").Logger(),
	}
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
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"error": fmt.Sprintf("invalid create operation: %v", err),
		})
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

	// Store the genesis operation.
	if err := h.store.Append(c.Context(), didParam, cid, op); err != nil {
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
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"error": fmt.Sprintf("invalid update operation: %v", err),
		})
	}

	// Get the full operation log to resolve current state and control eras.
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

	if current.Operation.IsTombstone() {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"error": "invalid transition: DID has been deactivated",
		})
	}

	// The prev field must reference the CID of the current latest operation.
	if op.Prev == nil || *op.Prev != current.CID {
		return c.Status(fiber.StatusConflict).JSON(fiber.Map{
			"error":    "prev CID does not match current head",
			"expected": current.CID,
		})
	}

	// Verify signature against the current rotation keys.
	if err := did.VerifyOperationSignature(op, current.Operation.RotationKeys); err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"error": fmt.Sprintf("invalid signature: %v", err),
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

	// Store the operation.
	if err := h.store.Append(c.Context(), didParam, cid, op); err != nil {
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
