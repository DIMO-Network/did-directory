package handlers

import (
	"github.com/DIMO-Network/did-directory/internal/did"
	"github.com/DIMO-Network/did-directory/internal/store"
	"github.com/gofiber/fiber/v2"
	"github.com/rs/zerolog"
)

// ResolveHandler handles GET /:did for DID resolution and GET /:did/data for raw state.
type ResolveHandler struct {
	store store.Store
	log   zerolog.Logger
}

// NewResolveHandler creates a new ResolveHandler.
func NewResolveHandler(s store.Store, log zerolog.Logger) *ResolveHandler {
	return &ResolveHandler{
		store: s,
		log:   log.With().Str("handler", "resolve").Logger(),
	}
}

// HandleResolve returns the W3C DID Document for a given DID.
func (h *ResolveHandler) HandleResolve(c *fiber.Ctx) error {
	didParam := c.Params("did")

	records, err := h.store.GetLog(c.Context(), didParam)
	if err != nil {
		h.log.Error().Err(err).Str("did", didParam).Msg("Failed to resolve DID")
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
			"error": "internal error",
		})
	}
	if len(records) == 0 {
		return c.Status(fiber.StatusNotFound).JSON(fiber.Map{
			"error": "DID not found",
		})
	}

	latest := records[len(records)-1]

	// Resolve the sacdEpoch from the full operation log.
	ops := make([]did.Operation, len(records))
	for i, r := range records {
		ops[i] = r.Operation
	}
	sacdEpoch := did.ResolveSacdEpoch(ops)

	doc, err := did.GenerateDocument(didParam, &latest.Operation, sacdEpoch)
	if err != nil {
		return c.Status(fiber.StatusGone).JSON(fiber.Map{
			"error": err.Error(),
		})
	}

	return c.JSON(doc)
}

// HandleData returns the raw PLC state data for a DID.
func (h *ResolveHandler) HandleData(c *fiber.Ctx) error {
	didParam := c.Params("did")

	records, err := h.store.GetLog(c.Context(), didParam)
	if err != nil {
		h.log.Error().Err(err).Str("did", didParam).Msg("Failed to get DID data")
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
			"error": "internal error",
		})
	}
	if len(records) == 0 {
		return c.Status(fiber.StatusNotFound).JSON(fiber.Map{
			"error": "DID not found",
		})
	}

	latest := records[len(records)-1]

	// Resolve the sacdEpoch from the full operation log.
	ops := make([]did.Operation, len(records))
	for i, r := range records {
		ops[i] = r.Operation
	}
	sacdEpoch := did.ResolveSacdEpoch(ops)

	return c.JSON(fiber.Map{
		"did":                 latest.DID,
		"cid":                 latest.CID,
		"rotationKeys":        latest.Operation.RotationKeys,
		"verificationMethods": latest.Operation.VerificationMethods,
		"alsoKnownAs":         latest.Operation.AlsoKnownAs,
		"services":            latest.Operation.Services,
		"sacdEpoch":           sacdEpoch,
		"createdAt":           latest.CreatedAt,
	})
}
