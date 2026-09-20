package handlers

import (
	"github.com/DIMO-Network/did-directory/internal/did"
	"github.com/DIMO-Network/did-directory/internal/store"
	"github.com/DIMO-Network/did-directory/pkg/control"
	"github.com/gofiber/fiber/v2"
	"github.com/rs/zerolog"
)

// ResolveHandler handles GET /:did for DID resolution, GET /:did/data for raw state,
// and GET /:did/control for control era history.
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

	state := resolveControlState(didParam, records)

	doc, err := did.GenerateDocument(didParam, &latest.Operation, state)
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

	state := resolveControlState(didParam, records)

	return c.JSON(fiber.Map{
		"did":                 latest.DID,
		"cid":                 latest.CID,
		"rotationKeys":        latest.Operation.RotationKeys,
		"verificationMethods": latest.Operation.VerificationMethods,
		"alsoKnownAs":         latest.Operation.AlsoKnownAs,
		"services":            latest.Operation.Services,
		"controlCommitment":   latest.Operation.ControlCommitment,
		"eras":                state.Eras,
		"createdAt":           latest.CreatedAt,
	})
}

// HandleControl returns the control era history of a DID. Uncontrolled DIDs
// return an empty era list.
func (h *ResolveHandler) HandleControl(c *fiber.Ctx) error {
	didParam := c.Params("did")

	records, err := h.store.GetLog(c.Context(), didParam)
	if err != nil {
		h.log.Error().Err(err).Str("did", didParam).Msg("Failed to get DID control state")
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
			"error": "internal error",
		})
	}
	if len(records) == 0 {
		return c.Status(fiber.StatusNotFound).JSON(fiber.Map{
			"error": "DID not found",
		})
	}

	return c.JSON(resolveControlState(didParam, records))
}

func resolveControlState(didStr string, records []store.OperationRecord) *control.State {
	ops := make([]did.Operation, len(records))
	for i, r := range records {
		ops[i] = r.Operation
	}
	return did.ResolveControlState(didStr, ops)
}
