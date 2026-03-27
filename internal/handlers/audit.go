package handlers

import (
	"github.com/DIMO-Network/did-directory/internal/store"
	"github.com/gofiber/fiber/v2"
	"github.com/rs/zerolog"
)

// AuditHandler handles GET /:did/log/audit for operation history.
type AuditHandler struct {
	store store.Store
	log   zerolog.Logger
}

// NewAuditHandler creates a new AuditHandler.
func NewAuditHandler(s store.Store, log zerolog.Logger) *AuditHandler {
	return &AuditHandler{
		store: s,
		log:   log.With().Str("handler", "audit").Logger(),
	}
}

// Handle returns the full operation log for a DID.
func (h *AuditHandler) Handle(c *fiber.Ctx) error {
	didParam := c.Params("did")

	// Check existence first.
	exists, err := h.store.Exists(c.Context(), didParam)
	if err != nil {
		h.log.Error().Err(err).Str("did", didParam).Msg("Failed to check DID existence")
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
			"error": "internal error",
		})
	}

	if !exists {
		return c.Status(fiber.StatusNotFound).JSON(fiber.Map{
			"error": "DID not found",
		})
	}

	records, err := h.store.GetLog(c.Context(), didParam)
	if err != nil {
		h.log.Error().Err(err).Str("did", didParam).Msg("Failed to get audit log")
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
			"error": "internal error",
		})
	}

	// Transform to audit entries.
	entries := make([]fiber.Map, 0, len(records))
	for _, rec := range records {
		entries = append(entries, fiber.Map{
			"did":       rec.DID,
			"cid":       rec.CID,
			"operation": rec.Operation,
			"createdAt": rec.CreatedAt,
		})
	}

	return c.JSON(entries)
}
