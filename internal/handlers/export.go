package handlers

import (
	"encoding/json"
	"strconv"

	"github.com/DIMO-Network/did-directory/internal/store"
	"github.com/gofiber/fiber/v2"
	"github.com/rs/zerolog"
)

// ExportHandler handles GET /export for bulk export.
type ExportHandler struct {
	store    store.Store
	log      zerolog.Logger
	pageSize int
}

// NewExportHandler creates a new ExportHandler.
func NewExportHandler(s store.Store, pageSize int, log zerolog.Logger) *ExportHandler {
	return &ExportHandler{
		store:    s,
		log:      log.With().Str("handler", "export").Logger(),
		pageSize: pageSize,
	}
}

// Handle returns operations as JSON Lines with cursor-based pagination.
func (h *ExportHandler) Handle(c *fiber.Ctx) error {
	afterStr := c.Query("after", "0")
	after, err := strconv.ParseInt(afterStr, 10, 64)
	if err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"error": "invalid 'after' parameter",
		})
	}

	limitStr := c.Query("limit", strconv.Itoa(h.pageSize))
	limit, err := strconv.Atoi(limitStr)
	if err != nil || limit <= 0 || limit > h.pageSize {
		limit = h.pageSize
	}

	records, err := h.store.Export(c.Context(), after, limit)
	if err != nil {
		h.log.Error().Err(err).Int64("after", after).Msg("Failed to export operations")
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
			"error": "internal error",
		})
	}

	// Return as JSON Lines (application/jsonl).
	c.Set("Content-Type", "application/jsonl")

	for _, rec := range records {
		entry := store.ExportRecord{
			DID:       rec.DID,
			CID:       rec.CID,
			Operation: rec.Operation,
			CreatedAt: rec.CreatedAt.Format("2006-01-02T15:04:05.000Z"),
		}

		line, err := json.Marshal(entry)
		if err != nil {
			h.log.Error().Err(err).Int64("seq", rec.Seq).Msg("Failed to marshal export record")
			continue
		}

		_, _ = c.Write(line)
		_, _ = c.Write([]byte("\n"))
	}

	return nil
}
