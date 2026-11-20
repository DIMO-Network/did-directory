package server

import (
	"context"
	"sync/atomic"
	"time"

	"github.com/DIMO-Network/did-directory/internal/config"
	"github.com/DIMO-Network/did-directory/internal/handlers"
	"github.com/DIMO-Network/did-directory/internal/store"
	"github.com/gofiber/fiber/v2"
	"github.com/gofiber/fiber/v2/middleware/cors"
	"github.com/gofiber/fiber/v2/middleware/recover"
	"github.com/gofiber/fiber/v2/middleware/requestid"
	"github.com/rs/zerolog"
)

// New creates and configures the Fiber HTTP server.
func New(cfg *config.Settings, st store.Store, log zerolog.Logger) *fiber.App {
	app := fiber.New(fiber.Config{
		AppName:               "did-directory",
		DisableStartupMessage: true,
	})

	// Middleware.
	app.Use(recover.New())
	app.Use(requestid.New())
	app.Use(cors.New())

	// Liveness: process only, never touches the store.
	app.Get("/ping", func(c *fiber.Ctx) error {
		return c.JSON(fiber.Map{"status": "ok"})
	})

	// Readiness: includes the store. Logs only on a state change.
	var ready atomic.Bool
	ready.Store(true)
	app.Get("/health", func(c *fiber.Ctx) error {
		ctx, cancel := context.WithTimeout(c.UserContext(), 2*time.Second)
		defer cancel()
		// A saturated pool proves the database is reachable; pinging would
		// queue behind the load and fail readiness for the wrong reason.
		if b, ok := st.(interface{ Busy() bool }); !(ok && b.Busy()) {
			if err := st.Ping(ctx); err != nil {
				if ready.Swap(false) {
					log.Warn().Err(err).Msg("health check: store unreachable, not ready")
				}
				return c.Status(fiber.StatusServiceUnavailable).JSON(fiber.Map{
					"error": "store unavailable",
				})
			}
		}
		if !ready.Swap(true) {
			log.Info().Msg("health check: store reachable, ready")
		}
		return c.JSON(fiber.Map{
			"status": "ok",
		})
	})

	// Initialize handlers.
	submitHandler := handlers.NewSubmitHandler(st, log)
	resolveHandler := handlers.NewResolveHandler(st, log)
	auditHandler := handlers.NewAuditHandler(st, log)
	exportHandler := handlers.NewExportHandler(st, cfg.ExportPageSize, log)

	// Export endpoint (must be before /:did to avoid capture).
	app.Get("/export", exportHandler.Handle)

	// DID operations.
	app.Post("/:did", submitHandler.Handle)
	app.Get("/:did", resolveHandler.HandleResolve)
	app.Get("/:did/data", resolveHandler.HandleData)
	app.Get("/:did/control", resolveHandler.HandleControl)
	app.Get("/:did/log/audit", auditHandler.Handle)

	return app
}
