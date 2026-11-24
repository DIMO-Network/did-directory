package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"github.com/DIMO-Network/did-directory/internal/config"
	"github.com/DIMO-Network/did-directory/internal/server"
	"github.com/DIMO-Network/did-directory/internal/store"
	"github.com/rs/zerolog"
)

func main() {
	settingsFile := flag.String("settings", "settings.yaml", "path to settings file")
	flag.Parse()

	log := zerolog.New(os.Stdout).With().
		Timestamp().
		Str("app", "did-directory").
		Logger()

	cfg, err := config.LoadConfig(*settingsFile)
	if err != nil {
		log.Fatal().Err(err).Msg("Failed to load config")
	}

	level, err := zerolog.ParseLevel(cfg.LogLevel)
	if err == nil {
		zerolog.SetGlobalLevel(level)
	}

	log.Info().
		Int("port", cfg.Port).
		Int("monitoring_port", cfg.MonitoringPort).
		Msg("Starting did-directory")

	ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGTERM, syscall.SIGINT)
	defer cancel()

	// Initialize store.
	var st store.Store
	if cfg.DatabaseURL != "" {
		pgStore, err := store.NewPostgresStore(ctx, cfg.DatabaseURL, log)
		if err != nil {
			log.Fatal().Err(err).Msg("Failed to connect to PostgreSQL")
		}
		defer pgStore.Close()
		st = pgStore
		log.Info().Msg("Using PostgreSQL store")
	} else {
		if os.Getenv("ALLOW_MEMORY_STORE") != "true" {
			log.Fatal().Msg("DATABASE_URL is empty: refusing to start on an in-memory store, which loses every operation on restart; set ALLOW_MEMORY_STORE=true for local runs")
		}
		st = store.NewMemoryStore()
		log.Warn().Msg("Using in-memory store (ALLOW_MEMORY_STORE=true)")
	}

	// Create and start the HTTP server.
	app := server.New(cfg, st, log)

	// Start server in a goroutine.
	go func() {
		addr := fmt.Sprintf(":%d", cfg.Port)
		if err := app.Listen(addr); err != nil {
			log.Fatal().Err(err).Msg("Server failed")
		}
	}()

	log.Info().Int("port", cfg.Port).Msg("Server listening")

	// Wait for shutdown signal.
	<-ctx.Done()
	log.Info().Msg("Shutting down")

	if err := app.Shutdown(); err != nil {
		log.Error().Err(err).Msg("Server shutdown error")
	}
}
