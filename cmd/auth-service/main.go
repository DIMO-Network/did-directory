package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"fmt"
	"os"
	"os/signal"
	"syscall"

	dimocrypto "github.com/DIMO-Network/did-directory/internal/crypto"
	"github.com/DIMO-Network/did-directory/internal/auth"
	"github.com/DIMO-Network/did-directory/pkg/client"
	"github.com/gofiber/fiber/v2"
	"github.com/gofiber/fiber/v2/middleware/cors"
	"github.com/gofiber/fiber/v2/middleware/recover"
	"github.com/rs/zerolog"
)

func main() {
	log := zerolog.New(os.Stdout).With().
		Timestamp().
		Str("app", "auth-service").
		Logger()

	port := os.Getenv("PORT")
	if port == "" {
		port = "8081"
	}

	directoryURL := os.Getenv("DIRECTORY_URL")
	if directoryURL == "" {
		directoryURL = "http://localhost:8080"
	}

	// Generate an ephemeral P-256 key for signing JWTs.
	signingKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		log.Fatal().Err(err).Msg("Failed to generate signing key")
	}

	didKey, err := dimocrypto.EncodeDIDKey(&signingKey.PublicKey)
	if err != nil {
		log.Fatal().Err(err).Msg("Failed to encode signing key")
	}
	log.Info().Str("signing_key", didKey).Msg("Ephemeral JWT signing key generated")

	// Initialize dependencies.
	dirClient := client.New(directoryURL)
	challenges := auth.NewChallengeStore()
	tokenSigner := auth.NewTokenSigner(signingKey)
	handler := auth.NewHandler(challenges, tokenSigner, dirClient, log)

	// Set up Fiber.
	app := fiber.New(fiber.Config{
		AppName:               "auth-service",
		DisableStartupMessage: true,
	})
	app.Use(recover.New())
	app.Use(cors.New())

	app.Get("/health", func(c *fiber.Ctx) error {
		return c.JSON(fiber.Map{"status": "ok"})
	})

	app.Get("/v1/challenge", handler.HandleChallenge)
	app.Post("/v1/auth", handler.HandleAuth)
	app.Get("/.well-known/jwks.json", handler.HandleJWKS)

	// Start server.
	go func() {
		addr := fmt.Sprintf(":%s", port)
		if err := app.Listen(addr); err != nil {
			log.Fatal().Err(err).Msg("Server failed")
		}
	}()

	log.Info().Str("port", port).Str("directory", directoryURL).Msg("Auth service listening")

	// Wait for shutdown signal.
	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGTERM, syscall.SIGINT)
	<-quit

	log.Info().Msg("Shutting down")
	if err := app.Shutdown(); err != nil {
		log.Error().Err(err).Msg("Server shutdown error")
	}
}
