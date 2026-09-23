// Command org-host serves org repositories: the signed commit logs that hold
// every org's delegations, roles, tags, memberships, custody periods and
// control openings (docs/superpowers/plans/2026-09-22-org-host-plan.md).
package main

import (
	"context"
	"encoding/base64"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/DIMO-Network/did-directory/internal/orghost"
	"github.com/DIMO-Network/did-directory/internal/orghost/store"
	"github.com/DIMO-Network/did-directory/pkg/agreement"
	"github.com/DIMO-Network/did-directory/pkg/client"
	"github.com/rs/zerolog"
)

func main() {
	settingsFile := flag.String("settings", "org-host.yaml", "path to settings file")
	flag.Parse()

	log := zerolog.New(os.Stdout).With().Timestamp().Str("app", "org-host").Logger()

	cfg, err := orghost.LoadSettings(*settingsFile)
	if err != nil {
		log.Fatal().Err(err).Msg("Failed to load config")
	}
	if level, err := zerolog.ParseLevel(cfg.LogLevel); err == nil {
		zerolog.SetGlobalLevel(level)
	}

	ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGTERM, syscall.SIGINT)
	defer cancel()

	var st store.Store
	var sealer *orghost.Sealer
	if cfg.DatabaseURL != "" {
		if cfg.MasterKey == "" {
			log.Fatal().Msg("MASTER_KEY is required with DATABASE_URL: org signing keys are sealed at rest")
		}
		masterKey, err := base64.StdEncoding.DecodeString(cfg.MasterKey)
		if err != nil {
			log.Fatal().Err(err).Msg("MASTER_KEY must be base64")
		}
		if sealer, err = orghost.NewSealer(masterKey); err != nil {
			log.Fatal().Err(err).Msg("Bad MASTER_KEY")
		}
		pg, err := store.NewPostgresStore(ctx, cfg.DatabaseURL, log)
		if err != nil {
			log.Fatal().Err(err).Msg("Failed to connect to PostgreSQL")
		}
		defer func() { _ = pg.Close() }()
		st = pg
		log.Info().Msg("Using PostgreSQL store")
	} else {
		if sealer, err = orghost.NewEphemeralSealer(); err != nil {
			log.Fatal().Err(err).Msg("Failed to create sealer")
		}
		st = store.NewMemoryStore()
		log.Warn().Msg("Using in-memory store (no DATABASE_URL configured): org keys do not outlive this process")
	}

	var auth orghost.Authenticator
	switch {
	case cfg.IdentityJWKSURL != "":
		auth, err = orghost.NewJWKSAuthenticatorFromURL(ctx, cfg.IdentityJWKSURL, cfg.IdentityIssuer)
	case cfg.IdentityJWKS != "":
		auth, err = orghost.NewJWKSAuthenticator([]byte(cfg.IdentityJWKS), cfg.IdentityIssuer)
	default:
		log.Fatal().Msg("IDENTITY_JWKS_URL or IDENTITY_JWKS is required: writes are attributed to the identity token's sub")
	}
	if err != nil {
		log.Fatal().Err(err).Msg("Failed to load identity keys")
	}

	if cfg.DirectoryURL == "" {
		log.Fatal().Msg("DIRECTORY_URL is required: /authorize reads control state from the directory")
	}
	var controlTTL time.Duration
	if cfg.ControlCacheTTL != "" {
		if controlTTL, err = time.ParseDuration(cfg.ControlCacheTTL); err != nil || controlTTL <= 0 {
			log.Fatal().Str("value", cfg.ControlCacheTTL).Msg("CONTROL_CACHE_TTL must be a positive duration")
		}
	}
	if len(cfg.IssuerDIDs) == 0 {
		log.Warn().Msg("No ISSUER_DIDS configured: nothing may call /authorize")
	}

	// The commit policy profiles a role may name (plan §3.2). The booking
	// profile is registered here by name; what a booking is stays with the
	// booking service (decision F).
	booking := agreement.CommitPolicy()
	policies := orghost.Policies{booking.Name: booking}

	repo := &orghost.Repository{Store: st, Signer: orghost.NewLocalSigner(st, sealer)}
	app := orghost.New(orghost.Options{
		Repo:            repo,
		Auth:            auth,
		Control:         client.New(cfg.DirectoryURL),
		Issuers:         cfg.IssuerDIDs,
		Admins:          cfg.AdminDIDs,
		Policies:        policies,
		PageSize:        cfg.PageSize,
		ControlCacheTTL: controlTTL,
		Log:             log,
	})

	go func() {
		if err := app.Listen(fmt.Sprintf(":%d", cfg.Port)); err != nil {
			log.Fatal().Err(err).Msg("Server failed")
		}
	}()
	log.Info().Int("port", cfg.Port).Msg("org-host listening")

	<-ctx.Done()
	log.Info().Msg("Shutting down")
	if err := app.Shutdown(); err != nil {
		log.Error().Err(err).Msg("Server shutdown error")
	}
}
