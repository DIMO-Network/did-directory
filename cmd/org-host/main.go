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
	"strings"
	"syscall"
	"time"

	"github.com/DIMO-Network/did-directory/internal/orghost"
	"github.com/DIMO-Network/did-directory/internal/orghost/store"
	"github.com/DIMO-Network/did-directory/pkg/agreement"
	"github.com/DIMO-Network/did-directory/pkg/client"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/kms"
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

	if cfg.Signer != "local" && cfg.Signer != "kms" {
		log.Fatal().Str("value", cfg.Signer).Msg("ORG_SIGNER must be local or kms")
	}
	if cfg.Signer == "kms" && !strings.HasPrefix(cfg.KMSAliasPrefix, "alias/") {
		log.Fatal().Str("value", cfg.KMSAliasPrefix).Msg("KMS_ALIAS_PREFIX must start with alias/")
	}

	var st store.Store
	var sealer *orghost.Sealer
	if cfg.DatabaseURL != "" {
		// Orgs registered under the local signer stay sealed under MASTER_KEY, so
		// it is required unless ORG_SIGNER=kms and the store holds no such org
		// (checked once the store is open).
		if cfg.MasterKey == "" && cfg.Signer == "local" {
			log.Fatal().Msg("MASTER_KEY is required with DATABASE_URL: org signing keys are sealed at rest")
		}
		if cfg.MasterKey != "" {
			masterKey, err := base64.StdEncoding.DecodeString(cfg.MasterKey)
			if err != nil {
				log.Fatal().Err(err).Msg("MASTER_KEY must be base64")
			}
			if sealer, err = orghost.NewSealer(masterKey); err != nil {
				log.Fatal().Err(err).Msg("Bad MASTER_KEY")
			}
		} else {
			log.Warn().Msg("No MASTER_KEY: this host runs KMS-only")
		}
		pg, err := store.NewPostgresStore(ctx, cfg.DatabaseURL, log)
		if err != nil {
			log.Fatal().Err(err).Msg("Failed to connect to PostgreSQL")
		}
		defer func() { _ = pg.Close() }()
		st = pg
		if sealer == nil {
			has, err := pg.HasLocalOrgs(ctx)
			if err != nil {
				log.Fatal().Err(err).Msg("Failed to check for orgs with local signing keys")
			}
			if has {
				log.Fatal().Msg("MASTER_KEY is required: this host has orgs with local signing keys")
			}
		}
		log.Info().Msg("Using PostgreSQL store")
	} else {
		if sealer, err = orghost.NewEphemeralSealer(); err != nil {
			log.Fatal().Err(err).Msg("Failed to create sealer")
		}
		st = store.NewMemoryStore()
		log.Warn().Msg("Using in-memory store (no DATABASE_URL configured): org keys do not outlive this process")
	}

	if cfg.IdentityIssuer == "" || cfg.IdentityAudience == "" {
		log.Fatal().Msg("IDENTITY_ISSUER and IDENTITY_AUDIENCE are required: a token for another service must not write here")
	}
	var auth orghost.Authenticator
	switch {
	case cfg.IdentityJWKSURL != "":
		auth, err = orghost.NewJWKSAuthenticatorFromURL(ctx, cfg.IdentityJWKSURL, cfg.IdentityIssuer, cfg.IdentityAudience)
	case cfg.IdentityJWKS != "":
		auth, err = orghost.NewJWKSAuthenticator([]byte(cfg.IdentityJWKS), cfg.IdentityIssuer, cfg.IdentityAudience)
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
	if cfg.RegisterRateLimitPerMinute < 0 {
		log.Fatal().Int("value", cfg.RegisterRateLimitPerMinute).Msg("REGISTER_RATE_LIMIT_PER_MINUTE must be 0 (no limit) or more")
	}
	publicURL := cfg.HostURL()
	log.Info().Str("public_url", publicURL).Int("register_per_minute", cfg.RegisterRateLimitPerMinute).
		Msg("Orgs register here only if their DID names this URL as #dimo_org_host")

	// The commit policy profiles a role may name (plan §3.2). The booking
	// profile is registered here by name; what a booking is stays with the
	// booking service (decision F).
	booking := agreement.CommitPolicy()
	policies := orghost.Policies{booking.Name: booking}

	var local *orghost.LocalSigner
	if sealer != nil {
		local = orghost.NewLocalSigner(st, sealer)
	}
	var kmsSigner *orghost.KMSSigner
	registerWith := orghost.Registrar(local)
	if cfg.Signer == "kms" {
		awsCfg, err := config.LoadDefaultConfig(ctx, config.WithRegion(cfg.KMSRegion))
		if err != nil {
			log.Fatal().Err(err).Msg("Failed to load AWS config")
		}
		kmsSigner = orghost.NewKMSSigner(st, kms.NewFromConfig(awsCfg), cfg.KMSAliasPrefix)
		registerWith = kmsSigner
	}
	log.Info().Str("signer", cfg.Signer).Msg("New orgs register with this signer")
	repo := &orghost.Repository{Store: st, Signer: orghost.NewRoutingSigner(st, local, kmsSigner, registerWith)}
	directory := client.New(cfg.DirectoryURL)
	app := orghost.New(orghost.Options{
		Repo:              repo,
		Auth:              auth,
		Control:           directory,
		Documents:         directory,
		PublicURL:         publicURL,
		RegisterPerMinute: cfg.RegisterRateLimitPerMinute,
		Issuers:           cfg.IssuerDIDs,
		Admins:            cfg.AdminDIDs,
		Policies:          policies,
		PageSize:          cfg.PageSize,
		ControlCacheTTL:   controlTTL,
		Log:               log,
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
