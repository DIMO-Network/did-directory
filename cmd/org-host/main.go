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
	if err := cfg.Validate(); err != nil {
		log.Fatal().Err(err).Msg("Bad host URL")
	}
	var auth *orghost.JWKSAuthenticator
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
	// Accepted DPoP proofs are remembered in the database when there is one, so
	// every replica refuses a proof any of them accepted.
	var proofs store.ProofStore = store.NewMemoryProofs(store.DefaultMaxProofs)
	if pg, ok := st.(*store.PostgresStore); ok {
		proofs = pg
		go orghost.SweepProofs(ctx, pg, time.Minute, log)
	}
	if cfg.DPoPMaxProofsPerSubject < 0 {
		log.Fatal().Int("value", cfg.DPoPMaxProofsPerSubject).Msg("DPOP_MAX_PROOFS_PER_SUBJECT must be 0 (no limit) or more")
	}
	auth.UseProofStore(proofs, cfg.DPoPMaxProofsPerSubject, cfg.IssuerDIDs)

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
	for name, v := range map[string]int{
		"REGISTER_RATE_LIMIT_PER_MINUTE":            cfg.RegisterRateLimitPerMinute,
		"REGISTER_RATE_LIMIT_PER_CALLER_PER_MINUTE": cfg.RegisterRateLimitPerCallerPerMinute,
		"ORG_REGISTER_MAX_PER_DAY":                  cfg.RegisterMaxPerDay,
	} {
		if v < 0 {
			log.Fatal().Int("value", v).Msgf("%s must be 0 (no limit) or more", name)
		}
	}
	publicURL := cfg.HostURL()
	log.Info().Str("public_url", publicURL).Int("register_per_minute", cfg.RegisterRateLimitPerMinute).
		Int("register_per_caller_per_minute", cfg.RegisterRateLimitPerCallerPerMinute).Int("register_max_per_day", cfg.RegisterMaxPerDay).
		Msg("Orgs register here only if their DID names this URL as #dimo_org_host")

	// The commit policy profiles a role may name (plan §3.2). The booking
	// profile is registered here by name; what a booking is stays with the
	// booking service (decision F).
	booking := agreement.CommitPolicy()
	policies := orghost.Policies{booking.Name: booking}

	signers, err := orghost.BuildSigners(ctx, st, sealer, orghost.SignerConfig{Signer: cfg.Signer, AliasPrefix: cfg.KMSAliasPrefix},
		func(ctx context.Context) (orghost.KMSAPI, error) {
			awsCfg, err := config.LoadDefaultConfig(ctx, config.WithRegion(cfg.KMSRegion))
			if err != nil {
				return nil, err
			}
			return kms.NewFromConfig(awsCfg), nil
		})
	if err != nil {
		log.Fatal().Err(err).Msg("Failed to set up org signing keys")
	}
	log.Info().Str("signer", cfg.Signer).Bool("kms_client", signers.KMS != nil).Bool("local_signer", signers.Local != nil).
		Msg("New orgs register with this signer; existing orgs keep the backend their row names")
	repo := &orghost.Repository{Store: st, Signer: signers.Signer}
	directory := client.New(cfg.DirectoryURL)
	app := orghost.New(orghost.Options{
		Repo:                       repo,
		Auth:                       auth,
		Control:                    directory,
		Documents:                  directory,
		PublicURL:                  publicURL,
		RegisterPerMinute:          cfg.RegisterRateLimitPerMinute,
		RegisterPerCallerPerMinute: cfg.RegisterRateLimitPerCallerPerMinute,
		RegisterMaxPerDay:          cfg.RegisterMaxPerDay,
		Issuers:                    cfg.IssuerDIDs,
		Admins:                     cfg.AdminDIDs,
		Policies:                   policies,
		PageSize:                   cfg.PageSize,
		ControlCacheTTL:            controlTTL,
		Log:                        log,
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
