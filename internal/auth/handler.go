package auth

import (
	"context"
	"errors"
	"time"

	dimocrypto "github.com/DIMO-Network/did-directory/internal/crypto"
	"github.com/DIMO-Network/did-directory/pkg/client"
	"github.com/DIMO-Network/did-directory/pkg/sacd"
	"github.com/gofiber/fiber/v2"
	"github.com/rs/zerolog"
)

// Handler holds the auth service's dependencies.
type Handler struct {
	challenges  *ChallengeStore
	tokenSigner *TokenSigner
	dirClient   *client.Client
	log         zerolog.Logger
}

// NewHandler creates a new auth handler.
func NewHandler(challenges *ChallengeStore, tokenSigner *TokenSigner, dirClient *client.Client, log zerolog.Logger) *Handler {
	return &Handler{
		challenges:  challenges,
		tokenSigner: tokenSigner,
		dirClient:   dirClient,
		log:         log.With().Str("component", "auth_handler").Logger(),
	}
}

// HandleChallenge handles GET /v1/challenge.
func (h *Handler) HandleChallenge(c *fiber.Ctx) error {
	nonce, expiresAt, err := h.challenges.Generate()
	if err != nil {
		h.log.Error().Err(err).Msg("Failed to generate challenge")
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
			"error": "failed to generate challenge",
		})
	}

	return c.JSON(fiber.Map{
		"challenge": nonce,
		"expiresAt": expiresAt.Format(time.RFC3339),
	})
}

// AuthRequest is the body for POST /v1/auth.
type AuthRequest struct {
	DID       string          `json:"did"`
	Challenge string          `json:"challenge"`
	Signature string          `json:"signature"`
	SACDs     []sacd.Document `json:"sacds"`
	Audience  []string        `json:"audience"`
}

// HandleAuth handles POST /v1/auth.
func (h *Handler) HandleAuth(c *fiber.Ctx) error {
	var req AuthRequest
	if err := c.BodyParser(&req); err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"error": "invalid request body",
		})
	}

	// Validate challenge.
	challengeBytes, err := h.challenges.Consume(req.Challenge)
	if err != nil {
		return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{
			"error": "invalid or expired challenge: " + err.Error(),
		})
	}

	ctx := context.Background()

	// Resolve developer DID.
	devDoc, err := h.dirClient.Resolve(ctx, req.DID)
	if err != nil {
		h.log.Error().Err(err).Str("did", req.DID).Msg("Failed to resolve developer DID")
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"error": "failed to resolve developer DID: " + err.Error(),
		})
	}

	if len(devDoc.VerificationMethod) == 0 {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"error": "developer DID has no verification methods",
		})
	}

	// Verify the challenge signature against every verification method the DID
	// publishes. Taking only the first one makes a developer with two keys
	// authenticate or get a 401 depending on the resolve's map ordering.
	var sigErr error = errors.New("no verification method matched the signature")
	verified := false
	for _, vm := range devDoc.VerificationMethod {
		if err := dimocrypto.VerifyWithDIDKey("did:key:"+vm.PublicKeyMultibase, challengeBytes, req.Signature); err == nil {
			verified = true
			break
		} else {
			sigErr = err
		}
	}
	if !verified {
		return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{
			"error": "challenge signature verification failed: " + sigErr.Error(),
		})
	}

	// Validate each SACD.
	var assets []AssetClaim
	for i := range req.SACDs {
		sacdDoc := &req.SACDs[i]

		// The challenge proves only that the caller controls req.DID. Without this
		// an SACD is a bearer token: anyone who copies one out of a log, a file or
		// a support ticket mints a JWT carrying the asset's permissions.
		if sacdDoc.Grantee != req.DID {
			return c.Status(fiber.StatusForbidden).JSON(fiber.Map{
				"error":      "SACD was not granted to the authenticated DID",
				"sacd_index": i,
				"grantee":    sacdDoc.Grantee,
			})
		}

		if err := ValidateSACD(ctx, h.dirClient, sacdDoc); err != nil {
			return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
				"error":      "SACD validation failed",
				"sacd_index": i,
				"detail":     err.Error(),
			})
		}

		storage := StorageFromDoc(ctx, h.dirClient, sacdDoc.Asset)

		assets = append(assets, AssetClaim{
			DID:         sacdDoc.Asset,
			Permissions: sacdDoc.Permissions,
			Storage:     storage,
		})
	}

	// Generate JWT.
	token, err := h.tokenSigner.Sign(req.DID, assets, req.Audience)
	if err != nil {
		h.log.Error().Err(err).Msg("Failed to sign JWT")
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
			"error": "failed to generate token",
		})
	}

	h.log.Info().
		Str("sub", req.DID).
		Int("assets", len(assets)).
		Msg("Token issued")

	return c.JSON(fiber.Map{
		"token": token,
	})
}

// HandleJWKS handles GET /.well-known/jwks.json.
func (h *Handler) HandleJWKS(c *fiber.Ctx) error {
	return c.JSON(h.tokenSigner.JWKS())
}
