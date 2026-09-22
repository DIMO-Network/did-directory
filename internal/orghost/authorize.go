package orghost

import (
	"errors"
	"fmt"
	"slices"
	"strings"
	"time"

	"github.com/DIMO-Network/did-directory/internal/orghost/store"
	"github.com/DIMO-Network/did-directory/pkg/delegation"
	"github.com/gofiber/fiber/v2"
)

// AuthorizeRequest is the body of POST /authorize (plan §3.3): the delegation
// the caller is exercising, who they are, over which vehicle, for what.
type AuthorizeRequest struct {
	URI       string   `json:"uri"`
	Caller    string   `json:"caller"`
	ClientID  string   `json:"clientId,omitempty"`
	Vehicle   string   `json:"vehicle"`
	Abilities []string `json:"abilities"`
	// At is refused in v1: evaluation is at the host clock, and nobody is yet
	// allowed to ask about the past.
	At *time.Time `json:"at,omitempty"`
}

// AuthorizeResponse is delegation.Coverage plus the time it was evaluated at,
// which is what the issuer sets a token's lifetime from.
type AuthorizeResponse struct {
	*delegation.Coverage
	At time.Time `json:"at"`
}

// Refusal codes on a 403 from /authorize. They are the evaluator's errors by
// name, so the issuer can tell "somebody is driving" from "never granted"
// without parsing prose.
const (
	CodeNotCovered       = "not_covered"
	CodeExclusiveHold    = "exclusive_hold"
	CodeUnauthorized     = "unauthorized"
	CodeRevoked          = "revoked"
	CodeNotValid         = "not_valid"
	CodeClientNotAllowed = "client_not_allowed"
	CodeNotNarrowing     = "not_narrowing"
	CodeChainTooDeep     = "chain_too_deep"
	CodeLienNotAllowed   = "lien_not_allowed"
	CodeSelfDealing      = "self_dealing"
	CodeExceedsRole      = "exceeds_role"
	// CodeDenied is any other evaluation refusal: an invalid record in the
	// chain, an author who lacked authority, a cycle.
	CodeDenied = "denied"
)

var refusalCodes = []struct {
	err  error
	code string
}{
	{delegation.ErrExclusiveHold, CodeExclusiveHold},
	{delegation.ErrNotCovered, CodeNotCovered},
	{delegation.ErrUnauthorized, CodeUnauthorized},
	{delegation.ErrRevoked, CodeRevoked},
	{delegation.ErrNotValid, CodeNotValid},
	{delegation.ErrClientNotAllowed, CodeClientNotAllowed},
	{delegation.ErrNotNarrowing, CodeNotNarrowing},
	{delegation.ErrChainTooDeep, CodeChainTooDeep},
	{delegation.ErrLienNotAllowed, CodeLienNotAllowed},
	{delegation.ErrSelfDealing, CodeSelfDealing},
	{delegation.ErrExceedsRole, CodeExceedsRole},
}

// authorize runs the evaluator for the issuer (plan §1 decision A). The caller
// is dauth, authenticated as one of the configured issuer DIDs; the principal
// being authorized is in the body, because dauth is the one that authenticated
// them.
func (s *Server) authorize(c *fiber.Ctx) error {
	if !s.issuers[caller(c)] {
		return c.Status(fiber.StatusForbidden).JSON(fiber.Map{"error": "only a configured issuer may call /authorize"})
	}
	var req AuthorizeRequest
	if err := c.BodyParser(&req); err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": fmt.Sprintf("invalid JSON: %v", err)})
	}
	if err := req.validate(); err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": err.Error()})
	}
	req.own()

	at := s.repo.now()
	ev := &delegation.Evaluator{Resolver: s.resolver}
	cov, err := ev.Authorize(c.Context(), req.URI, req.Caller, req.ClientID, req.Vehicle, req.Abilities, at)
	if err != nil {
		return s.refuse(c, &req, err)
	}
	log := s.log.Info().Str("uri", req.URI).Str("caller", req.Caller).Str("vehicle", req.Vehicle).Strs("abilities", req.Abilities)
	if cov.RecoveryUsed {
		// The one operation that overrides somebody's custody (§12.2); the issuer
		// logs it too, but the host is where the record of it is kept.
		log = log.Bool("recoveryUsed", true)
	}
	log.Msg("authorized")
	return c.JSON(AuthorizeResponse{Coverage: cov, At: at})
}

func (r *AuthorizeRequest) validate() error {
	if _, _, _, err := delegation.ParseURI(r.URI); err != nil {
		return fmt.Errorf("uri: %w", err)
	}
	if !isDID(r.Caller) {
		return errors.New("caller must be a DID")
	}
	if !isDID(r.Vehicle) {
		return errors.New("vehicle must be a DID")
	}
	if len(r.Abilities) == 0 {
		return errors.New("abilities must not be empty")
	}
	if slices.Contains(r.Abilities, "") {
		return errors.New("abilities must not contain an empty string")
	}
	if r.At != nil {
		return errors.New("at is not accepted: evaluation is at the host clock")
	}
	return nil
}

// own copies the strings out of Fiber's request buffer, since they end up in
// log lines and error messages after the handler returns.
func (r *AuthorizeRequest) own() {
	r.URI, r.Caller, r.ClientID, r.Vehicle = strings.Clone(r.URI), strings.Clone(r.Caller), strings.Clone(r.ClientID), strings.Clone(r.Vehicle)
	for i := range r.Abilities {
		r.Abilities[i] = strings.Clone(r.Abilities[i])
	}
}

// refuse maps an evaluation error to a response: 404 for a record that is not
// here, 500 when the host could not read what it needed, and otherwise 403
// with a code the issuer can act on.
func (s *Server) refuse(c *fiber.Ctx, req *AuthorizeRequest, err error) error {
	switch {
	case store.IsNotFound(err):
		return c.Status(fiber.StatusNotFound).JSON(fiber.Map{"error": err.Error(), "code": "not_found"})
	case errors.Is(err, ErrResolve):
		s.log.Error().Err(err).Str("uri", req.URI).Msg("authorize: resolver failed")
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "internal error"})
	}
	body := fiber.Map{"error": err.Error(), "code": CodeDenied}
	for _, rc := range refusalCodes {
		if errors.Is(err, rc.err) {
			body["code"] = rc.code
			break
		}
	}
	var hold *delegation.ExclusiveHoldError
	if errors.As(err, &hold) {
		body["suspended"] = hold.Suspended
	}
	s.log.Info().Str("uri", req.URI).Str("caller", req.Caller).Str("vehicle", req.Vehicle).Str("code", body["code"].(string)).Msg("authorize refused")
	return c.Status(fiber.StatusForbidden).JSON(body)
}

// partyBody is the JSON shape of a party over HTTP.
type partyBody struct {
	Kind     string `json:"kind"`
	Operator bool   `json:"operator"`
}

func (s *Server) getParty(c *fiber.Ctx) error {
	did := strings.Clone(c.Params("did"))
	p, err := s.repo.Store.GetParty(c.Context(), did)
	if err != nil {
		return s.fail(c, err)
	}
	return c.JSON(p)
}

// setParty records DIMO's attestation of a DID's kind and operator status.
func (s *Server) setParty(c *fiber.Ctx) error {
	if !s.admins[caller(c)] {
		return c.Status(fiber.StatusForbidden).JSON(fiber.Map{"error": "only a configured admin may set party attributes"})
	}
	did := strings.Clone(c.Params("did"))
	if !isDID(did) {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "party must be a DID"})
	}
	var body partyBody
	if err := c.BodyParser(&body); err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": fmt.Sprintf("invalid JSON: %v", err)})
	}
	if body.Kind != store.KindPerson && body.Kind != store.KindOrg {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "kind must be person or org"})
	}
	p := store.Party{DID: did, Kind: strings.Clone(body.Kind), Operator: body.Operator, SetAt: s.repo.now()}
	if err := s.repo.Store.SetParty(c.Context(), p); err != nil {
		return s.fail(c, err)
	}
	s.log.Info().Str("did", did).Str("kind", p.Kind).Bool("operator", p.Operator).Str("by", caller(c)).Msg("party set")
	return c.JSON(p)
}
