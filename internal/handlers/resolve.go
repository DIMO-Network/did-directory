package handlers

import (
	"context"
	"errors"

	"github.com/DIMO-Network/did-directory/internal/did"
	"github.com/DIMO-Network/did-directory/internal/store"
	"github.com/DIMO-Network/did-directory/pkg/control"
	"github.com/gofiber/fiber/v2"
	"github.com/rs/zerolog"
)

// ResolveHandler handles GET /:did for DID resolution, GET /:did/data for raw state,
// and GET /:did/control for control era history.
//
// Each reads the DID's head first and the whole log only when the answer needs
// the era history. An uncontrolled, live DID (a person or an org, which dauth
// resolves at every sign-in) is answered from one row on all three paths, and
// resolve and /data answer a tombstone 410 from one row. /control on a
// tombstone reads the log, since the tombstone may close a controlled DID's
// last era, and answers 200 with deactivated set. The store keeps no era
// summary, so a controlled DID still reads its whole log;
// MAX_OPERATIONS_PER_DID and did.MaxOperationBytes bound it.
type ResolveHandler struct {
	store store.Store
	log   zerolog.Logger
}

// NewResolveHandler creates a new ResolveHandler.
func NewResolveHandler(s store.Store, log zerolog.Logger) *ResolveHandler {
	return &ResolveHandler{
		store: s,
		log:   log.With().Str("handler", "resolve").Logger(),
	}
}

// HandleResolve returns the W3C DID Document for a given DID.
func (h *ResolveHandler) HandleResolve(c *fiber.Ctx) error {
	didParam := c.Params("did")

	head, err := h.store.GetLatest(c.Context(), didParam)
	if store.IsNotFound(err) {
		return notFound(c)
	}
	if err != nil {
		h.log.Error().Err(err).Str("did", didParam).Msg("Failed to resolve DID")
		return internalError(c)
	}
	if head.Operation.IsTombstone() {
		return gone(c, didParam)
	}

	latest, state, err := h.withState(c.Context(), didParam, head)
	if err != nil {
		h.log.Error().Err(err).Str("did", didParam).Msg("Failed to resolve DID")
		return internalError(c)
	}

	doc, err := did.GenerateDocument(didParam, &latest.Operation, state)
	if errors.Is(err, did.ErrDeactivated) {
		return c.Status(fiber.StatusGone).JSON(fiber.Map{
			"error": err.Error(),
		})
	}
	if err != nil {
		// The head does not make a document (a key that does not decode, in a
		// row stored before updates were checked). The DID is unusable, not
		// deactivated, and callers must not read it as a tombstone.
		return c.Status(fiber.StatusUnprocessableEntity).JSON(fiber.Map{
			"error": err.Error(),
		})
	}

	return c.JSON(doc)
}

// HandleData returns the raw PLC state data for a DID.
func (h *ResolveHandler) HandleData(c *fiber.Ctx) error {
	didParam := c.Params("did")

	head, err := h.store.GetLatest(c.Context(), didParam)
	if store.IsNotFound(err) {
		return notFound(c)
	}
	if err != nil {
		h.log.Error().Err(err).Str("did", didParam).Msg("Failed to get DID data")
		return internalError(c)
	}
	if head.Operation.IsTombstone() {
		return gone(c, didParam)
	}

	latest, state, err := h.withState(c.Context(), didParam, head)
	if err != nil {
		h.log.Error().Err(err).Str("did", didParam).Msg("Failed to get DID data")
		return internalError(c)
	}
	if latest.Operation.IsTombstone() {
		// Deactivated between the two reads.
		return gone(c, didParam)
	}

	return c.JSON(fiber.Map{
		"did":                 latest.DID,
		"cid":                 latest.CID,
		"rotationKeys":        latest.Operation.RotationKeys,
		"verificationMethods": latest.Operation.VerificationMethods,
		"alsoKnownAs":         latest.Operation.AlsoKnownAs,
		"services":            latest.Operation.Services,
		"controlCommitment":   latest.Operation.ControlCommitment,
		"eras":                state.Eras,
		"createdAt":           latest.CreatedAt,
	})
}

// HandleControl returns the control era history of a DID. Uncontrolled DIDs
// return an empty era list.
func (h *ResolveHandler) HandleControl(c *fiber.Ctx) error {
	didParam := c.Params("did")

	head, err := h.store.GetLatest(c.Context(), didParam)
	if store.IsNotFound(err) {
		return notFound(c)
	}
	if err != nil {
		h.log.Error().Err(err).Str("did", didParam).Msg("Failed to get DID control state")
		return internalError(c)
	}

	_, state, err := h.withState(c.Context(), didParam, head)
	if err != nil {
		h.log.Error().Err(err).Str("did", didParam).Msg("Failed to get DID control state")
		return internalError(c)
	}
	return c.JSON(state)
}

// withState returns the control state that goes with head, and the head it
// was resolved with. An uncontrolled, live head needs no log: only a genesis
// with a commitment opens an era, and ValidateTransition never lets an update
// add a commitment to an uncontrolled DID, so it has no eras. Any other head
// (controlled, or a tombstone, which may close a controlled DID's last era)
// needs the era history, which only the whole log holds; the log's own head
// is returned with it so that the two agree.
func (h *ResolveHandler) withState(ctx context.Context, didStr string, head *store.OperationRecord) (*store.OperationRecord, *control.State, error) {
	if !head.Operation.IsTombstone() && !head.Operation.IsControlled() {
		return head, &control.State{DID: didStr, Eras: []control.Era{}}, nil
	}
	records, err := h.store.GetLog(ctx, didStr)
	if err != nil {
		return nil, nil, err
	}
	if len(records) == 0 {
		return nil, nil, errors.New("operation log is empty after its head was read")
	}
	return &records[len(records)-1], resolveControlState(didStr, records), nil
}

func notFound(c *fiber.Ctx) error {
	return c.Status(fiber.StatusNotFound).JSON(fiber.Map{
		"error": "DID not found",
	})
}

func gone(c *fiber.Ctx, didStr string) error {
	return c.Status(fiber.StatusGone).JSON(fiber.Map{
		"error": "DID " + didStr + " has been deactivated",
	})
}

func internalError(c *fiber.Ctx) error {
	return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
		"error": "internal error",
	})
}

func resolveControlState(didStr string, records []store.OperationRecord) *control.State {
	ops := make([]did.Operation, len(records))
	for i, r := range records {
		ops[i] = r.Operation
	}
	return did.ResolveControlState(didStr, ops)
}
