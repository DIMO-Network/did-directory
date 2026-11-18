package orghost

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/DIMO-Network/did-directory/internal/orghost/store"
	"github.com/DIMO-Network/did-directory/pkg/delegation"
	"github.com/DIMO-Network/did-directory/pkg/odrl"
	"github.com/gofiber/fiber/v2"
)

// listPending returns the org's writes awaiting approval that the caller may
// see: those they could read once committed, and those they hold the
// authority to approve (checkApprover). Approving is still checked per write.
func (s *Server) listPending(c *fiber.Ctx) error {
	org, _, _ := params(c)
	who := caller(c)
	r, err := s.reader(c.Context(), org, who)
	if err != nil {
		return s.fail(c, err)
	}
	pending, err := s.repo.Store.ListPending(c.Context(), org)
	if err != nil {
		return s.fail(c, err)
	}
	out := []store.Pending{}
	for i := range pending {
		p := &pending[i]
		uri := "at://" + org + "/" + p.Collection + "/" + p.RKey
		ok, err := r.canRead(c.Context(), uri, p.Collection, p.Record, p.CommittedBy)
		if err != nil {
			return s.fail(c, err)
		}
		if !ok {
			if ok, err = s.couldApprove(c.Context(), org, who, p); err != nil {
				return s.fail(c, err)
			}
		}
		if ok {
			out = append(out, *p)
		}
	}
	return c.JSON(fiber.Map{"pending": out})
}

// couldApprove reports whether member holds the authority an approver of p
// needs: the managing ability over a delegation's or role's scope, or
// tag:write over a membership's tag. The author-and-recipient exclusions are
// left to the approval itself.
func (s *Server) couldApprove(ctx context.Context, org, member string, p *store.Pending) (bool, error) {
	var scope delegation.Covers
	var need string
	switch p.Collection {
	case delegation.CollectionDelegation, delegation.CollectionRole:
		rec, err := odrl.Decode(p.Record)
		if err != nil {
			return false, err
		}
		scope, need = rec.Covers, delegation.ManageAbility(rec)
	case delegation.CollectionTagMembership:
		var m delegation.MembershipRecord
		if err := json.Unmarshal(p.Record, &m); err != nil {
			return false, err
		}
		scope, need = delegation.Covers{Tag: m.Tag}, delegation.AbilityTagWrite
	default:
		return false, nil
	}
	roles, err := s.evaluator().RolesCovering(ctx, org, member, scope, []string{need}, s.repo.now())
	return len(roles) > 0, err
}

// approve commits a pending write as approved by the caller (plan §3.2 step
// 4). The checks run again, now, with the approval carried: the author must
// still hold their authority, because the commit time is what evaluation
// checks it at, and the approver must hold the same authority and be neither
// the author nor the recipient.
func (s *Server) approve(c *fiber.Ctx) error {
	org, _, _ := params(c)
	id := strings.Clone(c.Params("id"))
	p, err := s.repo.Store.GetPending(c.Context(), org, id)
	if err != nil {
		return s.fail(c, err)
	}
	record, err := s.repo.Prepare(p.Org, p.Collection, p.RKey, p.Record, p.CommittedBy)
	if err != nil {
		return s.fail(c, err)
	}
	// Claim the pending write before committing it, so two approvers cannot
	// both commit it and a withdrawal cannot land between the check and the
	// commit. If the commit does not happen, the write goes back to waiting.
	if err := s.repo.Store.DeletePending(c.Context(), org, id); err != nil {
		return s.fail(c, err)
	}
	approver := caller(c)
	w := &write{org: p.Org, collection: p.Collection, rkey: p.RKey, record: record, committedBy: p.CommittedBy, approvedBy: approver}
	res, err := s.repo.Put(c.Context(), p.Org, p.Collection, p.RKey, record, p.CommittedBy, []string{approver}, func(ctx context.Context, _ *store.Stored) error {
		return s.checkWrite(ctx, w)
	})
	if err != nil {
		if rerr := s.repo.Store.AddPending(c.Context(), *p); rerr != nil {
			s.log.Error().Err(rerr).Str("pending", id).Msg("restoring a pending write after a failed approval")
		}
		return s.fail(c, err)
	}
	s.log.Info().Str("uri", res.URI).Str("op", res.Op).Str("by", p.CommittedBy).Str("approvedBy", approver).Msg("record committed with approval")
	status := fiber.StatusOK
	if res.Op == "create" {
		status = fiber.StatusCreated
	}
	return c.Status(status).JSON(res)
}

// withdraw drops a pending write. Its author may, and so may the org.
func (s *Server) withdraw(c *fiber.Ctx) error {
	org, _, _ := params(c)
	id := strings.Clone(c.Params("id"))
	p, err := s.repo.Store.GetPending(c.Context(), org, id)
	if err != nil {
		return s.fail(c, err)
	}
	if by := caller(c); by != org && by != p.CommittedBy {
		return s.fail(c, forbidden("only the author or the org may withdraw a pending write"))
	}
	if err := s.repo.Store.DeletePending(c.Context(), org, id); err != nil {
		return s.fail(c, err)
	}
	return c.JSON(fiber.Map{"withdrawn": id})
}

// revokeAuthoredByRequest is the body of POST /orgs/:org/revoke-authored-by
// (plan §3.5): the member and the time their key is suspected from, and, on
// the second call, the reviewed set to tombstone.
type revokeAuthoredByRequest struct {
	Member string `json:"member"`
	Since  string `json:"since"`
	// URIs is the reviewed set. Absent, the call only lists what the member
	// authored after since.
	URIs []string `json:"uris"`
}

// revokeAuthoredBy is the compromised-member procedure (spec §6.3): list every
// live record whose current version the member committed after since, and,
// when the caller sends the reviewed set back, tombstone it as one batch.
// Every tombstone in the batch is checked as a DELETE by the caller would be,
// all before any is written.
func (s *Server) revokeAuthoredBy(c *fiber.Ctx) error {
	org, _, _ := params(c)
	var req revokeAuthoredByRequest
	if err := c.BodyParser(&req); err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": fmt.Sprintf("invalid JSON: %v", err)})
	}
	req.Member = strings.Clone(req.Member)
	for i := range req.URIs {
		req.URIs[i] = strings.Clone(req.URIs[i])
	}
	if !isDID(req.Member) {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "member must be a DID"})
	}
	since, err := parseSince(req.Since)
	if err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": err.Error()})
	}
	r, err := s.reader(c.Context(), org, caller(c))
	if err != nil {
		return s.fail(c, err)
	}
	all, err := s.repo.Store.Authored(c.Context(), org, req.Member, since)
	if err != nil {
		return s.fail(c, err)
	}
	// The caller sees, and may send back, only what they could read.
	authored := []store.Stored{}
	for i := range all {
		ok, err := r.canReadStored(c.Context(), &all[i])
		if err != nil {
			return s.fail(c, err)
		}
		if ok {
			authored = append(authored, all[i])
		}
	}
	if req.URIs == nil {
		return c.JSON(fiber.Map{"records": authored})
	}

	byURI := map[string]*store.Stored{}
	for i := range authored {
		byURI[authored[i].URI] = &authored[i]
	}
	batch := make([]*store.Stored, 0, len(req.URIs))
	for _, uri := range req.URIs {
		st, ok := byURI[uri]
		if !ok {
			return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": fmt.Sprintf("%s is not a live record %s authored after %s", uri, req.Member, req.Since)})
		}
		if err := s.checkTombstone(c.Context(), org, caller(c), st); err != nil {
			return s.fail(c, fmt.Errorf("%s: %w", uri, err))
		}
		batch = append(batch, st)
	}

	// One append: every tombstone commits or none does. Each is checked again
	// under the org's write lock, as a DELETE by the caller would be; one that
	// somebody else already tombstoned is skipped, since the outcome is the one
	// asked for.
	keys := make([]Key, len(batch))
	for i, st := range batch {
		keys[i] = Key{Collection: st.Collection, RKey: st.RKey}
	}
	who := caller(c)
	revoked, err := s.repo.DeleteAll(c.Context(), org, keys, committedBy(c, org), func(ctx context.Context, curs []*store.Stored) error {
		for _, cur := range curs {
			if err := s.checkTombstone(ctx, org, who, cur); err != nil {
				return fmt.Errorf("%s: %w", cur.URI, err)
			}
		}
		return nil
	})
	if err != nil {
		return s.fail(c, err)
	}
	s.log.Info().Str("org", org).Str("member", req.Member).Str("since", req.Since).Int("revoked", len(revoked)).Str("by", caller(c)).Msg("revoked records authored by member")
	return c.JSON(fiber.Map{"revoked": revoked})
}
