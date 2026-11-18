package orghost

import (
	"errors"
	"strings"

	"github.com/DIMO-Network/did-directory/internal/orghost/store"
	"github.com/DIMO-Network/did-directory/pkg/delegation"
	"github.com/gofiber/fiber/v2"
)

// HeldRole is one entry of GET /me/roles: a role the caller holds, and the
// org it is held in.
type HeldRole struct {
	Org string `json:"org"`
	store.Stored
}

// myRoles serves GET /me/roles: the roles the caller holds now, in every org
// on this host. Every other route starts from an org, and members are not
// listed in DID documents (spec §6.3), so without this a member has no way to
// learn which orgs to ask. Only roles the evaluator holds live are listed, in
// orgs that can have members, which a reader requires too.
func (s *Server) myRoles(c *fiber.Ctx) error {
	me := caller(c)
	assigned, err := s.repo.Store.Assigned(c.Context(), delegation.CollectionRole, me)
	if err != nil {
		return s.fail(c, err)
	}
	at := s.repo.now()
	ev := s.evaluator()
	out := []HeldRole{}
	for i := 0; i < len(assigned); {
		org, _, _, err := delegation.ParseURI(assigned[i].URI)
		if err != nil {
			return s.fail(c, err)
		}
		j := i
		for j < len(assigned) && strings.HasPrefix(assigned[j].URI, "at://"+org+"/") {
			j++
		}
		inOrg := assigned[i:j]
		i = j

		party, err := s.resolver.Party(c.Context(), org)
		if err != nil {
			return s.fail(c, err)
		}
		if !party.CanHaveMembers() {
			continue
		}
		held, err := ev.HeldRoles(c.Context(), org, me, at)
		if err != nil {
			return s.fail(c, err)
		}
		live := map[string]bool{}
		for k := range held {
			live[held[k].URI] = true
		}
		for k := range inOrg {
			if live[inOrg[k].URI] {
				out = append(out, HeldRole{Org: org, Stored: inOrg[k]})
			}
		}
	}
	return c.JSON(fiber.Map{"at": at, "roles": out})
}

// Inbound is one entry of GET /me/delegations: a delegation addressed to the
// caller and, when a vehicle was asked about, what it gives over that vehicle
// now, with Refused saying why when it gives nothing.
type Inbound struct {
	store.Stored
	Coverage *delegation.Coverage `json:"coverage,omitempty"`
	Refused  string               `json:"refused,omitempty"`
}

// myDelegations serves GET /me/delegations[?vehicle=]: the delegations, from
// every repository on this host, whose assignee is the caller. A delegation
// gives something only over a vehicle, so without ?vehicle= the records are
// listed as stored, tombstones included, since whether a tombstone counts is
// the evaluator's call. With it, each is resolved over that vehicle as
// /descendants does. A coverage proof (GET .../proof) is still how a grantee
// shows a third party what it holds.
func (s *Server) myDelegations(c *fiber.Ctx) error {
	me := caller(c)
	vehicle := strings.Clone(c.Query("vehicle"))
	if vehicle != "" && !isDID(vehicle) {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "vehicle must be a DID"})
	}
	assigned, err := s.repo.Store.Assigned(c.Context(), delegation.CollectionDelegation, me)
	if err != nil {
		return s.fail(c, err)
	}
	at := s.repo.now()
	ev := s.evaluator()
	out := make([]Inbound, 0, len(assigned))
	for i := range assigned {
		in := Inbound{Stored: assigned[i]}
		if vehicle != "" {
			cov, err := ev.Coverage(c.Context(), assigned[i].URI, vehicle, at)
			switch {
			case err == nil:
				in.Coverage = cov
			case errors.Is(err, ErrResolve):
				return s.fail(c, err)
			default:
				in.Refused = codeOf(err)
			}
		}
		out = append(out, in)
	}
	resp := fiber.Map{"at": at, "delegations": out}
	if vehicle != "" {
		resp["vehicle"] = vehicle
	}
	return c.JSON(resp)
}
