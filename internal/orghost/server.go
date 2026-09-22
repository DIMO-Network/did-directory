package orghost

import (
	"crypto/ecdsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"strconv"
	"strings"

	"github.com/DIMO-Network/did-directory/internal/orghost/store"
	"github.com/DIMO-Network/did-directory/pkg/repo"
	"github.com/gofiber/fiber/v2"
	"github.com/gofiber/fiber/v2/middleware/cors"
	"github.com/gofiber/fiber/v2/middleware/recover"
	"github.com/gofiber/fiber/v2/middleware/requestid"
	"github.com/rs/zerolog"
)

// Server serves org repositories over HTTP (plan §3).
//
// Every route but /health needs an identity token. Under /orgs the org itself
// may do anything to its own repository; anyone else is a member only through
// a live role, and each write takes the role and ability plan §3.2 names,
// passes delegation.CheckCommit under that role's policy, and lands as
// pending when the policy wants a second approval. /authorize is for the
// issuer (dauth) and /parties for DIMO, each an allowlist of DIDs.
type Server struct {
	repo     *Repository
	auth     Authenticator
	resolver *Resolver
	policies Policies
	issuers  map[string]bool
	admins   map[string]bool
	pageSize int
	log      zerolog.Logger
}

// Options configures a Server.
type Options struct {
	Repo *Repository
	Auth Authenticator
	// Control is where control state comes from: the DID directory.
	Control ControlSource
	// Issuers are the DIDs that may call POST /authorize (plan §3.3): dauth.
	Issuers []string
	// Admins are the DIDs that may set party attributes (plan §1 decision E).
	Admins []string
	// Policies are the commit policy profiles a role may name; the default
	// profile is always present.
	Policies Policies
	// PageSize bounds list and log responses; zero means 100.
	PageSize int
	Log      zerolog.Logger
}

// New builds the Fiber app.
func New(o Options) *fiber.App {
	if o.PageSize <= 0 {
		o.PageSize = 100
	}
	set := func(dids []string) map[string]bool {
		m := map[string]bool{}
		for _, d := range dids {
			if d != "" {
				m[d] = true
			}
		}
		return m
	}
	policies := DefaultPolicies()
	for name, p := range o.Policies {
		policies[name] = p
	}
	s := &Server{
		repo: o.Repo, auth: o.Auth,
		resolver: &Resolver{Store: o.Repo.Store, Control: o.Control, Now: o.Repo.now},
		policies: policies,
		issuers:  set(o.Issuers), admins: set(o.Admins),
		pageSize: o.PageSize, log: o.Log.With().Str("component", "orghost").Logger(),
	}

	app := fiber.New(fiber.Config{AppName: "org-host", DisableStartupMessage: true})
	app.Use(recover.New())
	app.Use(requestid.New())
	app.Use(cors.New())

	app.Get("/health", func(c *fiber.Ctx) error {
		return c.JSON(fiber.Map{"status": "ok"})
	})

	app.Post("/authorize", s.authenticate, s.authorize)
	parties := app.Group("/parties", s.authenticate)
	parties.Get("/:did", s.getParty)
	parties.Put("/:did", s.setParty)

	orgs := app.Group("/orgs", s.authenticate)
	orgs.Post("/:org", s.register)
	orgs.Get("/:org", s.getOrg)
	// Before /:org/:collection, which would otherwise capture them.
	orgs.Get("/:org/commits", s.commits)
	orgs.Get("/:org/pending", s.listPending)
	orgs.Post("/:org/pending/:id/approve", s.approve)
	orgs.Delete("/:org/pending/:id", s.withdraw)
	orgs.Post("/:org/revoke-authored-by", s.revokeAuthoredBy)
	orgs.Post("/:org/:collection", s.create)
	orgs.Get("/:org/:collection", s.list)
	orgs.Put("/:org/:collection/:rkey", s.put)
	orgs.Get("/:org/:collection/:rkey", s.get)
	orgs.Delete("/:org/:collection/:rkey", s.tombstone)
	return app
}

const callerKey = "caller"

// authenticate resolves the caller's DID into c.Locals(callerKey).
func (s *Server) authenticate(c *fiber.Ctx) error {
	did, err := s.auth.Authenticate(c.Context(), c.Get(fiber.HeaderAuthorization))
	if err != nil {
		return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{"error": err.Error()})
	}
	c.Locals(callerKey, strings.Clone(did))
	return c.Next()
}

func caller(c *fiber.Ctx) string {
	did, _ := c.Locals(callerKey).(string)
	return did
}

// committedBy is what the commit records for this caller: "" when the org
// writes as itself (plan §3.2), the member DID otherwise.
func committedBy(c *fiber.Ctx, org string) string {
	if did := caller(c); did != org {
		return did
	}
	return ""
}

// params returns the org, collection and rkey route params as owned strings.
// Fiber params alias a reused request buffer, and these end up inside commits.
func params(c *fiber.Ctx) (org, collection, rkey string) {
	return strings.Clone(c.Params("org")), strings.Clone(c.Params("collection")), strings.Clone(c.Params("rkey"))
}

// register puts an org on this host. Only the org itself may do it: this is
// where its signing key is born, and in v1 an identity token for the org DID is
// the proof the directory-level check (does #dimo_org match) will join in step 3.
func (s *Server) register(c *fiber.Ctx) error {
	org, _, _ := params(c)
	if caller(c) != org {
		return c.Status(fiber.StatusForbidden).JSON(fiber.Map{"error": "only the org itself may register its repository"})
	}
	var body struct {
		// PrivateKey is an optional PKCS#8 key in base64, for an org whose key
		// was generated elsewhere (dimocli create --org keeps one).
		PrivateKey string `json:"privateKey"`
	}
	if len(c.Body()) > 0 {
		if err := json.Unmarshal(c.Body(), &body); err != nil {
			return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": fmt.Sprintf("invalid JSON: %v", err)})
		}
	}
	var key *ecdsa.PrivateKey
	if body.PrivateKey != "" {
		der, err := base64.StdEncoding.DecodeString(body.PrivateKey)
		if err != nil {
			return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "privateKey must be base64 PKCS#8"})
		}
		parsed, err := x509.ParsePKCS8PrivateKey(der)
		if err != nil {
			return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": fmt.Sprintf("privateKey: %v", err)})
		}
		var ok bool
		if key, ok = parsed.(*ecdsa.PrivateKey); !ok {
			return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "privateKey must be an ECDSA key"})
		}
	}
	didKey, err := s.repo.Register(c.Context(), org, key)
	if errors.Is(err, store.ErrOrgExists) {
		return c.Status(fiber.StatusConflict).JSON(fiber.Map{"error": "org is already registered on this host"})
	}
	if err != nil {
		s.log.Error().Err(err).Str("org", org).Msg("register org")
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "internal error"})
	}
	s.log.Info().Str("org", org).Str("key", didKey).Msg("org registered")
	return c.Status(fiber.StatusCreated).JSON(fiber.Map{"did": org, "key": didKey})
}

func (s *Server) getOrg(c *fiber.Ctx) error {
	org, _, _ := params(c)
	head, err := s.repo.Store.Head(c.Context(), org)
	if err != nil {
		return s.fail(c, err)
	}
	key, err := s.repo.Signer.PublicKey(c.Context(), org)
	if err != nil {
		return s.fail(c, err)
	}
	return c.JSON(fiber.Map{"did": org, "key": key, "head": fiber.Map{"seq": head.Seq, "cid": head.CID, "rev": head.Rev}})
}

func (s *Server) commits(c *fiber.Ctx) error {
	org, _, _ := params(c)
	if err := s.checkRead(c.Context(), org, caller(c), ""); err != nil {
		return s.fail(c, err)
	}
	after, err := strconv.ParseInt(c.Query("after", "0"), 10, 64)
	if err != nil || after < 0 {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "after must be a non-negative integer"})
	}
	log, err := s.repo.Log(c.Context(), org, after, s.limit(c))
	if err != nil {
		return s.fail(c, err)
	}
	return c.JSON(fiber.Map{"commits": log})
}

func (s *Server) create(c *fiber.Ctx) error {
	org, collection, _ := params(c)
	return s.write(c, org, collection, repo.NewTID())
}

func (s *Server) put(c *fiber.Ctx) error {
	org, collection, rkey := params(c)
	return s.write(c, org, collection, rkey)
}

// write is the write path (plan §3.2): prepare, check, then commit or park.
func (s *Server) write(c *fiber.Ctx, org, collection, rkey string) error {
	by := committedBy(c, org)
	record, err := s.repo.Prepare(org, collection, rkey, c.Body(), by)
	if err != nil {
		return s.fail(c, err)
	}
	w := &write{org: org, collection: collection, rkey: rkey, record: record, committedBy: by}
	if err := s.checkWrite(c.Context(), w); err != nil {
		var need *ApprovalRequiredError
		if !errors.As(err, &need) {
			return s.fail(c, err)
		}
		p := store.Pending{
			ID: repo.NewTID(), Org: org, Collection: collection, RKey: rkey, Record: record,
			CommittedBy: by, Reasons: need.Reasons, CreatedAt: s.repo.now(),
		}
		if err := s.repo.Store.AddPending(c.Context(), p); err != nil {
			return s.fail(c, err)
		}
		s.log.Info().Str("uri", w.uri()).Str("pending", p.ID).Str("by", caller(c)).Strs("reasons", p.Reasons).Msg("write pending approval")
		return c.Status(fiber.StatusAccepted).JSON(fiber.Map{"pending": p.ID, "uri": w.uri(), "reasons": p.Reasons})
	}
	res, err := s.repo.Put(c.Context(), org, collection, rkey, record, by, nil)
	if err != nil {
		return s.fail(c, err)
	}
	s.log.Info().Str("uri", res.URI).Str("op", res.Op).Str("by", caller(c)).Msg("record committed")
	status := fiber.StatusOK
	if res.Op == repo.OpCreate {
		status = fiber.StatusCreated
	}
	return c.Status(status).JSON(res)
}

func (s *Server) tombstone(c *fiber.Ctx) error {
	org, collection, rkey := params(c)
	cur, err := s.repo.Get(c.Context(), org, collection, rkey)
	if err != nil {
		return s.fail(c, err)
	}
	if !cur.Live() {
		return s.fail(c, ErrNotLive)
	}
	if err := s.checkTombstone(c.Context(), org, caller(c), cur); err != nil {
		return s.fail(c, err)
	}
	res, err := s.repo.Delete(c.Context(), org, collection, rkey, committedBy(c, org), nil)
	if err != nil {
		return s.fail(c, err)
	}
	s.log.Info().Str("uri", res.URI).Str("by", caller(c)).Msg("record tombstoned")
	return c.JSON(res)
}

func (s *Server) get(c *fiber.Ctx) error {
	org, collection, rkey := params(c)
	if err := s.checkRead(c.Context(), org, caller(c), collection); err != nil {
		return s.fail(c, err)
	}
	st, err := s.repo.Get(c.Context(), org, collection, rkey)
	if err != nil {
		return s.fail(c, err)
	}
	if !st.Live() {
		// The record existed and was revoked; say so, with what it was, since a
		// tombstone is the fact a dispute turns on (spec §6.2).
		return c.Status(fiber.StatusGone).JSON(st)
	}
	return c.JSON(st)
}

func (s *Server) list(c *fiber.Ctx) error {
	org, collection, _ := params(c)
	if err := s.checkRead(c.Context(), org, caller(c), collection); err != nil {
		return s.fail(c, err)
	}
	records, err := s.repo.List(c.Context(), org, collection, c.Query("after"), s.limit(c))
	if err != nil {
		return s.fail(c, err)
	}
	return c.JSON(fiber.Map{"records": records})
}

func (s *Server) limit(c *fiber.Ctx) int {
	n, err := strconv.Atoi(c.Query("limit", ""))
	if err != nil || n <= 0 || n > s.pageSize {
		return s.pageSize
	}
	return n
}

// fail maps a repository error to a response.
func (s *Server) fail(c *fiber.Ctx, err error) error {
	switch {
	case errors.Is(err, ErrInvalid):
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": err.Error()})
	case errors.Is(err, ErrForbidden):
		return c.Status(fiber.StatusForbidden).JSON(fiber.Map{"error": err.Error()})
	case store.IsNotFound(err):
		return c.Status(fiber.StatusNotFound).JSON(fiber.Map{"error": "not found"})
	case errors.Is(err, ErrNotLive):
		return c.Status(fiber.StatusConflict).JSON(fiber.Map{"error": "record is already tombstoned"})
	case errors.Is(err, ErrContended):
		return c.Status(fiber.StatusConflict).JSON(fiber.Map{"error": err.Error()})
	default:
		s.log.Error().Err(err).Str("path", c.Path()).Msg("request failed")
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "internal error"})
	}
}
