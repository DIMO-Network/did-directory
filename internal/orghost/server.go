package orghost

import (
	"context"
	"crypto/ecdsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/DIMO-Network/did-directory/internal/orghost/store"
	"github.com/DIMO-Network/did-directory/pkg/delegation"
	"github.com/DIMO-Network/did-directory/pkg/dpop"
	"github.com/DIMO-Network/did-directory/pkg/identity"
	"github.com/DIMO-Network/did-directory/pkg/odrl"
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
	repo      *Repository
	auth      Authenticator
	resolver  *Resolver
	documents DocumentSource
	publicURL string
	registers *rateLimiter
	policies  Policies
	issuers   map[string]bool
	admins    map[string]bool
	pageSize  int
	log       zerolog.Logger
}

// Options configures a Server.
type Options struct {
	Repo *Repository
	Auth Authenticator
	// Control is where control state comes from: the DID directory.
	Control ControlSource
	// Documents resolves DID documents, also from the directory: register
	// checks that the org's DID names this host.
	Documents DocumentSource
	// PublicURL is this host's own URL, which an org's DID must publish as its
	// #dimo_org_host to register here. A trailing slash is dropped; the
	// endpoint is then compared exactly.
	PublicURL string
	// RegisterPerMinute bounds registers host-wide in any rolling minute, since
	// each one can make a billable KMS key; zero means no limit.
	RegisterPerMinute int
	// Issuers are the DIDs that may call POST /authorize (plan §3.3): dauth.
	Issuers []string
	// Admins are the DIDs that may set party attributes (plan §1 decision E).
	Admins []string
	// Policies are the commit policy profiles a role may name; the default
	// profile is always present.
	Policies Policies
	// PageSize bounds list and log responses; zero means 100.
	PageSize int
	// ControlCacheTTL is how long the resolver serves a cached control state;
	// zero means DefaultControlCacheTTL.
	ControlCacheTTL time.Duration
	Log             zerolog.Logger
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
		resolver:  &Resolver{Store: o.Repo.Store, Control: o.Control, Now: o.Repo.now, ControlCacheTTL: o.ControlCacheTTL},
		documents: o.Documents, publicURL: strings.TrimRight(o.PublicURL, "/"),
		registers: &rateLimiter{limit: o.RegisterPerMinute},
		policies:  policies,
		issuers:   set(o.Issuers), admins: set(o.Admins),
		pageSize: o.PageSize, log: o.Log.With().Str("component", "orghost").Logger(),
	}

	app := fiber.New(fiber.Config{AppName: "org-host", DisableStartupMessage: true})
	app.Use(recover.New())
	app.Use(requestid.New())
	app.Use(cors.New())

	app.Get("/health", func(c *fiber.Ctx) error {
		return c.JSON(fiber.Map{"status": "ok"})
	})

	// Every route names the scope its token must carry (pkg/identity): reads
	// read, writes write, and the acts behind a second look approve.
	read, write, approve := s.needs(identity.ScopeRead), s.needs(identity.ScopeWrite), s.needs(identity.ScopeApprove)

	app.Post("/authorize", s.authenticate, read, s.authorize)
	parties := app.Group("/parties", s.authenticate)
	parties.Get("/:did", read, s.getParty)
	parties.Put("/:did", write, s.setParty)

	me := app.Group("/me", s.authenticate)
	me.Get("/roles", read, s.myRoles)
	me.Get("/delegations", read, s.myDelegations)

	orgs := app.Group("/orgs", s.authenticate)
	orgs.Post("/:org", approve, s.register)
	orgs.Get("/:org", read, s.getOrg)
	// Before /:org/:collection, which would otherwise capture them.
	orgs.Get("/:org/commits", read, s.commits)
	orgs.Get("/:org/pending", read, s.listPending)
	orgs.Post("/:org/pending/:id/approve", approve, s.approve)
	orgs.Delete("/:org/pending/:id", write, s.withdraw)
	orgs.Post("/:org/revoke-authored-by", approve, s.revokeAuthoredBy)
	orgs.Get("/:org/delegations/:rkey/proof", read, s.proof)
	orgs.Get("/:org/delegations/:rkey/descendants", read, s.descendants)
	orgs.Get("/:org/delegations/:rkey/vehicles", read, s.vehicles)
	orgs.Get("/:org/vehicles/:vehicle/access", read, s.vehicleAccess)
	orgs.Post("/:org/:collection", write, s.create)
	orgs.Get("/:org/:collection", read, s.list)
	orgs.Put("/:org/:collection/:rkey", write, s.put)
	orgs.Get("/:org/:collection/:rkey", read, s.get)
	orgs.Delete("/:org/:collection/:rkey", write, s.tombstone)
	return app
}

const callerKey = "caller"

const scopesKey = "scopes"

// authenticate resolves the caller's DID into c.Locals(callerKey) and its
// token's scopes into c.Locals(scopesKey). Bad credentials are 401
// invalid_token; credentials that could not be checked (ErrUnavailable, or any
// other failure that is not ErrUnauthenticated) are 503, retryable.
func (s *Server) authenticate(c *fiber.Ctx) error {
	id, err := s.auth.Authenticate(c.Context(), Credentials{
		Authorization: c.Get(fiber.HeaderAuthorization),
		Proof:         c.Get(dpop.HeaderName),
		Method:        c.Method(),
		Path:          strings.Clone(c.Path()),
	})
	if err != nil {
		if errors.Is(err, ErrUnauthenticated) {
			c.Set(fiber.HeaderWWWAuthenticate, `DPoP error="invalid_token"`)
			return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{"error": err.Error(), "code": "invalid_token"})
		}
		s.log.Warn().Err(err).Str("path", c.Path()).Msg("could not authenticate the request")
		c.Set(fiber.HeaderRetryAfter, "1")
		return c.Status(fiber.StatusServiceUnavailable).JSON(fiber.Map{
			"error": "could not check the request's credentials, retry shortly",
			"code":  "temporarily_unavailable",
		})
	}
	c.Locals(callerKey, strings.Clone(id.DID))
	c.Locals(scopesKey, id.Scopes)
	return c.Next()
}

// needs refuses a token that does not carry scope, with 403
// insufficient_scope, before the route looks at anything.
func (s *Server) needs(scope string) fiber.Handler {
	return func(c *fiber.Ctx) error {
		scopes, _ := c.Locals(scopesKey).([]string)
		if !slices.Contains(scopes, scope) {
			c.Set(fiber.HeaderWWWAuthenticate, fmt.Sprintf(`DPoP error="insufficient_scope", scope=%q`, scope))
			return c.Status(fiber.StatusForbidden).JSON(fiber.Map{
				"error": fmt.Sprintf("this needs a token with scope %q; sign in again asking for it", scope),
				"code":  "insufficient_scope", "scope": scope,
			})
		}
		return c.Next()
	}
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
// where its signing key is born, and under KMS each key is billed. So the
// caller must be the org, the org's DID must already name this host as its
// #dimo_org_host, and registers are rate limited host-wide.
func (s *Server) register(c *fiber.Ctx) error {
	org, _, _ := params(c)
	if caller(c) != org {
		return c.Status(fiber.StatusForbidden).JSON(fiber.Map{"error": "only the org itself may register its repository"})
	}
	if ok, wait := s.registers.allow(s.repo.now()); !ok {
		c.Set(fiber.HeaderRetryAfter, strconv.Itoa(retryAfterSeconds(wait)))
		return c.Status(fiber.StatusTooManyRequests).JSON(fiber.Map{"error": "too many registers on this host, retry later"})
	}
	if s.documents == nil {
		s.log.Error().Str("org", org).Msg("register: no DID document source configured")
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "internal error"})
	}
	ours, err := namesThisHost(c.Context(), s.documents, org, s.publicURL)
	if err != nil {
		s.log.Warn().Err(err).Str("org", org).Msg("register: could not resolve the org's DID")
		c.Set(fiber.HeaderRetryAfter, "1")
		return c.Status(fiber.StatusServiceUnavailable).JSON(fiber.Map{
			"error": "could not resolve the org's DID, retry shortly",
			"code":  "temporarily_unavailable",
		})
	}
	if !ours {
		return c.Status(fiber.StatusForbidden).JSON(fiber.Map{"error": errNotThisHost})
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
	if errors.Is(err, ErrPrivateKeyNotAccepted) {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "privateKey is not accepted with the KMS signer"})
	}
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
	r, err := s.reader(c.Context(), org, caller(c))
	if err != nil {
		return s.fail(c, err)
	}
	if err := r.requireAdmin(); err != nil {
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
	// The checks run under the org's write lock, against the head the commit
	// follows (Repository.Check).
	res, err := s.repo.Put(c.Context(), org, collection, rkey, record, by, nil, func(ctx context.Context, _ *store.Stored) error {
		return s.checkWrite(ctx, w)
	})
	if err != nil {
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
	s.log.Info().Str("uri", res.URI).Str("op", res.Op).Str("by", caller(c)).Msg("record committed")
	status := fiber.StatusOK
	if res.Op == repo.OpCreate {
		status = fiber.StatusCreated
	}
	return c.Status(status).JSON(res)
}

func (s *Server) tombstone(c *fiber.Ctx) error {
	org, collection, rkey := params(c)
	who := caller(c)
	res, err := s.repo.Delete(c.Context(), org, collection, rkey, committedBy(c, org), nil, func(ctx context.Context, cur *store.Stored) error {
		if cur == nil || !cur.Live() {
			return nil // Delete answers not found or not live itself
		}
		return s.checkTombstone(ctx, org, who, cur)
	})
	if err != nil {
		return s.fail(c, err)
	}
	s.log.Info().Str("uri", res.URI).Str("by", caller(c)).Msg("record tombstoned")
	return c.JSON(res)
}

func (s *Server) get(c *fiber.Ctx) error {
	org, collection, rkey := params(c)
	// A delegation or role may also be read by its assignee, who need not be
	// a member: /me lists it to them already. A caller refused a reader is
	// refused the same way whether or not the key exists, so the exception
	// tells nobody else anything.
	addressed := collection == delegation.CollectionDelegation || collection == delegation.CollectionRole
	r, refused := s.readerFor(c, org, collection)
	if refused != nil && (!addressed || !errors.Is(refused, ErrForbidden)) {
		return s.fail(c, refused)
	}
	st, err := s.repo.Get(c.Context(), org, collection, rkey)
	if err != nil {
		if refused != nil {
			return s.fail(c, refused)
		}
		return s.fail(c, err)
	}
	ok := false
	if r != nil {
		if ok, err = r.canReadStored(c.Context(), st); err != nil {
			return s.fail(c, err)
		}
	}
	if !ok && addressed {
		rec, err := odrl.Decode(st.Record)
		if err != nil {
			return s.fail(c, err)
		}
		ok = rec.To == caller(c)
	}
	// A record outside the caller's reach is not found, as one never written
	// is: its key alone can name a vehicle or a partner.
	if !ok {
		if refused != nil {
			return s.fail(c, refused)
		}
		return s.fail(c, store.ErrNotFound)
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
	r, err := s.readerFor(c, org, collection)
	if err != nil {
		return s.fail(c, err)
	}
	// Pages are filled with what the caller may read, reading on past what
	// they may not, so a page short of the limit is the end of the list and
	// the last record's key is still the cursor for the next one.
	limit := s.limit(c)
	after := c.Query("after")
	records := []store.Stored{}
	for len(records) < limit {
		page, err := s.repo.List(c.Context(), org, collection, after, s.pageSize)
		if err != nil {
			return s.fail(c, err)
		}
		for i := range page {
			ok, err := r.canReadStored(c.Context(), &page[i])
			if err != nil {
				return s.fail(c, err)
			}
			if ok {
				records = append(records, page[i])
				if len(records) == limit {
					break
				}
			}
		}
		if len(page) < s.pageSize {
			break
		}
		after = page[len(page)-1].RKey
	}
	return c.JSON(fiber.Map{"records": records})
}

// readerFor resolves the caller's read access for a collection route. The
// control openings are refused outright to anyone who does not read
// everything, rather than filtered to nothing.
func (s *Server) readerFor(c *fiber.Ctx, org, collection string) (*reader, error) {
	r, err := s.reader(c.Context(), org, caller(c))
	if err != nil {
		return nil, err
	}
	if collection == delegation.CollectionVehicleControl {
		if err := r.requireAdmin(); err != nil {
			return nil, err
		}
	}
	return r, nil
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
