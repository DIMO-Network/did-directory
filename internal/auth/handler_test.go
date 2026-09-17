package auth

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/DIMO-Network/did-directory/internal/config"
	dimocrypto "github.com/DIMO-Network/did-directory/internal/crypto"
	"github.com/DIMO-Network/did-directory/internal/did"
	"github.com/DIMO-Network/did-directory/internal/server"
	"github.com/DIMO-Network/did-directory/internal/store"
	"github.com/DIMO-Network/did-directory/pkg/client"
	"github.com/DIMO-Network/did-directory/pkg/control"
	"github.com/DIMO-Network/did-directory/pkg/sacd"
	"github.com/gofiber/fiber/v2"
	"github.com/rs/zerolog"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// harness runs a real directory over loopback with the auth service in front of
// it, so these tests exercise the same paths the deployed pair does.
type harness struct {
	t      *testing.T
	dir    *client.Client
	app    *fiber.App
	signer *TokenSigner
}

func newHarness(t *testing.T) *harness {
	t.Helper()

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)

	directory := server.New(&config.Settings{ExportPageSize: 100}, store.NewMemoryStore(), zerolog.Nop())
	go func() { _ = directory.Listener(ln) }()
	t.Cleanup(func() { _ = directory.Shutdown() })

	dir := client.New("http://" + ln.Addr().String())
	require.Eventually(t, func() bool {
		return dir.Health(context.Background()) == nil
	}, 5*time.Second, 10*time.Millisecond, "directory did not come up")

	signingKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	signer := NewTokenSigner(signingKey)
	handler := NewHandler(NewChallengeStore(), signer, dir, zerolog.Nop())

	app := fiber.New(fiber.Config{DisableStartupMessage: true})
	app.Get("/v1/challenge", handler.HandleChallenge)
	app.Post("/v1/auth", handler.HandleAuth)
	app.Get("/.well-known/jwks.json", handler.HandleJWKS)

	return &harness{t: t, dir: dir, app: app, signer: signer}
}

// principal is a DID plus the keys that speak for it.
type principal struct {
	did  string
	keys []*ecdsa.PrivateKey
}

func newKey(t *testing.T) (*ecdsa.PrivateKey, string) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	didKey, err := dimocrypto.EncodeDIDKey(&key.PublicKey)
	require.NoError(t, err)
	return key, didKey
}

func (h *harness) sign(key *ecdsa.PrivateKey, op *did.Operation) *did.Operation {
	h.t.Helper()
	data, err := json.Marshal(op.ToUnsigned())
	require.NoError(h.t, err)
	op.Sig, err = dimocrypto.SignOperation(key, data)
	require.NoError(h.t, err)
	return op
}

// newPerson creates an uncontrolled DID whose verification methods are named by
// vmIDs, one key each.
func (h *harness) newPerson(vmIDs ...string) *principal {
	h.t.Helper()

	rotation, rotationDIDKey := newKey(h.t)
	methods := map[string]string{}
	keys := []*ecdsa.PrivateKey{}
	for _, id := range vmIDs {
		key, didKey := newKey(h.t)
		methods[id] = didKey
		keys = append(keys, key)
	}

	genesis := h.sign(rotation, &did.Operation{
		Type:                did.OpTypeCreate,
		RotationKeys:        []string{rotationDIDKey},
		VerificationMethods: methods,
		AlsoKnownAs:         []string{},
		Services:            map[string]did.Service{},
	})
	didStr, err := did.DeriveFromGenesis(genesis)
	require.NoError(h.t, err)
	_, err = h.dir.Submit(context.Background(), didStr, genesis)
	require.NoError(h.t, err)

	return &principal{did: didStr, keys: keys}
}

// vehicle is a controlled DID plus the private opening of its commitment and the
// custody key that signs its identity operations.
type vehicle struct {
	did        string
	headCID    string
	custody    *ecdsa.PrivateKey
	opening    control.Opening
	controller string
}

func (h *harness) newVehicle(controller string) *vehicle {
	h.t.Helper()

	custody, custodyDIDKey := newKey(h.t)
	salt, err := control.NewSalt()
	require.NoError(h.t, err)
	opening := control.Opening{Controller: controller, Era: 0, Salt: salt}
	commitment, err := control.Commit(opening)
	require.NoError(h.t, err)

	genesis := h.sign(custody, &did.Operation{
		Type:              did.OpTypeCreate,
		RotationKeys:      []string{custodyDIDKey},
		AlsoKnownAs:       []string{},
		Services:          map[string]did.Service{},
		ControlCommitment: &commitment,
	})
	didStr, err := did.DeriveFromGenesis(genesis)
	require.NoError(h.t, err)
	resp, err := h.dir.Submit(context.Background(), didStr, genesis)
	require.NoError(h.t, err)

	return &vehicle{did: didStr, headCID: resp.CID, custody: custody, opening: opening, controller: controller}
}

// grant mints an SACD from the vehicle's controller of record to grantee.
func (h *harness) grant(v *vehicle, grantor *principal, grantee string, effectiveAt time.Time) *sacd.Document {
	h.t.Helper()

	state, err := h.dir.Control(context.Background(), v.did)
	require.NoError(h.t, err)
	cur := state.Current()
	require.NotNil(h.t, cur, "vehicle has no current era")

	doc := &sacd.Document{
		Type:         sacd.DocumentType,
		Grantor:      grantor.did,
		Grantee:      grantee,
		Asset:        v.did,
		Era:          cur.Number,
		Permissions:  []string{"telemetry:read"},
		EffectiveAt:  effectiveAt.UTC().Format(time.RFC3339),
		ExpiresAt:    time.Now().UTC().Add(24 * time.Hour).Format(time.RFC3339),
		ControlProof: &v.opening,
	}
	payload, err := doc.UnsignedPayload()
	require.NoError(h.t, err)
	doc.Signature, err = dimocrypto.SignOperation(grantor.keys[0], payload)
	require.NoError(h.t, err)
	return doc
}

// authenticate runs the full challenge/response against the auth service.
func (h *harness) authenticate(didStr string, key *ecdsa.PrivateKey, sacds []sacd.Document) (int, map[string]any) {
	h.t.Helper()

	resp, err := h.app.Test(httptest.NewRequest(http.MethodGet, "/v1/challenge", nil), -1)
	require.NoError(h.t, err)
	var challenge struct {
		Challenge string `json:"challenge"`
	}
	require.NoError(h.t, json.NewDecoder(resp.Body).Decode(&challenge))
	resp.Body.Close()
	require.NotEmpty(h.t, challenge.Challenge)

	nonce, err := base64.RawURLEncoding.DecodeString(challenge.Challenge)
	require.NoError(h.t, err)
	sig, err := dimocrypto.SignOperation(key, nonce)
	require.NoError(h.t, err)

	body, err := json.Marshal(AuthRequest{
		DID:       didStr,
		Challenge: challenge.Challenge,
		Signature: sig,
		SACDs:     sacds,
		Audience:  []string{"test-app"},
	})
	require.NoError(h.t, err)

	req := httptest.NewRequest(http.MethodPost, "/v1/auth", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	authResp, err := h.app.Test(req, -1)
	require.NoError(h.t, err)
	defer authResp.Body.Close()

	raw, err := io.ReadAll(authResp.Body)
	require.NoError(h.t, err)
	var out map[string]any
	_ = json.Unmarshal(raw, &out)
	return authResp.StatusCode, out
}

func TestHandleAuth_IssuesTokenForTheGrantee(t *testing.T) {
	h := newHarness(t)
	owner := h.newPerson("signing")
	dev := h.newPerson("signing")
	v := h.newVehicle(owner.did)

	grant := h.grant(v, owner, dev.did, time.Now().Add(-time.Minute))

	status, body := h.authenticate(dev.did, dev.keys[0], []sacd.Document{*grant})
	require.Equal(t, http.StatusOK, status, body)

	claims, err := h.signer.VerifyToken(body["token"].(string))
	require.NoError(t, err)
	assert.Equal(t, dev.did, claims.Subject)
	require.Len(t, claims.Assets, 1)
	assert.Equal(t, v.did, claims.Assets[0].DID)
	assert.Equal(t, []string{"telemetry:read"}, claims.Assets[0].Permissions)
}

// An SACD is a bearer document. The challenge proves only that the caller
// controls its own DID, and nothing compared the SACD's grantee to it — so a
// leaked grant (scripts/demo.sh prints them to stdout) minted a JWT carrying the
// vehicle's permissions for whoever picked it up.
func TestHandleAuth_RejectsSACDGrantedToSomebodyElse(t *testing.T) {
	h := newHarness(t)
	owner := h.newPerson("signing")
	dev := h.newPerson("signing")
	thief := h.newPerson("signing")
	v := h.newVehicle(owner.did)

	leaked := h.grant(v, owner, dev.did, time.Now().Add(-time.Minute))

	// The thief authenticates honestly, as itself, and presents the leaked grant.
	status, body := h.authenticate(thief.did, thief.keys[0], []sacd.Document{*leaked})

	assert.Equal(t, http.StatusForbidden, status, body)
	assert.Contains(t, body["error"], "not granted to the authenticated DID")
	assert.NotContains(t, body, "token")

	// Rewriting the grantee does not help: the grantor's signature covers it.
	forged := *leaked
	forged.Grantee = thief.did
	status, body = h.authenticate(thief.did, thief.keys[0], []sacd.Document{forged})
	assert.Equal(t, http.StatusBadRequest, status, body)
	assert.Contains(t, body["detail"], "signature")
}

func TestHandleAuth_RejectsBadChallengeSignature(t *testing.T) {
	h := newHarness(t)
	dev := h.newPerson("signing")
	impostor, _ := newKey(t)

	status, body := h.authenticate(dev.did, impostor, nil)
	assert.Equal(t, http.StatusUnauthorized, status, body)
	assert.Contains(t, body["error"], "challenge signature verification failed")
}

func TestHandleAuth_RejectsReplayedChallenge(t *testing.T) {
	h := newHarness(t)
	dev := h.newPerson("signing")

	resp, err := h.app.Test(httptest.NewRequest(http.MethodGet, "/v1/challenge", nil), -1)
	require.NoError(t, err)
	var challenge struct {
		Challenge string `json:"challenge"`
	}
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&challenge))
	resp.Body.Close()

	nonce, err := base64.RawURLEncoding.DecodeString(challenge.Challenge)
	require.NoError(t, err)
	sig, err := dimocrypto.SignOperation(dev.keys[0], nonce)
	require.NoError(t, err)

	post := func() int {
		body, err := json.Marshal(AuthRequest{DID: dev.did, Challenge: challenge.Challenge, Signature: sig})
		require.NoError(t, err)
		req := httptest.NewRequest(http.MethodPost, "/v1/auth", bytes.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		r, err := h.app.Test(req, -1)
		require.NoError(t, err)
		r.Body.Close()
		return r.StatusCode
	}

	assert.Equal(t, http.StatusOK, post())
	assert.Equal(t, http.StatusUnauthorized, post(), "a challenge is single-use")
}

// The handler authenticated against VerificationMethod[0] alone. The document's
// order used to be map order, so a developer with two keys authenticated on some
// requests and got a 401 on others; ordering the document makes that a permanent
// 401 for everyone whose key does not sort first. Try every method.
func TestHandleAuth_AcceptsAnyVerificationMethod(t *testing.T) {
	h := newHarness(t)
	dev := h.newPerson("aaa-laptop", "zzz-phone")
	require.Len(t, dev.keys, 2)

	doc, err := h.dir.Resolve(context.Background(), dev.did)
	require.NoError(t, err)
	require.Len(t, doc.VerificationMethod, 2)

	for i, key := range dev.keys {
		for attempt := range 5 {
			status, body := h.authenticate(dev.did, key, nil)
			require.Equal(t, http.StatusOK, status, "key %d attempt %d: %v", i, attempt, body)
		}
	}
}

func TestHandleAuth_RejectsUnknownDID(t *testing.T) {
	h := newHarness(t)
	key, _ := newKey(t)
	status, body := h.authenticate("did:dimo:aaaaaaaaaaaaaaaaaaaaaaaa", key, nil)
	assert.Equal(t, http.StatusBadRequest, status)
	assert.Contains(t, body["error"], "failed to resolve developer DID")
}

func TestHandleJWKS(t *testing.T) {
	h := newHarness(t)
	resp, err := h.app.Test(httptest.NewRequest(http.MethodGet, "/.well-known/jwks.json", nil), -1)
	require.NoError(t, err)
	defer resp.Body.Close()

	var jwks struct {
		Keys []map[string]any `json:"keys"`
	}
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&jwks))
	require.Len(t, jwks.Keys, 1)
	assert.Equal(t, "ES256", jwks.Keys[0]["alg"])
	assert.Equal(t, h.signer.KeyID(), jwks.Keys[0]["kid"])
}

// revokeSince records a compromise window and re-commits control for the next
// era, exactly as the CLI does.
func (h *harness) revokeSince(v *vehicle, since time.Time) {
	h.t.Helper()

	state, err := h.dir.Control(context.Background(), v.did)
	require.NoError(h.t, err)
	next := state.Current().Number + 1

	salt, err := control.NewSalt()
	require.NoError(h.t, err)
	opening := control.Opening{Controller: v.controller, Era: next, Salt: salt}
	commitment, err := control.Commit(opening)
	require.NoError(h.t, err)

	newCustody, newCustodyDIDKey := newKey(h.t)
	// A couple of seconds back, still well within the directory's ±5min skew, so
	// that a re-grant in the new era does not land on the era boundary. The
	// boundary itself fails closed: a grant racing the revocation loses.
	issued := time.Now().UTC().Add(-2 * time.Second).Format(time.RFC3339)
	op := h.sign(v.custody, &did.Operation{
		Type:              did.OpTypeRevokeSince,
		RotationKeys:      []string{newCustodyDIDKey},
		AlsoKnownAs:       []string{},
		Services:          map[string]did.Service{},
		ControlCommitment: &commitment,
		RevokeSince:       ptrStr(since.UTC().Format(time.RFC3339)),
		EffectiveAt:       &issued,
		Prev:              &v.headCID,
	})
	resp, err := h.dir.Submit(context.Background(), v.did, op)
	require.NoError(h.t, err)

	v.headCID = resp.CID
	v.custody = newCustody
	v.opening = opening
}

func ptrStr(s string) *string { return &s }

// dimo_revoke_since has to be able to revoke. The window is tested against
// effectiveAt, which the signer chooses: a stolen key backdates the grant to
// before the window, or post-dates it past one that will ever exist (validation
// caps a revocation's own effectiveAt at now+5min, so an SACD effective in 30
// days can never fall inside any future window). Ending the era is what bites.
func TestValidateSACD_RevokeSinceInvalidatesABackdatedGrant(t *testing.T) {
	h := newHarness(t)
	owner := h.newPerson("signing")
	dev := h.newPerson("signing")
	v := h.newVehicle(owner.did)
	ctx := context.Background()

	// A grant a thief dated well before the compromise it is about to be caught in.
	backdated := h.grant(v, owner, dev.did, time.Now().Add(-3*time.Hour))
	require.NoError(t, ValidateSACD(ctx, h.dir, backdated))

	// And one dated past any window that can ever be recorded: ValidateTransition
	// caps a revocation's own effectiveAt at now+5min, so nothing the controller
	// can sign will ever cover a grant effective in 30 days. Post-dating costs the
	// thief the use of it until then, which is the only thing holding the line.
	postdated := h.grant(v, owner, dev.did, time.Now().Add(30*24*time.Hour))
	assert.ErrorContains(t, ValidateSACD(ctx, h.dir, postdated), "not yet effective")

	h.revokeSince(v, time.Now().Add(-2*time.Hour))

	state, err := h.dir.Control(ctx, v.did)
	require.NoError(t, err)
	require.Equal(t, uint64(1), state.Current().Number, "the compromised era must be closed")

	assert.ErrorContains(t, ValidateSACD(ctx, h.dir, backdated), "era",
		"a grant backdated before the window must not survive the revocation")
	assert.ErrorContains(t, ValidateSACD(ctx, h.dir, postdated), "era")

	// The controller re-grants in the new era, and that grant works.
	fresh := h.grant(v, owner, dev.did, time.Now().Add(-time.Second))
	require.NoError(t, ValidateSACD(ctx, h.dir, fresh))

	status, body := h.authenticate(dev.did, dev.keys[0], []sacd.Document{*backdated})
	assert.Equal(t, http.StatusBadRequest, status, body)
	status, body = h.authenticate(dev.did, dev.keys[0], []sacd.Document{*fresh})
	assert.Equal(t, http.StatusOK, status, body)
}

// Deactivating a vehicle must stop its grants. SACD verification reads control
// state, which never looked at the tombstone, so grants over a scrapped or
// stolen car kept validating while GET /:did already returned 410.
func TestValidateSACD_DeactivatedVehicle(t *testing.T) {
	h := newHarness(t)
	owner := h.newPerson("signing")
	dev := h.newPerson("signing")
	v := h.newVehicle(owner.did)
	ctx := context.Background()

	grant := h.grant(v, owner, dev.did, time.Now().Add(-time.Minute))
	require.NoError(t, ValidateSACD(ctx, h.dir, grant))

	at := time.Now().UTC().Format(time.RFC3339)
	tomb := h.sign(v.custody, &did.Operation{
		Type:        did.OpTypeTombstone,
		EffectiveAt: &at,
		Prev:        &v.headCID,
	})
	_, err := h.dir.Submit(ctx, v.did, tomb)
	require.NoError(t, err)

	assert.ErrorContains(t, ValidateSACD(ctx, h.dir, grant), "deactivated")

	status, body := h.authenticate(dev.did, dev.keys[0], []sacd.Document{*grant})
	assert.Equal(t, http.StatusBadRequest, status, body)
	assert.Contains(t, body["detail"], "deactivated")
}

func TestStorageFromDoc(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()

	rotation, rotationDIDKey := newKey(t)
	_, signingDIDKey := newKey(t)
	genesis := h.sign(rotation, &did.Operation{
		Type:                did.OpTypeCreate,
		RotationKeys:        []string{rotationDIDKey},
		VerificationMethods: map[string]string{"signing": signingDIDKey},
		AlsoKnownAs:         []string{},
		Services: map[string]did.Service{
			"metadata": {Type: "DeviceInfo", Endpoint: "firmware-v2.4.1"},
			"storage":  {Type: "DimoStorageNode", Endpoint: "https://node7.dimo.zone"},
		},
	})
	didStr, err := did.DeriveFromGenesis(genesis)
	require.NoError(t, err)
	_, err = h.dir.Submit(ctx, didStr, genesis)
	require.NoError(t, err)

	assert.Equal(t, "https://node7.dimo.zone", StorageFromDoc(ctx, h.dir, didStr))
	assert.Empty(t, StorageFromDoc(ctx, h.dir, "did:dimo:aaaaaaaaaaaaaaaaaaaaaaaa"))
}
