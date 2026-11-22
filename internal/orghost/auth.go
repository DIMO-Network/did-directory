package orghost

import (
	"context"
	"crypto"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/DIMO-Network/did-directory/internal/orghost/store"
	"github.com/DIMO-Network/did-directory/pkg/dpop"
	"github.com/DIMO-Network/did-directory/pkg/identity"
	"github.com/rs/zerolog"
)

// ErrUnauthenticated is returned when a request carries no usable identity.
var ErrUnauthenticated = errors.New("unauthenticated")

// ErrUnavailable is returned when a request's credentials could not be checked
// right now, as when the DPoP replay cache is full. It says nothing about the
// credentials: the same request may pass on retry, so it is answered 503, not
// 401.
var ErrUnavailable = errors.New("authentication temporarily unavailable")

// Authenticator answers "which DID is making this request, and for what". The
// v1 implementation checks a dauth-issued identity token whose sub is the
// member DID (plan §1 decision B), bound to a DPoP key; it is an interface so
// tests and a later service-to-service scheme can supply their own.
type Authenticator interface {
	// Authenticate returns the identity behind the request's credentials,
	// ErrUnauthenticated when they are missing or bad, or ErrUnavailable when
	// they could not be checked right now.
	Authenticate(ctx context.Context, cred Credentials) (Identity, error)
}

// Credentials is what a request presents: its Authorization and DPoP
// headers, and the method and path the proof must name.
type Credentials struct {
	Authorization string
	Proof         string
	Method        string
	// Path is the request path; the proof's htu is this host's public URL
	// (the audience) followed by it.
	Path string
}

// Identity is an authenticated caller: its DID and the scopes its token
// carries.
type Identity struct {
	DID    string
	Scopes []string
}

// ErrRateLimited is returned for a caller holding as many live proofs as it
// may; it is answered 429, for that caller alone.
var ErrRateLimited = errors.New("too many requests from this caller")

// tokenLeeway is how far a token's exp or nbf may disagree with this host's
// clock.
const tokenLeeway = time.Minute

// JWKSAuthenticator verifies RS256 identity tokens against a JSON Web Key Set,
// the way dauth publishes its signing keys. It enforces the signature, exp,
// nbf, the issuer, the audience, the scope claim and the DPoP binding: the
// token is presented under the DPoP scheme with a fresh proof for this request
// from the key cnf.jkt names, so a copied token is useless without the key. The audience is what keeps a token a
// member signed in with for some other service from writing records here as
// them: dauth issues one kind of identity token to every relying party, and
// aud is the only thing in it that says which.
type JWKSAuthenticator struct {
	issuer   string
	audience string
	fetch    func(ctx context.Context) ([]byte, error)
	// proofs checks each DPoP proof; it keeps no replay cache of its own.
	// replay remembers the accepted ones, perSubject bounds one caller's live
	// proofs there, and unlimited are the callers it does not bound.
	proofs     *dpop.Verifier
	replay     store.ProofStore
	perSubject int
	unlimited  map[string]bool
	// now is the clock the refresh schedule runs on; nil means time.Now.
	now func() time.Time

	mu   sync.Mutex
	keys map[string]*rsa.PublicKey
	// attemptedAt is when the key set was last fetched or tried: a failed
	// fetch counts, so a dauth outage costs one fetch per interval, not one per
	// request.
	attemptedAt time.Time
	// refreshing is closed when the fetch in flight ends; nil when none is.
	// refreshingAll says it was started because the whole set was due, so even
	// requests whose kid is known wait for it.
	refreshing    chan struct{}
	refreshingAll bool
}

// The key set is fetched again every jwksTTL whatever the requests name, so a
// key dauth has removed stops verifying within that time (dauth serves its
// JWKS with max-age 300), and on a kid it does not hold at most once every
// jwksRefreshInterval, so a new key is picked up promptly. Each fetch has
// jwksFetchTimeout.
const (
	jwksTTL             = 5 * time.Minute
	jwksRefreshInterval = time.Minute
)

var jwksFetchTimeout = 5 * time.Second

// NewJWKSAuthenticator builds an authenticator over a static key set. issuer
// is the iss claim a token must carry and audience a value its aud must
// contain; both are required.
func NewJWKSAuthenticator(jwksJSON []byte, issuer, audience string) (*JWKSAuthenticator, error) {
	if issuer == "" || audience == "" {
		return nil, errors.New("an identity token issuer and audience are both required")
	}
	keys, err := parseJWKS(jwksJSON)
	if err != nil {
		return nil, err
	}
	return &JWKSAuthenticator{
		issuer: issuer, audience: normalHostURL(audience), keys: keys, attemptedAt: time.Now(),
		// A Verifier built this way holds no replay cache: replay is what
		// remembers proofs, per process here and across replicas once the host
		// gives it the database (UseProofStore).
		proofs:     &dpop.Verifier{MaxAge: proofMaxAge, Skew: proofSkew},
		replay:     store.NewMemoryProofs(store.DefaultMaxProofs),
		perSubject: DefaultProofsPerSubject,
	}, nil
}

// A proof is accepted for proofMaxAge after its iat and proofSkew before it,
// so it is remembered for their sum.
const (
	proofMaxAge = 5 * time.Minute
	proofSkew   = time.Minute
)

// DefaultProofsPerSubject bounds how many live proofs one caller may hold: a
// proof lives six minutes, so this is about 28 requests a second, sustained.
const DefaultProofsPerSubject = 10_000

// UseProofStore makes ps where accepted proofs are remembered: the host's
// Postgres store, so a proof one replica accepted is refused by the others.
// perSubject bounds one caller's live proofs (zero or less: no bound), except
// for the DIDs in unlimited, such as the issuer calling /authorize.
func (a *JWKSAuthenticator) UseProofStore(ps store.ProofStore, perSubject int, unlimited []string) {
	a.replay, a.perSubject = ps, perSubject
	a.unlimited = map[string]bool{}
	for _, d := range unlimited {
		a.unlimited[d] = true
	}
}

// NewJWKSAuthenticatorFromURL fetches the key set from url now, again every
// five minutes so removed keys drop, and on a key id it does not hold at most
// once a minute. Every fetch gives up after five seconds.
func NewJWKSAuthenticatorFromURL(ctx context.Context, url, issuer, audience string) (*JWKSAuthenticator, error) {
	client := &http.Client{Timeout: jwksFetchTimeout}
	fetch := func(ctx context.Context) ([]byte, error) {
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
		if err != nil {
			return nil, err
		}
		resp, err := client.Do(req)
		if err != nil {
			return nil, err
		}
		defer func() { _ = resp.Body.Close() }()
		if resp.StatusCode != http.StatusOK {
			return nil, fmt.Errorf("fetch JWKS: %s", resp.Status)
		}
		return io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	}
	body, err := fetch(ctx)
	if err != nil {
		return nil, err
	}
	a, err := NewJWKSAuthenticator(body, issuer, audience)
	if err != nil {
		return nil, err
	}
	a.fetch = fetch
	return a, nil
}

func parseJWKS(data []byte) (map[string]*rsa.PublicKey, error) {
	var set struct {
		Keys []struct {
			Kty string `json:"kty"`
			Kid string `json:"kid"`
			Use string `json:"use"`
			N   string `json:"n"`
			E   string `json:"e"`
		} `json:"keys"`
	}
	if err := json.Unmarshal(data, &set); err != nil {
		return nil, fmt.Errorf("parse JWKS: %w", err)
	}
	keys := map[string]*rsa.PublicKey{}
	for _, k := range set.Keys {
		if k.Kty != "RSA" || (k.Use != "" && k.Use != "sig") {
			continue
		}
		n, err := base64.RawURLEncoding.DecodeString(k.N)
		if err != nil {
			return nil, fmt.Errorf("JWKS key %q: n: %w", k.Kid, err)
		}
		e, err := base64.RawURLEncoding.DecodeString(k.E)
		if err != nil {
			return nil, fmt.Errorf("JWKS key %q: e: %w", k.Kid, err)
		}
		eInt := new(big.Int).SetBytes(e)
		if !eInt.IsInt64() || eInt.Int64() < 3 {
			return nil, fmt.Errorf("JWKS key %q: bad exponent", k.Kid)
		}
		keys[k.Kid] = &rsa.PublicKey{N: new(big.Int).SetBytes(n), E: int(eInt.Int64())}
	}
	if len(keys) == 0 {
		return nil, errors.New("JWKS holds no RSA signing keys")
	}
	return keys, nil
}

func (a *JWKSAuthenticator) clock() time.Time {
	if a.now != nil {
		return a.now()
	}
	return time.Now()
}

// key returns the key kid names. When the set is due for a fetch, the request
// that notices starts one, single-flight, and the request waits for it if its
// kid is unknown or the whole set was due; a request whose kid is known waits
// for no fetch an unknown kid started. A failed fetch keeps the keys there
// were.
func (a *JWKSAuthenticator) key(ctx context.Context, kid string) (*rsa.PublicKey, bool) {
	a.mu.Lock()
	k, ok := a.keys[kid]
	if a.fetch == nil {
		a.mu.Unlock()
		return k, ok
	}
	if a.refreshing == nil {
		now := a.clock()
		since := now.Sub(a.attemptedAt)
		all := since >= jwksTTL
		if all || (!ok && since >= jwksRefreshInterval) {
			a.refreshing, a.refreshingAll, a.attemptedAt = make(chan struct{}), all, now
			go a.refresh(a.refreshing)
		}
	}
	wait := a.refreshing
	if wait == nil || (ok && !a.refreshingAll) {
		a.mu.Unlock()
		return k, ok
	}
	a.mu.Unlock()
	select {
	case <-wait:
	case <-ctx.Done():
		return nil, false
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	k, ok = a.keys[kid]
	return k, ok
}

// refresh fetches the key set under its own deadline, detached from the
// request that started it, and replaces the keys only on success.
func (a *JWKSAuthenticator) refresh(done chan struct{}) {
	ctx, cancel := context.WithTimeout(context.Background(), jwksFetchTimeout)
	defer cancel()
	body, err := a.fetch(ctx)
	var keys map[string]*rsa.PublicKey
	if err == nil {
		keys, err = parseJWKS(body)
	}
	a.mu.Lock()
	if err == nil {
		a.keys = keys
	}
	a.refreshing, a.refreshingAll = nil, false
	a.mu.Unlock()
	close(done)
}

// Authenticate implements Authenticator.
func (a *JWKSAuthenticator) Authenticate(ctx context.Context, cred Credentials) (Identity, error) {
	raw, ok := strings.CutPrefix(cred.Authorization, dpop.TokenType+" ")
	if !ok {
		return Identity{}, fmt.Errorf("%w: authorization header must use the DPoP scheme", ErrUnauthenticated)
	}
	raw = strings.TrimSpace(raw)
	parts := strings.Split(raw, ".")
	if len(parts) != 3 {
		return Identity{}, fmt.Errorf("%w: malformed token", ErrUnauthenticated)
	}
	headerJSON, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return Identity{}, fmt.Errorf("%w: malformed token header", ErrUnauthenticated)
	}
	var header struct {
		Alg string `json:"alg"`
		Kid string `json:"kid"`
	}
	if err := json.Unmarshal(headerJSON, &header); err != nil || header.Alg != "RS256" {
		return Identity{}, fmt.Errorf("%w: token must be RS256", ErrUnauthenticated)
	}
	pub, ok := a.key(ctx, header.Kid)
	if !ok {
		return Identity{}, fmt.Errorf("%w: unknown signing key", ErrUnauthenticated)
	}
	sig, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil {
		return Identity{}, fmt.Errorf("%w: malformed signature", ErrUnauthenticated)
	}
	digest := sha256.Sum256([]byte(parts[0] + "." + parts[1]))
	if err := rsa.VerifyPKCS1v15(pub, crypto.SHA256, digest[:], sig); err != nil {
		return Identity{}, fmt.Errorf("%w: invalid signature", ErrUnauthenticated)
	}

	claimsJSON, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return Identity{}, fmt.Errorf("%w: malformed claims", ErrUnauthenticated)
	}
	var claims struct {
		Iss   string                 `json:"iss"`
		Sub   string                 `json:"sub"`
		Aud   json.RawMessage        `json:"aud"`
		Exp   int64                  `json:"exp"`
		Nbf   int64                  `json:"nbf"`
		Scope string                 `json:"scope"`
		Cnf   *identity.Confirmation `json:"cnf"`
	}
	if err := json.Unmarshal(claimsJSON, &claims); err != nil {
		return Identity{}, fmt.Errorf("%w: malformed claims", ErrUnauthenticated)
	}
	now := time.Now()
	if claims.Exp == 0 || now.After(time.Unix(claims.Exp, 0).Add(tokenLeeway)) {
		return Identity{}, fmt.Errorf("%w: token expired", ErrUnauthenticated)
	}
	if claims.Nbf != 0 && now.Before(time.Unix(claims.Nbf, 0).Add(-tokenLeeway)) {
		return Identity{}, fmt.Errorf("%w: token not yet valid", ErrUnauthenticated)
	}
	if claims.Iss != a.issuer {
		return Identity{}, fmt.Errorf("%w: wrong issuer", ErrUnauthenticated)
	}
	if !audienceContains(claims.Aud, a.audience) {
		return Identity{}, fmt.Errorf("%w: token is not for this host (aud)", ErrUnauthenticated)
	}
	if !strings.HasPrefix(claims.Sub, "did:") || len(claims.Sub) == len("did:") {
		return Identity{}, fmt.Errorf("%w: sub must be a DID", ErrUnauthenticated)
	}
	scopes, err := identity.ParseScope(claims.Scope)
	if err != nil {
		return Identity{}, fmt.Errorf("%w: %v", ErrUnauthenticated, err)
	}
	if claims.Cnf == nil || claims.Cnf.JKT == "" {
		return Identity{}, fmt.Errorf("%w: token is not bound to a key (cnf.jkt)", ErrUnauthenticated)
	}
	// The proof is checked last, and recorded only once everything else
	// passed: it is single-use, and a request refused for its token or its
	// key should not spend it.
	if cred.Proof == "" {
		return Identity{}, fmt.Errorf("%w: a DPoP proof header is required", ErrUnauthenticated)
	}
	jkt, err := a.proofs.Verify(cred.Proof, cred.Method, a.audience+cred.Path, raw)
	if err != nil {
		// Every proof failure wraps dpop.ErrInvalid; anything else is this
		// host's trouble, not the caller's credentials. (Replays are caught by
		// remember below, which owns the proof store.)
		if !errors.Is(err, dpop.ErrInvalid) {
			return Identity{}, fmt.Errorf("%w: %v", ErrUnavailable, err)
		}
		return Identity{}, fmt.Errorf("%w: %v", ErrUnauthenticated, err)
	}
	if jkt != claims.Cnf.JKT {
		return Identity{}, fmt.Errorf("%w: the DPoP proof is not from the key the token is bound to", ErrUnauthenticated)
	}
	if err := a.remember(ctx, cred.Proof, jkt, claims.Sub); err != nil {
		return Identity{}, err
	}
	return Identity{DID: claims.Sub, Scopes: scopes}, nil
}

// remember records a proof that passed every other check, so it is accepted
// once. Only an accepted request spends its proof, and a caller over its share
// is refused alone.
func (a *JWKSAuthenticator) remember(ctx context.Context, proof, jkt, sub string) error {
	jti, err := proofID(proof)
	if err != nil {
		return fmt.Errorf("%w: %v", ErrUnauthenticated, err)
	}
	limit := a.perSubject
	if a.unlimited[sub] {
		limit = 0
	}
	now := time.Now()
	err = a.replay.RecordProof(ctx, store.Proof{JKT: jkt, JTI: jti, Subject: sub, Expires: now.Add(proofMaxAge + proofSkew)}, now, limit)
	switch {
	case err == nil:
		return nil
	case errors.Is(err, store.ErrProofReplayed):
		return fmt.Errorf("%w: invalid DPoP proof: proof replayed", ErrUnauthenticated)
	case errors.Is(err, store.ErrProofLimit):
		return fmt.Errorf("%w: %v", ErrRateLimited, err)
	default:
		// A full memory store or a database that did not answer: this host's
		// capacity, not the caller's credentials.
		return fmt.Errorf("%w: %v", ErrUnavailable, err)
	}
}

// SweepProofs deletes expired proofs from ps every interval until ctx ends:
// the Postgres store keeps no expiry of its own.
func SweepProofs(ctx context.Context, ps store.ProofStore, every time.Duration, log zerolog.Logger) {
	t := time.NewTicker(every)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case now := <-t.C:
			if _, err := ps.DeleteExpiredProofs(ctx, now); err != nil && ctx.Err() == nil {
				log.Warn().Err(err).Msg("could not delete expired DPoP proofs")
			}
		}
	}
}

// proofID reads the jti of a proof Verify has accepted.
func proofID(proof string) (string, error) {
	parts := strings.Split(proof, ".")
	if len(parts) != 3 {
		return "", errors.New("malformed DPoP proof")
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return "", errors.New("malformed DPoP proof")
	}
	var c struct {
		JTI string `json:"jti"`
	}
	if err := json.Unmarshal(payload, &c); err != nil || c.JTI == "" {
		return "", errors.New("DPoP proof has no jti")
	}
	return c.JTI, nil
}

// audienceContains reports whether a JWT aud claim, a string or an array of
// strings, names want, this host's normalised URL. Each value is compared
// after the same normalisation (sameHostURL), so the host is one URL wherever
// it is named.
func audienceContains(raw json.RawMessage, want string) bool {
	var one string
	if json.Unmarshal(raw, &one) == nil {
		return one == want || sameHostURL(one, want)
	}
	var many []string
	if json.Unmarshal(raw, &many) == nil {
		for _, a := range many {
			if a == want || sameHostURL(a, want) {
				return true
			}
		}
	}
	return false
}
