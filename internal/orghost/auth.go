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

	"github.com/DIMO-Network/did-directory/pkg/dpop"
	"github.com/DIMO-Network/did-directory/pkg/identity"
)

// ErrUnauthenticated is returned when a request carries no usable identity.
var ErrUnauthenticated = errors.New("unauthenticated")

// Authenticator answers "which DID is making this request, and for what". The
// v1 implementation checks a dauth-issued identity token whose sub is the
// member DID (plan §1 decision B), bound to a DPoP key; it is an interface so
// tests and a later service-to-service scheme can supply their own.
type Authenticator interface {
	// Authenticate returns the identity behind the request's credentials, or
	// ErrUnauthenticated.
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
	proofs   *dpop.Verifier

	mu        sync.RWMutex
	keys      map[string]*rsa.PublicKey
	fetchedAt time.Time
}

// jwksRefreshInterval bounds how often an unknown key id triggers a refetch.
const jwksRefreshInterval = time.Minute

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
	return &JWKSAuthenticator{issuer: issuer, audience: audience, proofs: dpop.NewVerifier(), keys: keys, fetchedAt: time.Now()}, nil
}

// NewJWKSAuthenticatorFromURL fetches the key set from url now and again
// whenever a token names a key id it does not hold, at most once a minute.
func NewJWKSAuthenticatorFromURL(ctx context.Context, url, issuer, audience string) (*JWKSAuthenticator, error) {
	fetch := func(ctx context.Context) ([]byte, error) {
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
		if err != nil {
			return nil, err
		}
		resp, err := http.DefaultClient.Do(req)
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

func (a *JWKSAuthenticator) key(ctx context.Context, kid string) (*rsa.PublicKey, bool) {
	a.mu.RLock()
	k, ok := a.keys[kid]
	stale := time.Since(a.fetchedAt) > jwksRefreshInterval
	a.mu.RUnlock()
	if ok || a.fetch == nil || !stale {
		return k, ok
	}
	body, err := a.fetch(ctx)
	if err != nil {
		return nil, false
	}
	keys, err := parseJWKS(body)
	if err != nil {
		return nil, false
	}
	a.mu.Lock()
	a.keys, a.fetchedAt = keys, time.Now()
	k, ok = a.keys[kid]
	a.mu.Unlock()
	return k, ok
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
	// The proof is checked last: it is single-use, and a request refused for
	// its token should not spend it.
	if cred.Proof == "" {
		return Identity{}, fmt.Errorf("%w: a DPoP proof header is required", ErrUnauthenticated)
	}
	jkt, err := a.proofs.Verify(cred.Proof, cred.Method, strings.TrimRight(a.audience, "/")+cred.Path, raw)
	if err != nil {
		return Identity{}, fmt.Errorf("%w: %v", ErrUnauthenticated, err)
	}
	if jkt != claims.Cnf.JKT {
		return Identity{}, fmt.Errorf("%w: the DPoP proof is not from the key the token is bound to", ErrUnauthenticated)
	}
	return Identity{DID: claims.Sub, Scopes: scopes}, nil
}

// audienceContains reports whether a JWT aud claim, a string or an array of
// strings, names want.
func audienceContains(raw json.RawMessage, want string) bool {
	var one string
	if json.Unmarshal(raw, &one) == nil {
		return one == want
	}
	var many []string
	if json.Unmarshal(raw, &many) == nil {
		for _, a := range many {
			if a == want {
				return true
			}
		}
	}
	return false
}
