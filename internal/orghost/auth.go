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
)

// ErrUnauthenticated is returned when a request carries no usable identity.
var ErrUnauthenticated = errors.New("unauthenticated")

// Authenticator answers "which DID is making this request". The v1
// implementation checks a dauth-issued identity token whose sub is the member
// DID (plan §1 decision B); it is an interface so tests and a later
// service-to-service scheme can supply their own.
type Authenticator interface {
	// Authenticate returns the DID behind the Authorization header, or
	// ErrUnauthenticated.
	Authenticate(ctx context.Context, authorization string) (string, error)
}

// tokenLeeway is how far a token's exp or nbf may disagree with this host's
// clock.
const tokenLeeway = time.Minute

// JWKSAuthenticator verifies RS256 identity tokens against a JSON Web Key Set,
// the way dauth publishes its signing keys. It enforces the signature, exp and
// nbf, and an issuer when one is configured; audience is left to the issuer's
// own conventions until dauth mints these tokens (plan §6 step 7).
type JWKSAuthenticator struct {
	issuer string
	fetch  func(ctx context.Context) ([]byte, error)

	mu        sync.RWMutex
	keys      map[string]*rsa.PublicKey
	fetchedAt time.Time
}

// jwksRefreshInterval bounds how often an unknown key id triggers a refetch.
const jwksRefreshInterval = time.Minute

// NewJWKSAuthenticator builds an authenticator over a static key set. issuer
// is the required iss claim, or "" to accept any.
func NewJWKSAuthenticator(jwksJSON []byte, issuer string) (*JWKSAuthenticator, error) {
	keys, err := parseJWKS(jwksJSON)
	if err != nil {
		return nil, err
	}
	return &JWKSAuthenticator{issuer: issuer, keys: keys, fetchedAt: time.Now()}, nil
}

// NewJWKSAuthenticatorFromURL fetches the key set from url now and again
// whenever a token names a key id it does not hold, at most once a minute.
func NewJWKSAuthenticatorFromURL(ctx context.Context, url, issuer string) (*JWKSAuthenticator, error) {
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
	a, err := NewJWKSAuthenticator(body, issuer)
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
func (a *JWKSAuthenticator) Authenticate(ctx context.Context, authorization string) (string, error) {
	raw, ok := strings.CutPrefix(authorization, "Bearer ")
	if !ok {
		return "", fmt.Errorf("%w: authorization header must use the Bearer scheme", ErrUnauthenticated)
	}
	parts := strings.Split(strings.TrimSpace(raw), ".")
	if len(parts) != 3 {
		return "", fmt.Errorf("%w: malformed token", ErrUnauthenticated)
	}
	headerJSON, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return "", fmt.Errorf("%w: malformed token header", ErrUnauthenticated)
	}
	var header struct {
		Alg string `json:"alg"`
		Kid string `json:"kid"`
	}
	if err := json.Unmarshal(headerJSON, &header); err != nil || header.Alg != "RS256" {
		return "", fmt.Errorf("%w: token must be RS256", ErrUnauthenticated)
	}
	pub, ok := a.key(ctx, header.Kid)
	if !ok {
		return "", fmt.Errorf("%w: unknown signing key", ErrUnauthenticated)
	}
	sig, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil {
		return "", fmt.Errorf("%w: malformed signature", ErrUnauthenticated)
	}
	digest := sha256.Sum256([]byte(parts[0] + "." + parts[1]))
	if err := rsa.VerifyPKCS1v15(pub, crypto.SHA256, digest[:], sig); err != nil {
		return "", fmt.Errorf("%w: invalid signature", ErrUnauthenticated)
	}

	claimsJSON, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return "", fmt.Errorf("%w: malformed claims", ErrUnauthenticated)
	}
	var claims struct {
		Iss string `json:"iss"`
		Sub string `json:"sub"`
		Exp int64  `json:"exp"`
		Nbf int64  `json:"nbf"`
	}
	if err := json.Unmarshal(claimsJSON, &claims); err != nil {
		return "", fmt.Errorf("%w: malformed claims", ErrUnauthenticated)
	}
	now := time.Now()
	if claims.Exp == 0 || now.After(time.Unix(claims.Exp, 0).Add(tokenLeeway)) {
		return "", fmt.Errorf("%w: token expired", ErrUnauthenticated)
	}
	if claims.Nbf != 0 && now.Before(time.Unix(claims.Nbf, 0).Add(-tokenLeeway)) {
		return "", fmt.Errorf("%w: token not yet valid", ErrUnauthenticated)
	}
	if a.issuer != "" && claims.Iss != a.issuer {
		return "", fmt.Errorf("%w: wrong issuer", ErrUnauthenticated)
	}
	if !strings.HasPrefix(claims.Sub, "did:") || len(claims.Sub) == len("did:") {
		return "", fmt.Errorf("%w: sub must be a DID", ErrUnauthenticated)
	}
	return claims.Sub, nil
}
