package auth

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"math/big"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

const tokenTTL = 15 * time.Minute

// AssetClaim represents a single asset in the JWT claims.
type AssetClaim struct {
	DID         string   `json:"did"`
	Permissions []string `json:"permissions"`
	Storage     string   `json:"storage,omitempty"`
}

// Claims represents the custom JWT claims.
type Claims struct {
	jwt.RegisteredClaims
	Assets []AssetClaim `json:"assets"`
}

// TokenSigner manages JWT signing with an ECDSA key.
type TokenSigner struct {
	key   *ecdsa.PrivateKey
	keyID string
}

// NewTokenSigner creates a new token signer with the given private key.
func NewTokenSigner(key *ecdsa.PrivateKey) *TokenSigner {
	// Compute a key ID from the SHA-256 of the compressed public key.
	compressed := elliptic.MarshalCompressed(key.PublicKey.Curve, key.PublicKey.X, key.PublicKey.Y)
	hash := sha256.Sum256(compressed)
	kid := base64.RawURLEncoding.EncodeToString(hash[:8])

	return &TokenSigner{
		key:   key,
		keyID: kid,
	}
}

// Sign generates a signed JWT with the given claims.
func (s *TokenSigner) Sign(sub string, assets []AssetClaim, audience []string) (string, error) {
	now := time.Now().UTC()

	claims := Claims{
		RegisteredClaims: jwt.RegisteredClaims{
			Issuer:    "https://auth.dimo.zone",
			Subject:   sub,
			Audience:  audience,
			IssuedAt:  jwt.NewNumericDate(now),
			ExpiresAt: jwt.NewNumericDate(now.Add(tokenTTL)),
		},
		Assets: assets,
	}

	token := jwt.NewWithClaims(jwt.SigningMethodES256, claims)
	token.Header["kid"] = s.keyID

	return token.SignedString(s.key)
}

// JWKS returns the JWKS representation of the signing public key.
func (s *TokenSigner) JWKS() map[string]interface{} {
	pub := &s.key.PublicKey

	return map[string]interface{}{
		"keys": []map[string]interface{}{
			{
				"kty": "EC",
				"crv": "P-256",
				"use": "sig",
				"alg": "ES256",
				"kid": s.keyID,
				"x":   base64.RawURLEncoding.EncodeToString(padToN(pub.X, 32)),
				"y":   base64.RawURLEncoding.EncodeToString(padToN(pub.Y, 32)),
			},
		},
	}
}

func padToN(i *big.Int, n int) []byte {
	b := i.Bytes()
	if len(b) >= n {
		return b
	}
	padded := make([]byte, n)
	copy(padded[n-len(b):], b)
	return padded
}

// Issuer returns the issuer string used in tokens.
func (s *TokenSigner) Issuer() string {
	return "https://auth.dimo.zone"
}

// KeyID returns the key ID used in the JWT header.
func (s *TokenSigner) KeyID() string {
	return s.keyID
}

// PublicKey returns the public key for verification.
func (s *TokenSigner) PublicKey() *ecdsa.PublicKey {
	return &s.key.PublicKey
}

// VerifyToken parses and verifies a JWT token string. Exported for testing.
func (s *TokenSigner) VerifyToken(tokenStr string) (*Claims, error) {
	token, err := jwt.ParseWithClaims(tokenStr, &Claims{}, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodECDSA); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}
		return &s.key.PublicKey, nil
	})
	if err != nil {
		return nil, fmt.Errorf("parse token: %w", err)
	}

	claims, ok := token.Claims.(*Claims)
	if !ok || !token.Valid {
		return nil, fmt.Errorf("invalid token claims")
	}

	return claims, nil
}
