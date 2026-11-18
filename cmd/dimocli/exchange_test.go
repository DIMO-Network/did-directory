package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"math/big"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// The proof is what dauth's pkg/dpop verifies: an ES256 JWS with the key in
// the header and the request bound in the claims. This checks the encoding
// without importing dauth, which depends on this module.
func TestDPoPProof(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	now := time.Date(2026, 9, 22, 12, 0, 0, 0, time.UTC)

	proof, err := dpopProof(key, "POST", "http://localhost:8080/exchange", "", now)
	require.NoError(t, err)
	parts := strings.Split(proof, ".")
	require.Len(t, parts, 3)

	var header struct {
		Typ string            `json:"typ"`
		Alg string            `json:"alg"`
		JWK map[string]string `json:"jwk"`
	}
	raw, err := base64.RawURLEncoding.DecodeString(parts[0])
	require.NoError(t, err)
	require.NoError(t, json.Unmarshal(raw, &header))
	assert.Equal(t, "dpop+jwt", header.Typ)
	assert.Equal(t, "ES256", header.Alg)
	assert.Equal(t, "EC", header.JWK["kty"])
	assert.Equal(t, "P-256", header.JWK["crv"])
	x, err := base64.RawURLEncoding.DecodeString(header.JWK["x"])
	require.NoError(t, err)
	assert.Equal(t, key.X.FillBytes(make([]byte, 32)), x)

	var claims struct {
		JTI string `json:"jti"`
		HTM string `json:"htm"`
		HTU string `json:"htu"`
		IAT int64  `json:"iat"`
		ATH string `json:"ath"`
	}
	raw, err = base64.RawURLEncoding.DecodeString(parts[1])
	require.NoError(t, err)
	require.NoError(t, json.Unmarshal(raw, &claims))
	assert.Len(t, claims.JTI, 32)
	assert.Equal(t, "POST", claims.HTM)
	assert.Equal(t, "http://localhost:8080/exchange", claims.HTU)
	assert.Equal(t, now.Unix(), claims.IAT)
	assert.Empty(t, claims.ATH, "no token presented, no ath")

	sig, err := base64.RawURLEncoding.DecodeString(parts[2])
	require.NoError(t, err)
	require.Len(t, sig, 64, "JWS ES256 is r||s, 32 bytes each")
	digest := sha256.Sum256([]byte(parts[0] + "." + parts[1]))
	assert.True(t, ecdsa.Verify(&key.PublicKey, digest[:], new(big.Int).SetBytes(sig[:32]), new(big.Int).SetBytes(sig[32:])))

	again, err := dpopProof(key, "POST", "http://localhost:8080/exchange", "", now)
	require.NoError(t, err)
	assert.NotEqual(t, proof, again, "every proof has its own jti")

	// A proof for a request that presents a token hashes it into ath.
	bound, err := dpopProof(key, "POST", "http://localhost:3000/query", "the.access.token", now)
	require.NoError(t, err)
	raw, err = base64.RawURLEncoding.DecodeString(strings.Split(bound, ".")[1])
	require.NoError(t, err)
	require.NoError(t, json.Unmarshal(raw, &claims))
	sum := sha256.Sum256([]byte("the.access.token"))
	assert.Equal(t, base64.RawURLEncoding.EncodeToString(sum[:]), claims.ATH)
}

func TestDPoPProofNeedsP256(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	require.NoError(t, err)
	_, err = dpopProof(key, "POST", "http://localhost:8080/exchange", "", time.Now())
	assert.Error(t, err)
}

func TestJWTClaims(t *testing.T) {
	b64 := base64.RawURLEncoding.EncodeToString
	token := b64([]byte(`{"alg":"RS256"}`)) + "." + b64([]byte(`{"sub":"did:dimo:renter","grants":[{"subject":"did:dimo:car"}]}`)) + ".sig"
	out, err := jwtClaims(token)
	require.NoError(t, err)
	var claims map[string]any
	require.NoError(t, json.Unmarshal(out, &claims))
	assert.Equal(t, "did:dimo:renter", claims["sub"])

	_, err = jwtClaims("not.a-jwt")
	assert.Error(t, err)
}
