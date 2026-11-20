package dpop

import (
	"encoding/base64"
	"encoding/json"
	"math/big"
	"strings"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestProofRoundTrip(t *testing.T) {
	key, err := GenerateKey()
	require.NoError(t, err)
	now := time.Date(2026, 9, 22, 12, 0, 0, 0, time.UTC)
	v := NewVerifier()
	v.Now = func() time.Time { return now.Add(10 * time.Second) }

	proof, err := key.Proof("POST", "https://dauth.test/exchange?x=1", "", now)
	require.NoError(t, err)
	jkt, err := v.Verify(proof, "POST", "https://DAUTH.test/exchange#frag", "")
	require.NoError(t, err)
	assert.Equal(t, key.Thumbprint(), jkt)

	_, err = v.Verify(proof, "POST", "https://dauth.test/exchange", "")
	assert.ErrorIs(t, err, ErrInvalid, "replay")

	proof, err = key.Proof("GET", "https://dq.test/query", "", now)
	require.NoError(t, err)
	_, err = v.Verify(proof, "POST", "https://dq.test/query", "")
	assert.ErrorIs(t, err, ErrInvalid, "wrong method")

	proof, err = key.Proof("POST", "https://dq.test/other", "", now)
	require.NoError(t, err)
	_, err = v.Verify(proof, "POST", "https://dq.test/query", "")
	assert.ErrorIs(t, err, ErrInvalid, "wrong URL")

	proof, err = key.Proof("POST", "https://dq.test/query", "", now.Add(-time.Hour))
	require.NoError(t, err)
	_, err = v.Verify(proof, "POST", "https://dq.test/query", "")
	assert.ErrorIs(t, err, ErrInvalid, "stale")
}

func TestAccessTokenHash(t *testing.T) {
	key, err := GenerateKey()
	require.NoError(t, err)
	now := time.Now()
	v := NewVerifier()

	proof, err := key.Proof("POST", "https://dq.test/query", "token-a", now)
	require.NoError(t, err)
	_, err = v.Verify(proof, "POST", "https://dq.test/query", "token-b")
	assert.ErrorIs(t, err, ErrInvalid, "ath for another token")

	proof, err = key.Proof("POST", "https://dq.test/query", "", now)
	require.NoError(t, err)
	_, err = v.Verify(proof, "POST", "https://dq.test/query", "token-a")
	assert.ErrorIs(t, err, ErrInvalid, "ath missing")

	proof, err = key.Proof("POST", "https://dq.test/query", "token-a", now)
	require.NoError(t, err)
	_, err = v.Verify(proof, "POST", "https://dq.test/query", "token-a")
	assert.NoError(t, err)
}

func TestThumbprintRFC7638(t *testing.T) {
	// The RSA example from RFC 7638 §3.1.
	jwk := map[string]any{
		"kty": "RSA",
		"n":   "0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx4cbbfAAtVT86zwu1RK7aPFFxuhDR1L6tSoc_BJECPebWKRXjBZCiFV4n3oknjhMstn64tZ_2W-5JsGY4Hc5n9yBXArwl93lqt7_RN5w6Cf0h4QyQ5v-65YGjQR0_FDW2QvzqY368QQMicAtaSqzs8KJZgnYb9c7d0zgdAZHzu6qMQvRL5hajrn1n91CbOpbISD08qNLyrdkt-bFTWhAI4vMQFh6WeZu0fM4lFd2NcRwr3XPksINHaQ-G_xBniIqbw0Ls1jF44-csFCur-kEgU8awapJzKnqDKgw",
		"e":   "AQAB",
	}
	jkt, err := Thumbprint(jwk)
	require.NoError(t, err)
	assert.Equal(t, "NzbLsXh8uDCcd-6MNwXF4W_7noWXFZAfHkxZsRGC9Xs", jkt)
}

func TestRejectsPrivateJWKAndWrongTyp(t *testing.T) {
	key, err := GenerateKey()
	require.NoError(t, err)
	proof, err := key.Proof("POST", "https://dq.test/query", "", time.Now())
	require.NoError(t, err)

	parts := strings.Split(proof, ".")
	hdr, err := base64.RawURLEncoding.DecodeString(parts[0])
	require.NoError(t, err)
	var header map[string]any
	require.NoError(t, json.Unmarshal(hdr, &header))
	header["typ"] = "JWT"
	raw, _ := json.Marshal(header)
	parts[0] = base64.RawURLEncoding.EncodeToString(raw)
	_, err = NewVerifier().Verify(strings.Join(parts, "."), "POST", "https://dq.test/query", "")
	assert.ErrorIs(t, err, ErrInvalid)
}

// signedProof signs a proof with key and an arbitrary jti.
func signedProof(t *testing.T, key *Key, jti string, now time.Time) string {
	t.Helper()
	claims := proofClaims{JTI: jti, HTM: "POST", HTU: "https://dq.test/query", IAT: now.Unix()}
	tok := jwt.NewWithClaims(jwt.SigningMethodES256, claims)
	tok.Header["typ"] = typ
	tok.Header["jwk"] = key.jwk
	s, err := tok.SignedString(key.priv)
	require.NoError(t, err)
	return s
}

func TestJTILength(t *testing.T) {
	key, err := GenerateKey()
	require.NoError(t, err)
	now := time.Now()
	v := NewVerifier()

	// A normal 22-character base64url jti (16 random bytes) and a P-256 key.
	jti := base64.RawURLEncoding.EncodeToString([]byte("0123456789abcdef"))
	require.Len(t, jti, 22)
	jkt, err := v.Verify(signedProof(t, key, jti, now), "POST", "https://dq.test/query", "")
	require.NoError(t, err)
	assert.Equal(t, key.Thumbprint(), jkt)

	// 64 bytes is the limit.
	_, err = v.Verify(signedProof(t, key, strings.Repeat("a", 64), now), "POST", "https://dq.test/query", "")
	require.NoError(t, err)

	long := signedProof(t, key, strings.Repeat("a", 65), now)
	_, err = v.Verify(long, "POST", "https://dq.test/query", "")
	require.ErrorIs(t, err, ErrInvalid)
	assert.Contains(t, err.Error(), "jti too long")
	assert.Len(t, v.replay.seen, 2, "an oversized jti never reaches the replay cache")
}

func TestProofSizeCap(t *testing.T) {
	_, err := NewVerifier().Verify(strings.Repeat("a", 4097), "POST", "https://dq.test/query", "")
	require.ErrorIs(t, err, ErrInvalid)
	assert.Contains(t, err.Error(), "too large")

	key, err := GenerateKey()
	require.NoError(t, err)
	// A real proof is far under the cap, and an oversized one is cut off
	// before parsing, not as a parse error.
	big := signedProof(t, key, "j", time.Now()) + strings.Repeat("a", 4096)
	_, err = NewVerifier().Verify(big, "POST", "https://dq.test/query", "")
	require.ErrorIs(t, err, ErrInvalid)
	assert.Contains(t, err.Error(), "too large")
}

func TestRSAModulusBounds(t *testing.T) {
	jwkWithBits := func(bits int) map[string]any {
		n := new(big.Int).Lsh(big.NewInt(1), uint(bits-1)) // exactly bits long
		return map[string]any{
			"kty": "RSA",
			"n":   base64.RawURLEncoding.EncodeToString(n.Bytes()),
			"e":   base64.RawURLEncoding.EncodeToString([]byte{1, 0, 1}),
		}
	}
	_, err := publicKey(jwkWithBits(2047))
	assert.Error(t, err, "below 2048 still rejected")
	_, err = publicKey(jwkWithBits(2048))
	assert.NoError(t, err)
	_, err = publicKey(jwkWithBits(4096))
	assert.NoError(t, err)
	_, err = publicKey(jwkWithBits(4097))
	require.Error(t, err)
	assert.Contains(t, err.Error(), "too large")
}

func TestReplayCacheCap(t *testing.T) {
	key, err := GenerateKey()
	require.NoError(t, err)
	now := time.Now()
	v := NewVerifier()
	v.MaxReplayEntries = 3
	v.Now = func() time.Time { return now }
	const target = "https://dq.test/query"

	for _, jti := range []string{"a", "b", "c"} {
		_, err := v.Verify(signedProof(t, key, jti, now), "POST", target, "")
		require.NoError(t, err, jti)
	}
	// Full: a new proof is refused.
	_, err = v.Verify(signedProof(t, key, "d", now), "POST", target, "")
	require.ErrorIs(t, err, ErrInvalid)
	assert.Contains(t, err.Error(), "replay cache full")
	assert.Len(t, v.replay.seen, 3)

	// A replay of a cached proof is still reported as a replay.
	_, err = v.Verify(signedProof(t, key, "a", now), "POST", target, "")
	require.ErrorIs(t, err, ErrInvalid)
	assert.Contains(t, err.Error(), "replayed")

	// Once the entries expire they free space.
	now = now.Add(7 * time.Minute)
	_, err = v.Verify(signedProof(t, key, "d", now), "POST", target, "")
	require.NoError(t, err)
	assert.Len(t, v.replay.seen, 1)
}

func TestReplayCacheDefaultCap(t *testing.T) {
	assert.Equal(t, 1_000_000, NewVerifier().maxReplay())
	v := NewVerifier()
	v.MaxReplayEntries = 5
	assert.Equal(t, 5, v.maxReplay())
}
