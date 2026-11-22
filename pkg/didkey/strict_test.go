package didkey

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/hex"
	"strings"
	"testing"
	"time"

	"github.com/decred/dcrd/dcrec/secp256k1/v4"
	"github.com/multiformats/go-multibase"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// canonicalKeys returns one P-256 and one secp256k1 key with their raw
// multikey bytes (minimal multicodec varint, then the compressed point).
func canonicalKeys(t *testing.T) []*PublicKey {
	t.Helper()
	p, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	p256, err := FromECDSA(&p.PublicKey)
	require.NoError(t, err)
	k, err := secp256k1.GeneratePrivateKey()
	require.NoError(t, err)
	return []*PublicKey{p256, FromSecp256k1(k.PubKey())}
}

func multikey(k *PublicKey) []byte {
	return append(multicodecVarint(uint64(k.codec)), k.Compressed()...)
}

// nonMinimalVarint pads a minimal varint with a redundant continuation byte:
// 0x80 0x24 (P-256) becomes 0x80 0xa4 0x00, which binary.Uvarint still reads
// as 0x1200.
func nonMinimalVarint(code uint64) []byte {
	v := multicodecVarint(code)
	v[len(v)-1] |= 0x80
	return append(v, 0x00)
}

// One key must have one string. Every other multibase base and every padded
// varint is refused, so consumers that compare did:keys as strings agree.
func TestDecode_RefusesNonCanonicalForms(t *testing.T) {
	for _, k := range canonicalKeys(t) {
		raw := multikey(k)
		padded := append(nonMinimalVarint(uint64(k.codec)), k.Compressed()...)
		b58Padded, err := multibase.Encode(multibase.Base58BTC, padded)
		require.NoError(t, err)

		forms := map[string]string{
			"hex (f)":                   "f" + hex.EncodeToString(raw),
			"non-minimal varint, hex":   "f" + hex.EncodeToString(padded),
			"non-minimal varint, z":     b58Padded,
			"base32 (b)":                mustEncode(t, multibase.Base32, raw),
			"base64url (u)":             mustEncode(t, multibase.Base64url, raw),
			"base58flickr (Z)":          mustEncode(t, multibase.Base58Flickr, raw),
			"base64 padded (M)":         mustEncode(t, multibase.Base64pad, raw),
			"identity (0x00)":           mustEncode(t, multibase.Identity, raw),
			"base58btc, leading zero 1": "z1" + k.Multibase()[1:],
		}
		for name, form := range forms {
			t.Run(k.codec.String()+"/"+name, func(t *testing.T) {
				_, err := DecodeMultibase(form)
				assert.Error(t, err, "DecodeMultibase accepted %q", form)
				_, err = Decode("did:key:" + form)
				assert.Error(t, err, "Decode accepted did:key:%s", form)
			})
		}

		// The canonical form still decodes, and re-encodes to itself.
		got, err := Decode(k.DIDKey())
		require.NoError(t, err)
		assert.Equal(t, k.DIDKey(), got.DIDKey())
	}
}

func TestDecode_ErrorsNameTheRule(t *testing.T) {
	k := canonicalKeys(t)[0]
	_, err := DecodeMultibase("f" + hex.EncodeToString(multikey(k)))
	require.Error(t, err)
	assert.Contains(t, err.Error(), "base58btc")

	padded, err := multibase.Encode(multibase.Base58BTC, append(nonMinimalVarint(uint64(k.codec)), k.Compressed()...))
	require.NoError(t, err)
	_, err = DecodeMultibase(padded)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "minimal")
}

// Whatever Decode accepts re-encodes to exactly the input: near misses of a
// real key (every single-character substitution) either fail or are a
// different key in canonical form.
func TestDecode_AcceptedMeansCanonical(t *testing.T) {
	const alphabet = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
	for _, k := range canonicalKeys(t) {
		s := k.DIDKey()
		for i := len("did:key:z"); i < len(s); i++ {
			for _, c := range alphabet {
				variant := s[:i] + string(c) + s[i+1:]
				got, err := Decode(variant)
				if err == nil {
					require.Equal(t, variant, got.DIDKey())
				}
			}
		}
	}
}

// base58 decoding is quadratic in the input length, so an oversized string
// is refused before it is decoded (R3-F1's 1 MB rotation key took 3 s).
func TestDecode_RefusesOversizedInputUnread(t *testing.T) {
	huge := "did:key:z" + strings.Repeat("2", 1_000_000)
	start := time.Now()
	_, err := Decode(huge)
	elapsed := time.Since(start)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "too long")
	assert.Less(t, elapsed, 50*time.Millisecond)

	_, err = DecodeMultibase(strings.Repeat("z", MaxLength))
	require.Error(t, err)
	assert.Contains(t, err.Error(), "too long")

	// Canonical keys of both curves are 57 bytes, far under the bound.
	for _, k := range canonicalKeys(t) {
		assert.Len(t, k.DIDKey(), 57)
		assert.LessOrEqual(t, len(k.DIDKey()), MaxLength)
	}
}

func mustEncode(t *testing.T, base multibase.Encoding, data []byte) string {
	t.Helper()
	s, err := multibase.Encode(base, data)
	require.NoError(t, err)
	return s
}
