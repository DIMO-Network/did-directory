package crypto

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"testing"

	"github.com/decred/dcrd/dcrec/secp256k1/v4"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestEncodeDecode_P256(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	didKey, err := EncodeDIDKey(&key.PublicKey)
	require.NoError(t, err)

	assert.Contains(t, didKey, "did:key:z")

	decoded, err := DecodeDIDKey(didKey)
	require.NoError(t, err)

	assert.Equal(t, key.PublicKey.X.Cmp(decoded.X), 0)
	assert.Equal(t, key.PublicKey.Y.Cmp(decoded.Y), 0)
}

func TestEncodeDecode_Secp256k1(t *testing.T) {
	privKey, err := secp256k1.GeneratePrivateKey()
	require.NoError(t, err)

	pub := &ecdsa.PublicKey{
		Curve: secp256k1.S256(),
		X:     privKey.PubKey().X(),
		Y:     privKey.PubKey().Y(),
	}

	didKey, err := EncodeDIDKey(pub)
	require.NoError(t, err)

	assert.Contains(t, didKey, "did:key:z")

	decoded, err := DecodeDIDKey(didKey)
	require.NoError(t, err)

	assert.Equal(t, pub.X.Cmp(decoded.X), 0)
	assert.Equal(t, pub.Y.Cmp(decoded.Y), 0)
}

func TestCurveType_P256(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	didKey, err := EncodeDIDKey(&key.PublicKey)
	require.NoError(t, err)

	ct, err := CurveType(didKey)
	require.NoError(t, err)
	assert.Equal(t, "EcdsaSecp256r1VerificationKey2019", ct)

	assert.True(t, IsP256Key(didKey))
	assert.False(t, IsSecp256k1Key(didKey))
}

func TestCurveType_Secp256k1(t *testing.T) {
	privKey, err := secp256k1.GeneratePrivateKey()
	require.NoError(t, err)

	pub := &ecdsa.PublicKey{
		Curve: secp256k1.S256(),
		X:     privKey.PubKey().X(),
		Y:     privKey.PubKey().Y(),
	}

	didKey, err := EncodeDIDKey(pub)
	require.NoError(t, err)

	ct, err := CurveType(didKey)
	require.NoError(t, err)
	assert.Equal(t, "EcdsaSecp256k1VerificationKey2019", ct)

	assert.True(t, IsSecp256k1Key(didKey))
	assert.False(t, IsP256Key(didKey))
}

func TestDecodeDIDKey_Invalid(t *testing.T) {
	tests := []struct {
		name   string
		input  string
	}{
		{"empty", ""},
		{"wrong prefix", "did:web:example.com"},
		{"no multibase", "did:key:"},
		{"invalid multibase", "did:key:xyz"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := DecodeDIDKey(tt.input)
			assert.Error(t, err)
		})
	}
}

func TestPublicKeyMultibase(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	mb, err := PublicKeyMultibase(&key.PublicKey)
	require.NoError(t, err)

	assert.True(t, len(mb) > 0)
	// Multibase base58btc starts with 'z'.
	assert.Equal(t, byte('z'), mb[0])
}

func TestRoundTrip_MultipleKeys(t *testing.T) {
	// Generate several keys and ensure roundtrip works for each.
	for i := 0; i < 5; i++ {
		key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		require.NoError(t, err)

		didKey, err := EncodeDIDKey(&key.PublicKey)
		require.NoError(t, err)

		decoded, err := DecodeDIDKey(didKey)
		require.NoError(t, err)

		assert.True(t, key.PublicKey.Equal(decoded), "key %d roundtrip failed", i)
	}
}
