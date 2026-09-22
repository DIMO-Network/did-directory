package crypto

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"testing"

	"github.com/decred/dcrd/dcrec/secp256k1/v4"
	"github.com/multiformats/go-multicodec"
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

	assert.Equal(t, multicodec.P256Pub, decoded.Codec())
	assert.Equal(t, didKey, decoded.DIDKey())
	assert.True(t, decoded.p256.Equal(&key.PublicKey))
}

func TestEncodeDecode_Secp256k1(t *testing.T) {
	privKey, err := secp256k1.GeneratePrivateKey()
	require.NoError(t, err)

	pub := FromSecp256k1(privKey.PubKey())
	didKey := pub.DIDKey()

	assert.Contains(t, didKey, "did:key:z")

	decoded, err := DecodeDIDKey(didKey)
	require.NoError(t, err)

	assert.Equal(t, multicodec.Secp256k1Pub, decoded.Codec())
	assert.Equal(t, didKey, decoded.DIDKey())
	assert.True(t, decoded.k1.IsEqual(privKey.PubKey()))
}

func TestFromECDSA_RejectsOtherCurves(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	require.NoError(t, err)

	_, err = FromECDSA(&key.PublicKey)
	assert.Error(t, err)

	_, err = EncodeDIDKey(&key.PublicKey)
	assert.Error(t, err)
}

func TestCompressed(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	pub, err := FromECDSA(&key.PublicKey)
	require.NoError(t, err)

	compressed := pub.Compressed()
	require.Len(t, compressed, 33)
	assert.Contains(t, []byte{0x02, 0x03}, compressed[0])

	// The compressed form must agree with the standard library's uncompressed
	// encoding: same X, and a prefix matching the parity of Y.
	uncompressed, err := key.PublicKey.Bytes()
	require.NoError(t, err)
	assert.Equal(t, uncompressed[1:33], compressed[1:])
	assert.Equal(t, 0x02|uncompressed[64]&1, compressed[0])

	k1, err := secp256k1.GeneratePrivateKey()
	require.NoError(t, err)
	assert.Equal(t, k1.PubKey().SerializeCompressed(), FromSecp256k1(k1.PubKey()).Compressed())
}

func TestDecodeDIDKey_Invalid(t *testing.T) {
	tests := []struct {
		name  string
		input string
	}{
		{"empty", ""},
		{"wrong prefix", "did:web:example.com"},
		{"no multibase", "did:key:"},
		{"invalid multibase", "did:key:xyz"},
		// Ed25519 multicodec (0xed) is not supported.
		{"unsupported codec", "did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := DecodeDIDKey(tt.input)
			assert.Error(t, err)
		})
	}
}

func TestDecodeDIDKey_PointNotOnCurve(t *testing.T) {
	// x = 1 has no point on P-256: 1^3 - 3*1 + b is a quadratic non-residue
	// mod p, so decompression must fail. Flipping bits in a real key's X is
	// not a substitute, since about half of all X values do lie on the curve.
	bad := make([]byte, 1+coordSize)
	bad[0] = 0x02
	bad[coordSize] = 1
	_, err := unmarshalP256Compressed(bad)
	assert.Error(t, err)

	bad[0] = 0x03
	_, err = unmarshalP256Compressed(bad)
	assert.Error(t, err)
}

func TestMultibase(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	pub, err := FromECDSA(&key.PublicKey)
	require.NoError(t, err)

	mb := pub.Multibase()
	assert.True(t, len(mb) > 0)
	// Multibase base58btc starts with 'z'.
	assert.Equal(t, byte('z'), mb[0])
	assert.Equal(t, "did:key:"+mb, pub.DIDKey())
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

		assert.True(t, decoded.p256.Equal(&key.PublicKey))
	}
}
