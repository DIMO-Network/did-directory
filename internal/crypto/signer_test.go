package crypto

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"testing"

	"github.com/decred/dcrd/dcrec/secp256k1/v4"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestSignAndVerify_P256(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	data := []byte(`{"type":"plc_operation","rotationKeys":["did:key:z..."]}`)

	sig, err := SignOperation(key, data)
	require.NoError(t, err)
	assert.NotEmpty(t, sig)

	// Verify using the public key.
	err = VerifySignature(&key.PublicKey, data, sig)
	assert.NoError(t, err)
}

func TestSignAndVerify_Secp256k1(t *testing.T) {
	privKey, err := secp256k1.GeneratePrivateKey()
	require.NoError(t, err)

	ecdsaKey := privKey.ToECDSA()

	data := []byte(`{"type":"plc_operation","rotationKeys":["did:key:z..."]}`)

	sig, err := SignOperation(ecdsaKey, data)
	require.NoError(t, err)
	assert.NotEmpty(t, sig)

	pub := &ecdsa.PublicKey{
		Curve: secp256k1.S256(),
		X:     privKey.PubKey().X(),
		Y:     privKey.PubKey().Y(),
	}

	err = VerifySignature(pub, data, sig)
	assert.NoError(t, err)
}

func TestVerify_WrongData(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	data := []byte("original data")
	sig, err := SignOperation(key, data)
	require.NoError(t, err)

	// Verify with different data should fail.
	err = VerifySignature(&key.PublicKey, []byte("tampered data"), sig)
	assert.Error(t, err)
}

func TestVerify_WrongKey(t *testing.T) {
	key1, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	key2, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	data := []byte("test data")
	sig, err := SignOperation(key1, data)
	require.NoError(t, err)

	// Verify with wrong key should fail.
	err = VerifySignature(&key2.PublicKey, data, sig)
	assert.Error(t, err)
}

func TestVerifyWithDIDKey_P256(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	didKey, err := EncodeDIDKey(&key.PublicKey)
	require.NoError(t, err)

	data := []byte("sign this data")
	sig, err := SignOperation(key, data)
	require.NoError(t, err)

	err = VerifyWithDIDKey(didKey, data, sig)
	assert.NoError(t, err)
}

func TestDecodeSignature_InvalidBase64(t *testing.T) {
	_, _, err := DecodeSignature("not-valid-base64!!!", 32)
	assert.Error(t, err)
}

func TestDecodeSignature_WrongLength(t *testing.T) {
	// Create valid base64url but wrong length.
	hash := sha256.Sum256([]byte("test"))
	sig := hash[:16] // Too short.
	_ = sig
	_, _, err := DecodeSignature("AAAA", 32)
	assert.Error(t, err)
}
