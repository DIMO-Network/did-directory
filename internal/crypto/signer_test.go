package crypto

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/base64"
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
	pub, err := FromECDSA(&key.PublicKey)
	require.NoError(t, err)
	err = VerifySignature(pub, data, sig)
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

	// The signature came from the standard library's generic ECDSA over the
	// decred curve adaptor; verification goes through decred's own
	// implementation, so this also checks the two agree.
	pub := FromSecp256k1(privKey.PubKey())
	err = VerifySignature(pub, data, sig)
	assert.NoError(t, err)

	err = VerifySignature(pub, []byte("other data"), sig)
	assert.Error(t, err)

	other, err := secp256k1.GeneratePrivateKey()
	require.NoError(t, err)
	err = VerifySignature(FromSecp256k1(other.PubKey()), data, sig)
	assert.Error(t, err)
}

func TestVerify_WrongData(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	data := []byte("original data")
	sig, err := SignOperation(key, data)
	require.NoError(t, err)

	// Verify with different data should fail.
	pub, err := FromECDSA(&key.PublicKey)
	require.NoError(t, err)
	err = VerifySignature(pub, []byte("tampered data"), sig)
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
	pub2, err := FromECDSA(&key2.PublicKey)
	require.NoError(t, err)
	err = VerifySignature(pub2, data, sig)
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

func TestVerify_Secp256k1_ComponentOverflow(t *testing.T) {
	privKey, err := secp256k1.GeneratePrivateKey()
	require.NoError(t, err)
	pub := FromSecp256k1(privKey.PubKey())

	// r at 2^256-1 is above the group order and must be rejected rather
	// than reduced.
	sig := make([]byte, 64)
	for i := range sig[:32] {
		sig[i] = 0xff
	}
	sig[63] = 1
	err = VerifySignature(pub, []byte("data"), base64.RawURLEncoding.EncodeToString(sig))
	assert.Error(t, err)
}
