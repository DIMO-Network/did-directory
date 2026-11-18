package did

import (
	"encoding/hex"
	"encoding/json"
	"os"
	"testing"

	dimocrypto "github.com/DIMO-Network/did-directory/internal/crypto"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func readVectorFile(t *testing.T, path string) VectorFile {
	t.Helper()
	raw, err := os.ReadFile(path)
	require.NoError(t, err)
	var f VectorFile
	require.NoError(t, json.Unmarshal(raw, &f))
	return f
}

func TestVectorsUpToDate(t *testing.T) {
	got, err := GenerateVectors()
	require.NoError(t, err)
	want := readVectorFile(t, "../../testdata/vectors/did-ops.json")
	require.Len(t, want.Cases, 8)
	for i := range got.Cases {
		got.Cases[i].Sig, want.Cases[i].Sig = "", "" // ECDSA is randomized
	}
	assert.Equal(t, want, got)
}

func TestVectorSignaturesVerify(t *testing.T) {
	f := readVectorFile(t, "../../testdata/vectors/did-ops.json")
	for _, c := range f.Cases {
		payload, _ := hex.DecodeString(c.PayloadHex)
		assert.NoError(t, dimocrypto.VerifyWithDIDKey(c.SignerDIDKey, payload, c.Sig), c.Name)
		marshalled, _ := json.Marshal(c.Unsigned)
		assert.Equal(t, c.PayloadHex, hex.EncodeToString(marshalled), c.Name)
	}
}

func TestGenesisVectorsDeriveDID(t *testing.T) {
	f := readVectorFile(t, "../../testdata/vectors/did-ops.json")
	for _, c := range f.Cases {
		if c.DID == "" {
			continue
		}
		op := &Operation{Type: c.Unsigned.Type, RotationKeys: c.Unsigned.RotationKeys, VerificationMethods: c.Unsigned.VerificationMethods, AlsoKnownAs: c.Unsigned.AlsoKnownAs, Services: c.Unsigned.Services}
		d, err := DeriveFromGenesis(op)
		require.NoError(t, err)
		assert.Equal(t, c.DID, d, c.Name)
	}
}
