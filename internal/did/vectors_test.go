package did

import (
	"encoding/hex"
	"encoding/json"
	"os"
	"testing"
	"time"

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
	require.Len(t, want.Cases, 10)
	assert.Equal(t, want, got)
}

func TestVectorSignaturesVerify(t *testing.T) {
	f := readVectorFile(t, "../../testdata/vectors/did-ops.json")
	for _, c := range f.Cases {
		payload, err := hex.DecodeString(c.PayloadHex)
		require.NoError(t, err, c.Name)
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

func TestEscapingVectorCoverage(t *testing.T) {
	f := readVectorFile(t, "../../testdata/vectors/did-ops.json")
	var found bool
	for _, c := range f.Cases {
		if c.Name != "genesis-services-escaping" {
			continue
		}
		found = true
		raw, err := hex.DecodeString(c.PayloadHex)
		require.NoError(t, err)
		text := string(raw)
		for _, esc := range []string{`\u003c`, `\u003e`, `\u0026`, `\u2028`, `\u2029`} {
			assert.Contains(t, text, esc)
		}
	}
	require.True(t, found, "genesis-services-escaping case missing")
}

func TestOrgVectorsPassValidation(t *testing.T) {
	f := readVectorFile(t, "../../testdata/vectors/did-ops.json")
	ops := map[string]*Operation{}
	for _, c := range f.Cases {
		if c.Name != "org-genesis" && c.Name != "org-update-add-dimo-org" {
			continue
		}
		u := c.Unsigned
		ops[c.Name] = &Operation{Type: u.Type, RotationKeys: u.RotationKeys, VerificationMethods: u.VerificationMethods,
			AlsoKnownAs: u.AlsoKnownAs, Services: u.Services, Prev: u.Prev, Sig: c.Sig}
	}
	require.Len(t, ops, 2)
	genesis, update := ops["org-genesis"], ops["org-update-add-dimo-org"]
	require.NoError(t, ValidateCreate(genesis))
	require.NoError(t, ValidateUpdate(update))
	assert.Equal(t, []string{genesis.RotationKeys[0]}, update.RotationKeys)
	assert.Equal(t, "https://org-host.example.com", update.Services["dimo_org_host"].Endpoint)
	assert.Contains(t, update.VerificationMethods, "dimo_org")
	require.NoError(t, ValidateTransition(genesis, ResolveControlState("did:dimo:org", []Operation{*genesis}), update, time.Now()))
}
