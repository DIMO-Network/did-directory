package main

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/DIMO-Network/did-directory/pkg/control"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// R3-F9: a key file group or others may read is refused, ssh-style, rather
// than used silently.
func TestKeyFiles_RefuseLoosePermissions(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	const did = "did:dimo:perm"
	key, _, err := newKey()
	require.NoError(t, err)
	require.NoError(t, SaveKey(did, key))
	path := keyFilePath(did)

	for _, mode := range []os.FileMode{0o644, 0o640, 0o604, 0o660} {
		require.NoError(t, os.Chmod(path, mode))
		_, err := LoadKey(did)
		require.Error(t, err, "%04o", mode)
		assert.Contains(t, err.Error(), "chmod 600", "%04o", mode)
	}
	for _, mode := range []os.FileMode{0o600, 0o400} {
		require.NoError(t, os.Chmod(path, mode))
		_, err := LoadKey(did)
		assert.NoError(t, err, "%04o", mode)
	}

	api, _ := writeAPIKey(t)
	require.NoError(t, os.Chmod(api, 0o644))
	_, err = loadTurnkeyAPIKey(api)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "chmod 600")

	pemPath := filepath.Join(t.TempDir(), "machine.pem")
	_, err = loadOrCreatePEMKey(pemPath)
	require.NoError(t, err)
	require.NoError(t, os.Chmod(pemPath, 0o644))
	_, err = loadOrCreatePEMKey(pemPath)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "chmod 600")
}

// R3-F9: every write leaves the file 0600, also over a file that was looser:
// os.WriteFile only sets the mode of a file it creates.
func TestKeyFiles_WriteTightensMode(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	require.NoError(t, os.MkdirAll(keystoreDir(), 0o700))
	const did = "did:dimo:loose"
	key, _, err := newKey()
	require.NoError(t, err)
	for name, write := range map[string]struct {
		path string
		save func() error
	}{
		"key":     {keyFilePath(did), func() error { return SaveKey(did, key) }},
		"dpop":    {dpopKeyFilePath(did), func() error { return SaveDPoPKey(did, key) }},
		"org key": {orgKeyFilePath(did), func() error { return SaveOrgKey(did, key) }},
		"opening": {openingFilePath(did), func() error {
			return SaveOpening(did, control.Opening{Controller: "did:dimo:x", Era: 0, Salt: "c2FsdA"})
		}},
	} {
		require.NoError(t, os.WriteFile(write.path, []byte("{}"), 0o644), name)
		require.NoError(t, os.Chmod(write.path, 0o644), name)
		require.NoError(t, write.save(), name)
		fi, err := os.Stat(write.path)
		require.NoError(t, err, name)
		assert.Equal(t, os.FileMode(0o600), fi.Mode().Perm(), name)
	}
}
