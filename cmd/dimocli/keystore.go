package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/DIMO-Network/did-directory/pkg/control"
)

// KeyEntry represents a stored key in the keystore.
type KeyEntry struct {
	DID              string `json:"did"`
	Curve            string `json:"curve"`
	PrivateKeyBase64 string `json:"privateKeyBase64"`
	CreatedAt        string `json:"createdAt"`
}

func keystoreDir() string {
	home, err := os.UserHomeDir()
	if err != nil {
		home = "."
	}
	return filepath.Join(home, ".dimo", "keys")
}

func keyFilePath(did string) string {
	// Strip "did:dimo:" prefix for the filename.
	name := strings.TrimPrefix(did, "did:dimo:")
	return filepath.Join(keystoreDir(), name+".json")
}

// SaveKey stores a private key to the keystore.
func SaveKey(did string, key *ecdsa.PrivateKey) error {
	return writeKey(keyFilePath(did), did, key)
}

// writeKey stores key as a KeyEntry at path, creating the keystore directory.
func writeKey(path, did string, key *ecdsa.PrivateKey) error {
	dir := keystoreDir()
	if err := os.MkdirAll(dir, 0700); err != nil {
		return fmt.Errorf("create keystore dir: %w", err)
	}

	pkcs8Bytes, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return fmt.Errorf("marshal private key: %w", err)
	}

	entry := KeyEntry{
		DID:              did,
		Curve:            key.Curve.Params().Name,
		PrivateKeyBase64: base64.StdEncoding.EncodeToString(pkcs8Bytes),
		CreatedAt:        time.Now().UTC().Format(time.RFC3339),
	}

	data, err := json.MarshalIndent(entry, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal key entry: %w", err)
	}

	if err := writeSecretFile(path, data); err != nil {
		return fmt.Errorf("write key file: %w", err)
	}

	return nil
}

// LoadKey reads a private key from the keystore.
func LoadKey(did string) (*ecdsa.PrivateKey, error) {
	return readKey(keyFilePath(did))
}

// readKey parses the KeyEntry at path.
func readKey(path string) (*ecdsa.PrivateKey, error) {
	data, err := readSecretFile(path)
	if err != nil {
		return nil, fmt.Errorf("read key file %s: %w", path, err)
	}

	var entry KeyEntry
	if err := json.Unmarshal(data, &entry); err != nil {
		return nil, fmt.Errorf("unmarshal key entry: %w", err)
	}

	keyBytes, err := base64.StdEncoding.DecodeString(entry.PrivateKeyBase64)
	if err != nil {
		return nil, fmt.Errorf("decode private key base64: %w", err)
	}

	// Try PKCS8 first.
	parsed, err := x509.ParsePKCS8PrivateKey(keyBytes)
	if err == nil {
		ecKey, ok := parsed.(*ecdsa.PrivateKey)
		if !ok {
			return nil, fmt.Errorf("key is not ECDSA")
		}
		return ecKey, nil
	}

	// Fallback: try raw 32-byte scalar for P-256.
	if len(keyBytes) == 32 {
		key, err := ecdsa.ParseRawPrivateKey(elliptic.P256(), keyBytes)
		if err != nil {
			return nil, fmt.Errorf("parse raw private key: %w", err)
		}
		return key, nil
	}

	return nil, fmt.Errorf("unable to parse private key")
}

func openingFilePath(did string) string {
	name := strings.TrimPrefix(did, "did:dimo:")
	return filepath.Join(keystoreDir(), name+".control.json")
}

// SaveOpening stores the private opening of a controlled DID's commitment.
// It stands in for the controller's network.dimo.org.vehicleControl record.
func SaveOpening(did string, o control.Opening) error {
	if err := os.MkdirAll(keystoreDir(), 0700); err != nil {
		return fmt.Errorf("create keystore dir: %w", err)
	}
	data, err := json.MarshalIndent(o, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal opening: %w", err)
	}
	if err := writeSecretFile(openingFilePath(did), data); err != nil {
		return fmt.Errorf("write opening file: %w", err)
	}
	return nil
}

// LoadOpening reads the private opening of a controlled DID's commitment.
func LoadOpening(did string) (*control.Opening, error) {
	path := openingFilePath(did)
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read opening file %s: %w", path, err)
	}
	var o control.Opening
	if err := json.Unmarshal(data, &o); err != nil {
		return nil, fmt.Errorf("unmarshal opening: %w", err)
	}
	return &o, nil
}

func dpopKeyFilePath(did string) string {
	name := strings.TrimPrefix(did, "did:dimo:")
	return filepath.Join(keystoreDir(), name+".dpop.json")
}

// SaveDPoPKey stores the P-256 key a Turnkey-rooted DID's tokens are bound to.
// It signs DPoP proofs only; the DID's own key stays in Turnkey.
func SaveDPoPKey(did string, key *ecdsa.PrivateKey) error {
	return writeKey(dpopKeyFilePath(did), did, key)
}

// LoadDPoPKey reads the key SaveDPoPKey stored.
func LoadDPoPKey(did string) (*ecdsa.PrivateKey, error) {
	return readKey(dpopKeyFilePath(did))
}
