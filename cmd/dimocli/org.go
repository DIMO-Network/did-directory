package main

import (
	"crypto/ecdsa"
	"fmt"
	"path/filepath"
	"strings"

	dimocrypto "github.com/DIMO-Network/did-directory/internal/crypto"
	"github.com/DIMO-Network/did-directory/internal/did"
)

// OrgKeyID is the verification method fragment that carries an org's
// repository commit signing key (spec §4, §6.2). The org host signs every
// commit with it and the DID document publishes the public half as
// <did>#dimo_org, which is what a coverage proof verifies against offline.
const OrgKeyID = "dimo_org"

// OrgHostServiceID is the service entry naming the org host that serves the
// org's repository (spec §6.2). DIMO hosts by default; a self-hosting org
// points it at its own host.
const OrgHostServiceID = "dimo_org_host"

// OrgHostServiceType is the service type of the #dimo_org_host entry, in the
// same style as DimoStorageNode for #dimo_storage.
const OrgHostServiceType = "DimoOrgHost"

// orgKeyFilePath is where the CLI keeps the private half of #dimo_org when it
// generated the key itself. In v1 the org host holds this key (plan §1 decision
// C); the file exists so a demo host can be seeded from the CLI. An org whose
// host generated its own key publishes the public half with --org-key instead
// and never has this file.
func orgKeyFilePath(did string) string {
	name := strings.TrimPrefix(did, "did:dimo:")
	return filepath.Join(keystoreDir(), name+".org.json")
}

// SaveOrgKey stores the private half of an org's #dimo_org key.
func SaveOrgKey(did string, key *ecdsa.PrivateKey) error {
	return writeKey(orgKeyFilePath(did), did, key)
}

// LoadOrgKey reads the private half of an org's #dimo_org key.
func LoadOrgKey(did string) (*ecdsa.PrivateKey, error) {
	return readKey(orgKeyFilePath(did))
}

// orgKeyChoice is how a create or update decides what to publish as #dimo_org.
type orgKeyChoice struct {
	// Given is a did:key supplied by the caller, whose private half lives with
	// the org host. It wins over Generate.
	Given string
	// Generate asks the CLI to mint a key and keep it in the keystore.
	Generate bool
}

func (c orgKeyChoice) wanted() bool { return c.Given != "" || c.Generate }

// resolveOrgKey returns the did:key to publish as #dimo_org and, when the CLI
// generated it, the private key to store.
func resolveOrgKey(c orgKeyChoice) (string, *ecdsa.PrivateKey, error) {
	if c.Given != "" {
		if _, err := dimocrypto.DecodeDIDKey(c.Given); err != nil {
			return "", nil, fmt.Errorf("invalid --org-key: %w", err)
		}
		return c.Given, nil, nil
	}
	if !c.Generate {
		return "", nil, nil
	}
	key, didKey, err := newKey()
	if err != nil {
		return "", nil, fmt.Errorf("generate org key: %w", err)
	}
	return didKey, key, nil
}

// withOrgKey returns a copy of vms with #dimo_org set to didKey.
func withOrgKey(vms map[string]string, didKey string) map[string]string {
	out := make(map[string]string, len(vms)+1)
	for k, v := range vms {
		out[k] = v
	}
	out[OrgKeyID] = didKey
	return out
}

// withOrgHost returns a copy of services with #dimo_org_host set to endpoint.
func withOrgHost(services map[string]did.Service, endpoint string) map[string]did.Service {
	out := make(map[string]did.Service, len(services)+1)
	for k, v := range services {
		out[k] = v
	}
	out[OrgHostServiceID] = did.Service{Type: OrgHostServiceType, Endpoint: endpoint}
	return out
}

// parseServices adds the id=type:endpoint entries of spec to services.
func parseServices(spec string, services map[string]did.Service) error {
	if spec == "" {
		return nil
	}
	for _, s := range strings.Split(spec, ",") {
		parts := strings.SplitN(s, "=", 2)
		if len(parts) != 2 {
			return fmt.Errorf("invalid service format: %s (expected id=type:endpoint)", s)
		}
		typeParts := strings.SplitN(parts[1], ":", 2)
		if len(typeParts) != 2 {
			return fmt.Errorf("invalid service value: %s (expected type:endpoint)", parts[1])
		}
		services[parts[0]] = did.Service{Type: typeParts[0], Endpoint: typeParts[1]}
	}
	return nil
}
