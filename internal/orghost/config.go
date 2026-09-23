package orghost

import (
	"os"
	"strconv"
	"strings"

	"gopkg.in/yaml.v3"
)

// Settings configures the org host. Environment variables override the YAML
// file, as for the directory.
type Settings struct {
	Port        int    `yaml:"PORT"`
	DatabaseURL string `yaml:"DATABASE_URL"`
	LogLevel    string `yaml:"LOG_LEVEL"`
	// MasterKey seals org signing keys at rest, base64 of 32 bytes. Required
	// with DATABASE_URL; the in-memory store runs under an ephemeral key.
	MasterKey string `yaml:"MASTER_KEY"`
	// IdentityJWKSURL is where the identity token issuer publishes its signing
	// keys; IdentityJWKS is the same key set given inline, for development.
	IdentityJWKSURL string `yaml:"IDENTITY_JWKS_URL"`
	IdentityJWKS    string `yaml:"IDENTITY_JWKS"`
	// IdentityIssuer is the iss claim identity tokens must carry, or "" for any.
	IdentityIssuer string `yaml:"IDENTITY_ISSUER"`
	// DirectoryURL is the DID directory, for control state (plan §3.3).
	DirectoryURL string `yaml:"DIRECTORY_URL"`
	// IssuerDIDs are the DIDs that may call POST /authorize: dauth's.
	IssuerDIDs []string `yaml:"ISSUER_DIDS"`
	// AdminDIDs are the DIDs that may set party attributes (decision E).
	AdminDIDs []string `yaml:"ADMIN_DIDS"`
	// PageSize bounds list and log responses.
	PageSize int `yaml:"PAGE_SIZE"`
	// ControlCacheTTL is how long a vehicle's control state read from the
	// directory is served before it is fetched again (a Go duration such as
	// 30s); empty means DefaultControlCacheTTL. A demo against a directory on
	// the same machine sets it low so a transfer shows at once.
	ControlCacheTTL string `yaml:"CONTROL_CACHE_TTL"`
}

// LoadSettings reads path, then applies environment overrides.
func LoadSettings(path string) (*Settings, error) {
	s := &Settings{Port: 8081, LogLevel: "info", PageSize: 100}
	if data, err := os.ReadFile(path); err == nil {
		if err := yaml.Unmarshal(data, s); err != nil {
			return nil, err
		}
	}
	env := func(name string, dst *string) {
		if v := os.Getenv(name); v != "" {
			*dst = v
		}
	}
	env("DATABASE_URL", &s.DatabaseURL)
	env("LOG_LEVEL", &s.LogLevel)
	env("MASTER_KEY", &s.MasterKey)
	env("IDENTITY_JWKS_URL", &s.IdentityJWKSURL)
	env("IDENTITY_JWKS", &s.IdentityJWKS)
	env("IDENTITY_ISSUER", &s.IdentityIssuer)
	env("DIRECTORY_URL", &s.DirectoryURL)
	env("CONTROL_CACHE_TTL", &s.ControlCacheTTL)
	// Comma-separated in the environment.
	if v := os.Getenv("ISSUER_DIDS"); v != "" {
		s.IssuerDIDs = splitList(v)
	}
	if v := os.Getenv("ADMIN_DIDS"); v != "" {
		s.AdminDIDs = splitList(v)
	}
	if v := os.Getenv("PORT"); v != "" {
		if p, err := strconv.Atoi(v); err == nil {
			s.Port = p
		}
	}
	if v := os.Getenv("PAGE_SIZE"); v != "" {
		if p, err := strconv.Atoi(v); err == nil {
			s.PageSize = p
		}
	}
	return s, nil
}

func splitList(v string) []string {
	var out []string
	for _, p := range strings.Split(v, ",") {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}
	return out
}
