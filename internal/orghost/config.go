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
	// Signer picks where new orgs' #dimo_org keys live: "local" (sealed under
	// MASTER_KEY, the default) or "kms". Orgs already registered keep the backend
	// their row names, whatever this says.
	Signer string `yaml:"ORG_SIGNER"`
	// KMSRegion is the AWS region of the KMS keys; empty uses the SDK default.
	KMSRegion string `yaml:"KMS_REGION"`
	// KMSAliasPrefix prefixes each org key's alias; it must start with "alias/".
	// Give each environment its own (alias/dimo-org/prod/): the rest of the
	// alias is derived from the org DID alone.
	KMSAliasPrefix string `yaml:"KMS_ALIAS_PREFIX"`
	// IdentityJWKSURL is where the identity token issuer publishes its signing
	// keys; IdentityJWKS is the same key set given inline, for development.
	IdentityJWKSURL string `yaml:"IDENTITY_JWKS_URL"`
	IdentityJWKS    string `yaml:"IDENTITY_JWKS"`
	// IdentityIssuer is the iss claim identity tokens must carry, and
	// IdentityAudience a value their aud must contain: this host's own public
	// URL, which is what a member asks dauth for when signing in to write here.
	// Both are required.
	IdentityIssuer   string `yaml:"IDENTITY_ISSUER"`
	IdentityAudience string `yaml:"IDENTITY_AUDIENCE"`
	// PublicURL is this host's own URL, which an org's DID must publish as its
	// #dimo_org_host for the org to register here. Empty means
	// IdentityAudience, which is the same URL unless tokens name the host by
	// another one. See HostURL.
	PublicURL string `yaml:"PUBLIC_URL"`
	// RegisterRateLimitPerMinute bounds registers host-wide in any rolling
	// minute, since under KMS each one makes a billable key; 0 disables it.
	RegisterRateLimitPerMinute int `yaml:"REGISTER_RATE_LIMIT_PER_MINUTE"`
	// RegisterRateLimitPerCallerPerMinute bounds one caller's registers in any
	// rolling minute, so no single DID can spend the host-wide minute; 0
	// disables it.
	RegisterRateLimitPerCallerPerMinute int `yaml:"REGISTER_RATE_LIMIT_PER_CALLER_PER_MINUTE"`
	// RegisterMaxPerDay caps the orgs this host (every replica sharing its
	// database) creates in any rolling 24 hours. Past it registers are refused
	// and the host logs at error level, which is the alarm to page on. 0
	// disables it.
	RegisterMaxPerDay int `yaml:"ORG_REGISTER_MAX_PER_DAY"`
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
	s := &Settings{Port: 8081, LogLevel: "info", PageSize: 100, Signer: "local", KMSAliasPrefix: "alias/dimo-org/",
		RegisterRateLimitPerMinute: 10, RegisterRateLimitPerCallerPerMinute: 3, RegisterMaxPerDay: 200}
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
	env("ORG_SIGNER", &s.Signer)
	env("KMS_REGION", &s.KMSRegion)
	env("KMS_ALIAS_PREFIX", &s.KMSAliasPrefix)
	env("IDENTITY_JWKS_URL", &s.IdentityJWKSURL)
	env("IDENTITY_JWKS", &s.IdentityJWKS)
	env("IDENTITY_ISSUER", &s.IdentityIssuer)
	env("IDENTITY_AUDIENCE", &s.IdentityAudience)
	env("PUBLIC_URL", &s.PublicURL)
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
	envInt := func(name string, dst *int) {
		if v := os.Getenv(name); v != "" {
			if p, err := strconv.Atoi(v); err == nil {
				*dst = p
			}
		}
	}
	envInt("REGISTER_RATE_LIMIT_PER_MINUTE", &s.RegisterRateLimitPerMinute)
	envInt("REGISTER_RATE_LIMIT_PER_CALLER_PER_MINUTE", &s.RegisterRateLimitPerCallerPerMinute)
	envInt("ORG_REGISTER_MAX_PER_DAY", &s.RegisterMaxPerDay)
	return s, nil
}

// HostURL is the URL an org's #dimo_org_host must equal: PublicURL, else
// IdentityAudience, without a trailing slash.
func (s *Settings) HostURL() string {
	u := s.PublicURL
	if u == "" {
		u = s.IdentityAudience
	}
	return strings.TrimRight(u, "/")
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
