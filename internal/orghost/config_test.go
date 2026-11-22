package orghost

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestLoadSettings_PublicURLAndRegisterLimit(t *testing.T) {
	t.Setenv("IDENTITY_AUDIENCE", "https://org-host.example/")
	s, err := LoadSettings("/nonexistent")
	require.NoError(t, err)
	assert.Equal(t, 10, s.RegisterRateLimitPerMinute, "10 registers a minute by default")
	assert.Equal(t, "https://org-host.example", s.HostURL(), "no PUBLIC_URL: the identity audience, without a trailing slash")

	t.Setenv("PUBLIC_URL", "https://orgs.dimo.example//")
	t.Setenv("REGISTER_RATE_LIMIT_PER_MINUTE", "0")
	s, err = LoadSettings("/nonexistent")
	require.NoError(t, err)
	assert.Equal(t, 0, s.RegisterRateLimitPerMinute, "0 disables the limit")
	assert.Equal(t, "https://orgs.dimo.example", s.HostURL())
}

func TestLoadSettings_SampleParses(t *testing.T) {
	s, err := LoadSettings("../../org-host.sample.yaml")
	require.NoError(t, err)
	assert.Equal(t, 10, s.RegisterRateLimitPerMinute)
	assert.Equal(t, "http://localhost:8081", s.HostURL())
	assert.Equal(t, "local", s.Signer)
}

func TestLoadSettings_RegisterBudgets(t *testing.T) {
	s, err := LoadSettings("/nonexistent")
	require.NoError(t, err)
	assert.Equal(t, 3, s.RegisterRateLimitPerCallerPerMinute, "3 registers a minute per caller by default")
	assert.Equal(t, 200, s.RegisterMaxPerDay, "200 new orgs a day by default")
	assert.Equal(t, 30, s.RegisterAttemptsPerCallerPerMinute, "30 register attempts a minute per caller by default")
	s, err = LoadSettings("../../org-host.sample.yaml")
	require.NoError(t, err)
	assert.Equal(t, 3, s.RegisterRateLimitPerCallerPerMinute)
	assert.Equal(t, 200, s.RegisterMaxPerDay)
	assert.Equal(t, 30, s.RegisterAttemptsPerCallerPerMinute)

	t.Setenv("REGISTER_RATE_LIMIT_PER_CALLER_PER_MINUTE", "1")
	t.Setenv("ORG_REGISTER_MAX_PER_DAY", "0")
	s, err = LoadSettings("/nonexistent")
	require.NoError(t, err)
	assert.Equal(t, 1, s.RegisterRateLimitPerCallerPerMinute)
	assert.Equal(t, 0, s.RegisterMaxPerDay, "0 disables the cap")
}

// Contract 5 (R7-F6): the host refuses to start when IDENTITY_AUDIENCE or
// PUBLIC_URL ends in "/". dauth issues audiences without one and accounts
// publishes the host URL without one, so either would silently break every
// sign-in or register. Neither may carry userinfo, a query or a fragment.
func TestSettings_ValidateURLs(t *testing.T) {
	for name, s := range map[string]Settings{
		"audience slash":     {IdentityAudience: "https://org-host.example/"},
		"public URL slash":   {IdentityAudience: "https://org-host.example", PublicURL: "https://org-host.example/"},
		"path slash":         {IdentityAudience: "https://api.example/org-host/"},
		"userinfo":           {IdentityAudience: "https://ops@org-host.example"},
		"query":              {IdentityAudience: "https://org-host.example?x=1"},
		"empty query":        {IdentityAudience: "https://org-host.example?"},
		"fragment":           {IdentityAudience: "https://org-host.example#f"},
		"not http":           {IdentityAudience: "org-host"},
		"no host":            {IdentityAudience: "https://"},
		"public URL garbage": {IdentityAudience: "https://org-host.example", PublicURL: "ftp://org-host.example"},
	} {
		assert.Error(t, s.Validate(), name)
	}
	err := (&Settings{IdentityAudience: "https://org-host.example/"}).Validate()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "IDENTITY_AUDIENCE")
	assert.Contains(t, err.Error(), `must not end in "/"`)

	for name, s := range map[string]Settings{
		"bare":        {IdentityAudience: "https://org-host.example"},
		"with public": {IdentityAudience: "http://org-host-dev:8081", PublicURL: "https://org-host.example"},
		"with path":   {IdentityAudience: "https://api.example/org-host"},
	} {
		assert.NoError(t, s.Validate(), name)
	}
}

// R4-F6: the host URL is normalised once, scheme and host lowercased and the
// default port dropped, and that one form is what the register gate compares.
func TestSettings_HostURLIsNormalised(t *testing.T) {
	s := Settings{IdentityAudience: "HTTPS://Org-Host.Example:443"}
	assert.Equal(t, "https://org-host.example", s.HostURL())
	s = Settings{IdentityAudience: "https://a.example", PublicURL: "http://Org-Host:80/Base"}
	assert.Equal(t, "http://org-host/Base", s.HostURL(), "the path keeps its case")
	s = Settings{IdentityAudience: "http://localhost:8081"}
	assert.Equal(t, "http://localhost:8081", s.HostURL())
}

func TestLoadSettings_DPoPProofsPerSubject(t *testing.T) {
	s, err := LoadSettings("../../org-host.sample.yaml")
	require.NoError(t, err)
	assert.Equal(t, DefaultProofsPerSubject, s.DPoPMaxProofsPerSubject)
	s, err = LoadSettings("/nonexistent")
	require.NoError(t, err)
	assert.Equal(t, 10_000, s.DPoPMaxProofsPerSubject)
	t.Setenv("DPOP_MAX_PROOFS_PER_SUBJECT", "50")
	s, err = LoadSettings("/nonexistent")
	require.NoError(t, err)
	assert.Equal(t, 50, s.DPoPMaxProofsPerSubject)
}

// Fix round 1, item 5: a URL that only normalises to the host URL is refused
// too, as the trailing slash is: the audience dauth issues is the URL as
// written, so it must be written in the one form every compare uses.
func TestSettings_ValidateRefusesNonNormalURLs(t *testing.T) {
	for _, raw := range []string{"https://orghost.test:443", "http://orghost.test:80", "HTTPS://orghost.test", "https://OrgHost.test"} {
		for name, s := range map[string]Settings{
			"audience":   {IdentityAudience: raw},
			"public URL": {IdentityAudience: "https://orghost.test", PublicURL: raw},
		} {
			err := s.Validate()
			require.Error(t, err, "%s %s", name, raw)
			assert.Contains(t, err.Error(), "normal form", "%s %s", name, raw)
		}
	}
	for _, raw := range []string{"https://orghost.test", "http://localhost:8081", "https://api.example/Org-Host", "https://orghost.test:8443"} {
		assert.NoError(t, (&Settings{IdentityAudience: raw}).Validate(), raw)
	}
}
