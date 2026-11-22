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
	s, err = LoadSettings("../../org-host.sample.yaml")
	require.NoError(t, err)
	assert.Equal(t, 3, s.RegisterRateLimitPerCallerPerMinute)
	assert.Equal(t, 200, s.RegisterMaxPerDay)

	t.Setenv("REGISTER_RATE_LIMIT_PER_CALLER_PER_MINUTE", "1")
	t.Setenv("ORG_REGISTER_MAX_PER_DAY", "0")
	s, err = LoadSettings("/nonexistent")
	require.NoError(t, err)
	assert.Equal(t, 1, s.RegisterRateLimitPerCallerPerMinute)
	assert.Equal(t, 0, s.RegisterMaxPerDay, "0 disables the cap")
}
