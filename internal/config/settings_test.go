package config

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestLoadConfigLimitEnv(t *testing.T) {
	t.Setenv("MAX_OPERATIONS_PER_DID", "42")
	t.Setenv("EXPORT_PAGE_SIZE", "7")
	s, err := LoadConfig("/dev/null")
	require.NoError(t, err)
	require.Equal(t, 42, s.MaxOperationsPerDID)
	require.Equal(t, 7, s.ExportPageSize)
}

func TestLoadConfigLimitEnvDefaults(t *testing.T) {
	s, err := LoadConfig("/dev/null")
	require.NoError(t, err)
	require.Equal(t, 1000, s.MaxOperationsPerDID)
	require.Equal(t, 100, s.ExportPageSize)
}

func TestLoadConfigRejectsBadLimits(t *testing.T) {
	for _, name := range []string{"MAX_OPERATIONS_PER_DID", "EXPORT_PAGE_SIZE"} {
		for _, bad := range []string{"abc", "0", "-5", "1.5"} {
			t.Run(name+"="+bad, func(t *testing.T) {
				t.Setenv(name, bad)
				_, err := LoadConfig("/dev/null")
				require.ErrorContains(t, err, name)
			})
		}
	}
}
