package identity

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestParseScope(t *testing.T) {
	got, err := ParseScope("  approve read ")
	require.NoError(t, err)
	assert.Equal(t, []string{ScopeRead, ScopeApprove}, got, "in Scopes order, whatever the claim's")
	assert.Equal(t, "read approve", FormatScope(got))

	for _, bad := range []string{"", "   ", "admin", "read admin", "read read"} {
		_, err := ParseScope(bad)
		assert.Error(t, err, "%q", bad)
	}
}
