package store

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestBusyNeedsSaturationAndCycling(t *testing.T) {
	s := &PostgresStore{}

	// Saturated and AcquireCount advancing: busy.
	assert.True(t, s.busy(4, 4, 100))
	assert.True(t, s.busy(4, 4, 150))

	// Saturated but flat across probes: possibly stuck, not busy.
	assert.False(t, s.busy(4, 4, 150))
	assert.False(t, s.busy(4, 4, 150))

	// Cycling again.
	assert.True(t, s.busy(4, 4, 160))

	// Not saturated: never busy, even while the count advances.
	assert.False(t, s.busy(3, 4, 200))
}
