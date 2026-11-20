package dpop

import (
	"sync"
	"time"
)

// replayCache remembers accepted proof ids until they can no longer be
// presented, so a captured proof cannot be replayed within its window. It is
// per process; a resource server running several replicas accepts a replay on
// another replica, which the short proof lifetime bounds.
type replayCache struct {
	mu   sync.Mutex
	seen map[string]time.Time
	// sweepAt is when expired entries are next dropped.
	sweepAt time.Time
	// swept is when the last sweep ran.
	swept time.Time
}

// DefaultMaxReplayEntries bounds the replay cache when Verifier.MaxReplayEntries
// is zero.
const DefaultMaxReplayEntries = 1_000_000

func newReplayCache() *replayCache {
	return &replayCache{seen: map[string]time.Time{}}
}

type addResult int

const (
	addOK addResult = iota
	addReplayed
	addFull
)

func (c *replayCache) sweep(now time.Time) {
	for id, exp := range c.seen {
		if !now.Before(exp) {
			delete(c.seen, id)
		}
	}
	c.sweepAt = now.Add(time.Minute)
	c.swept = now
}

// add records jti until expiry. It reports addReplayed if jti was already
// present, and addFull if the cache holds limit live entries even after dropping
// expired ones, so an anonymous client cannot grow it without bound.
func (c *replayCache) add(jti string, expiry, now time.Time, limit int) addResult {
	c.mu.Lock()
	defer c.mu.Unlock()
	if !now.Before(c.sweepAt) {
		c.sweep(now)
	}
	if exp, ok := c.seen[jti]; ok && now.Before(exp) {
		return addReplayed
	}
	if _, ok := c.seen[jti]; !ok && len(c.seen) >= limit {
		// The periodic sweep may be a minute stale, so sweep before refusing,
		// but at most once a second: a full cache walked on every request
		// would hand an attacker a CPU lever.
		if now.Sub(c.swept) >= time.Second {
			c.sweep(now)
		}
		if len(c.seen) >= limit {
			return addFull
		}
	}
	c.seen[jti] = expiry
	return addOK
}
