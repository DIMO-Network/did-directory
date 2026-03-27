package auth

import (
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"sync"
	"time"
)

const challengeTTL = 5 * time.Minute

// ChallengeEntry holds a stored challenge with its expiration.
type ChallengeEntry struct {
	Nonce     string
	ExpiresAt time.Time
}

// ChallengeStore manages challenge nonces in memory.
type ChallengeStore struct {
	mu         sync.Mutex
	challenges map[string]ChallengeEntry
}

// NewChallengeStore creates a new in-memory challenge store.
func NewChallengeStore() *ChallengeStore {
	return &ChallengeStore{
		challenges: make(map[string]ChallengeEntry),
	}
}

// Generate creates a new challenge nonce and stores it.
func (s *ChallengeStore) Generate() (string, time.Time, error) {
	nonce := make([]byte, 32)
	if _, err := rand.Read(nonce); err != nil {
		return "", time.Time{}, fmt.Errorf("generate nonce: %w", err)
	}

	encoded := base64.RawURLEncoding.EncodeToString(nonce)
	expiresAt := time.Now().UTC().Add(challengeTTL)

	s.mu.Lock()
	s.challenges[encoded] = ChallengeEntry{
		Nonce:     encoded,
		ExpiresAt: expiresAt,
	}
	s.mu.Unlock()

	return encoded, expiresAt, nil
}

// Consume validates and removes a challenge (single-use).
// Returns the raw nonce bytes if valid.
func (s *ChallengeStore) Consume(nonce string) ([]byte, error) {
	s.mu.Lock()
	entry, ok := s.challenges[nonce]
	if ok {
		delete(s.challenges, nonce)
	}
	s.mu.Unlock()

	if !ok {
		return nil, fmt.Errorf("challenge not found or already used")
	}

	if time.Now().UTC().After(entry.ExpiresAt) {
		return nil, fmt.Errorf("challenge expired")
	}

	raw, err := base64.RawURLEncoding.DecodeString(nonce)
	if err != nil {
		return nil, fmt.Errorf("decode nonce: %w", err)
	}

	return raw, nil
}

// Cleanup removes expired challenges (call periodically if needed).
func (s *ChallengeStore) Cleanup() {
	s.mu.Lock()
	defer s.mu.Unlock()

	now := time.Now().UTC()
	for k, v := range s.challenges {
		if now.After(v.ExpiresAt) {
			delete(s.challenges, k)
		}
	}
}
