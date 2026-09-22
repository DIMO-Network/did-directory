// Package store persists org repositories for the org host: the orgs it serves,
// their sealed signing keys, their commit logs and the current head of every
// record key. It mirrors internal/store: one interface, a Postgres
// implementation and an in-memory one that is the default without a database.
package store

import (
	"context"
	"encoding/json"
	"errors"
	"time"

	"github.com/DIMO-Network/did-directory/pkg/repo"
)

// TestDatabaseURLEnv names the Postgres database the org host's tests run
// against. Without it the Postgres cases are skipped and only the memory store
// runs.
const TestDatabaseURLEnv = "ORG_HOST_TEST_DATABASE_URL"

var (
	// ErrNotFound is returned for an org, record or commit that does not exist.
	ErrNotFound = errors.New("not found")
	// ErrOrgExists is returned by CreateOrg for an org already on this host.
	ErrOrgExists = errors.New("org already exists")
	// ErrHeadChanged is returned by AppendAfter when another writer moved the
	// org's log head between the caller reading it and the append.
	ErrHeadChanged = errors.New("repository head changed")
)

// IsNotFound reports whether err is ErrNotFound.
func IsNotFound(err error) bool { return errors.Is(err, ErrNotFound) }

// IsHeadChanged reports whether err is a lost append race.
func IsHeadChanged(err error) bool { return errors.Is(err, ErrHeadChanged) }

// Org is an org served by this host.
type Org struct {
	DID string
	// KeyEnc is the org's #dimo_org private key, sealed by the host's master key.
	// The store never sees it in the clear.
	KeyEnc    []byte
	CreatedAt time.Time
}

// Head is the position of an org's log: its last commit, or the zero Head for
// an org with no commits yet.
type Head struct {
	Seq int64
	CID string
	Rev string
}

// Tombstone marks a revoked record: the commit that revoked it and who wrote it.
type Tombstone struct {
	At  time.Time `json:"at"`
	By  string    `json:"by"`
	Seq int64     `json:"seq"`
	CID string    `json:"cid"`
}

// Stored is the current state of one record key: the record as last created or
// updated, the commit that did it, and the tombstone if it has since been
// revoked. A tombstoned record keeps its last body, since disputes need to see
// what existed (spec §6.2).
type Stored struct {
	URI         string          `json:"uri"`
	Collection  string          `json:"collection"`
	RKey        string          `json:"rkey"`
	Record      json.RawMessage `json:"record"`
	Seq         int64           `json:"seq"`
	CID         string          `json:"cid"`
	Rev         string          `json:"rev"`
	CommittedBy string          `json:"committedBy"`
	ApprovedBy  []string        `json:"approvedBy,omitempty"`
	CommittedAt time.Time       `json:"committedAt"`
	Tombstone   *Tombstone      `json:"tombstone,omitempty"`
}

// Live reports whether the record has not been tombstoned.
func (s *Stored) Live() bool { return s.Tombstone == nil }

// Store persists org repositories.
type Store interface {
	// CreateOrg registers an org on this host with its sealed signing key.
	CreateOrg(ctx context.Context, org Org) error
	// GetOrg returns an org, or ErrNotFound.
	GetOrg(ctx context.Context, did string) (*Org, error)

	// Head returns the org's log head, or ErrNotFound for an org not on this host.
	Head(ctx context.Context, org string) (Head, error)

	// AppendAfter atomically appends a signed commit to the org's log, but only
	// if the head is still expectedHead. It returns ErrHeadChanged if another
	// writer got there first. The caller signs the commit before calling, so seq
	// and prev are inside the signature; the head check is what makes them true.
	AppendAfter(ctx context.Context, expectedHead Head, c repo.Committed) error

	// Current returns the state of a record key, tombstoned or not, or ErrNotFound
	// if nothing was ever committed under it.
	Current(ctx context.Context, org, collection, rkey string) (*Stored, error)
	// List returns live records in a collection ordered by record key, starting
	// after afterRKey, at most limit.
	List(ctx context.Context, org, collection, afterRKey string, limit int) ([]Stored, error)
	// Commits returns the org's commits with seq greater than afterSeq, in order,
	// at most limit.
	Commits(ctx context.Context, org string, afterSeq int64, limit int) ([]repo.Committed, error)

	// Close closes the store.
	Close() error
}
