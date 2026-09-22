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

// Pending is a write that needs a second approval before it is committed
// (plan §3.2 step 4): the record as the author sent it, who sent it, and why
// it stopped here. It is not in the log; approving it is what commits it.
type Pending struct {
	ID          string          `json:"id"`
	Org         string          `json:"org"`
	Collection  string          `json:"collection"`
	RKey        string          `json:"rkey"`
	Record      json.RawMessage `json:"record"`
	CommittedBy string          `json:"committedBy"`
	Reasons     []string        `json:"reasons"`
	CreatedAt   time.Time       `json:"createdAt"`
}

// Party kinds, as the party table stores them.
const (
	KindPerson = "person"
	KindOrg    = "org"
)

// Party is the DIMO-administered policy attributes of a DID (plan §1 decision
// E): what kind of principal it is and whether it is an attested commercial
// operator. It is a host-level table rather than a record, because it is
// DIMO's say-so and not the org's.
type Party struct {
	DID      string    `json:"did"`
	Kind     string    `json:"kind"`
	Operator bool      `json:"operator"`
	SetAt    time.Time `json:"setAt"`
}

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

	// The resolver queries (plan §3.3) read the current view of records. Each
	// returns live records only unless it says otherwise, ordered by seq.

	// Memberships returns org's live tagMembership records for tag and vehicle.
	Memberships(ctx context.Context, org, tag, vehicle string) ([]Stored, error)
	// TagSize counts the distinct vehicles with a live membership interval in
	// org's tag that contains at.
	TagSize(ctx context.Context, org, tag string, at time.Time) (int, error)
	// Custody returns every live custody record for vehicle and holder, from
	// every repository on this host.
	Custody(ctx context.Context, vehicle, holder string) ([]Stored, error)
	// Roles returns org's role records addressed to member, tombstoned ones
	// included: the evaluator decides for itself whether a tombstone counts.
	Roles(ctx context.Context, org, member string) ([]Stored, error)
	// Exclusives returns the live delegation records, from every repository on
	// this host, that claim exclusive abilities and cover vehicle: directly, or
	// through a tag the vehicle has a membership in at time at. Validity is the
	// caller's to check.
	Exclusives(ctx context.Context, vehicle string, at time.Time) ([]Stored, error)

	// DelegationsOverTag returns org's live delegation records whose covers.tag
	// is tag: the records a membership in the tag widens.
	DelegationsOverTag(ctx context.Context, org, tag string) ([]Stored, error)
	// DelegationsWithBasis returns the live delegation records, from every
	// repository on this host, whose basis names uri: its direct descendants
	// (spec §9.3).
	DelegationsWithBasis(ctx context.Context, uri string) ([]Stored, error)
	// Authored returns org's live records whose current version was committed
	// by member after since, ordered by seq.
	Authored(ctx context.Context, org, member string, since time.Time) ([]Stored, error)

	// AddPending stores a write awaiting approval.
	AddPending(ctx context.Context, p Pending) error
	// GetPending returns one pending write, or ErrNotFound.
	GetPending(ctx context.Context, org, id string) (*Pending, error)
	// ListPending returns org's pending writes, oldest first.
	ListPending(ctx context.Context, org string) ([]Pending, error)
	// DeletePending removes a pending write, or returns ErrNotFound. It is
	// called once the write is committed or withdrawn.
	DeletePending(ctx context.Context, org, id string) error

	// SetParty records or replaces a DID's party attributes.
	SetParty(ctx context.Context, p Party) error
	// GetParty returns a DID's party attributes, or ErrNotFound.
	GetParty(ctx context.Context, did string) (*Party, error)

	// Close closes the store.
	Close() error
}
