package store

import (
	"context"
	"errors"
	"time"

	"github.com/DIMO-Network/did-directory/internal/did"
)

// ErrHeadChanged is returned by AppendAfter when another writer moved the DID's
// log head between the caller reading it and the append.
var ErrHeadChanged = errors.New("operation log head changed")

// IsHeadChanged reports whether err is a lost append race.
func IsHeadChanged(err error) bool {
	return errors.Is(err, ErrHeadChanged)
}

// OperationRecord is a stored operation with metadata.
type OperationRecord struct {
	DID       string        `json:"did"`
	CID       string        `json:"cid"`
	Operation did.Operation `json:"operation"`
	CreatedAt time.Time     `json:"createdAt"`
	Seq       int64         `json:"seq"`
}

// ExportRecord is an operation record formatted for export.
type ExportRecord struct {
	DID       string        `json:"did"`
	CID       string        `json:"cid"`
	Operation did.Operation `json:"operation"`
	CreatedAt string        `json:"createdAt"`
}

// Store defines the interface for persisting DID operations.
type Store interface {
	// AppendAfter atomically adds an operation to a DID's log, but only if the
	// log's head is still expectedHead. expectedHead is "" for a genesis
	// operation, which requires the log to be empty. It returns ErrHeadChanged if
	// another writer got there first.
	//
	// Validation reads the head, checks the transition and then writes, so the
	// check and the write have to be one step. Without it two concurrent
	// dimo_transfer posts both pass `prev == head`, both append distinct CIDs,
	// and the DID resolves to two rival eras.
	AppendAfter(ctx context.Context, did string, expectedHead string, cid string, op *did.Operation) error

	// GetLatest retrieves the most recent operation for a DID.
	GetLatest(ctx context.Context, did string) (*OperationRecord, error)

	// GetLog retrieves the full operation log for a DID, ordered by sequence.
	GetLog(ctx context.Context, did string) ([]OperationRecord, error)

	// Exists checks if a DID exists in the store.
	Exists(ctx context.Context, did string) (bool, error)

	// Export returns operations after the given sequence number, up to limit.
	Export(ctx context.Context, afterSeq int64, limit int) ([]OperationRecord, error)

	// Close closes the store.
	Close() error
}
