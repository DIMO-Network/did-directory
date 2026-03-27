package store

import (
	"context"
	"time"

	"github.com/DIMO-Network/did-directory/internal/did"
)

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
	// Append adds a new operation to the log for the given DID.
	Append(ctx context.Context, did string, cid string, op *did.Operation) error

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
