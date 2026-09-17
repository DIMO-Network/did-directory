package store

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/DIMO-Network/did-directory/internal/did"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/rs/zerolog"
)

var errNotFound = errors.New("not found")

// IsNotFound checks if an error is a not-found error.
func IsNotFound(err error) bool {
	return errors.Is(err, errNotFound)
}

// PostgresStore implements Store using PostgreSQL.
type PostgresStore struct {
	pool *pgxpool.Pool
	log  zerolog.Logger
}

// NewPostgresStore creates a new PostgreSQL-backed store.
func NewPostgresStore(ctx context.Context, connStr string, log zerolog.Logger) (*PostgresStore, error) {
	pool, err := pgxpool.New(ctx, connStr)
	if err != nil {
		return nil, fmt.Errorf("pgxpool new: %w", err)
	}

	if err := pool.Ping(ctx); err != nil {
		return nil, fmt.Errorf("pgxpool ping: %w", err)
	}

	s := &PostgresStore{
		pool: pool,
		log:  log.With().Str("component", "postgres_store").Logger(),
	}

	if err := s.ensureSchema(ctx); err != nil {
		return nil, fmt.Errorf("ensure schema: %w", err)
	}

	return s, nil
}

func (s *PostgresStore) ensureSchema(ctx context.Context) error {
	query := `
		CREATE TABLE IF NOT EXISTS operations (
			seq         BIGSERIAL PRIMARY KEY,
			did         TEXT NOT NULL,
			cid         TEXT NOT NULL,
			operation   JSONB NOT NULL,
			created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
			UNIQUE(did, cid)
		);
		CREATE INDEX IF NOT EXISTS idx_operations_did ON operations(did);
		CREATE INDEX IF NOT EXISTS idx_operations_seq ON operations(seq);
	`
	_, err := s.pool.Exec(ctx, query)
	return err
}

func (s *PostgresStore) AppendAfter(ctx context.Context, didStr string, expectedHead string, cid string, op *did.Operation) error {
	opJSON, err := json.Marshal(op)
	if err != nil {
		return fmt.Errorf("marshal operation: %w", err)
	}

	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return fmt.Errorf("begin: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()

	// Serialize writers for this DID. The conflict is between two rows that do
	// not exist yet, so no row lock — and no UNIQUE(did,cid), since the rival
	// operations carry different CIDs — can catch it.
	if _, err := tx.Exec(ctx, `SELECT pg_advisory_xact_lock(hashtextextended($1, 0))`, didStr); err != nil {
		return fmt.Errorf("lock did: %w", err)
	}

	var head string
	err = tx.QueryRow(ctx, `SELECT cid FROM operations WHERE did = $1 ORDER BY seq DESC LIMIT 1`, didStr).Scan(&head)
	if err != nil && !errors.Is(err, pgx.ErrNoRows) {
		return fmt.Errorf("query head: %w", err)
	}
	if head != expectedHead {
		return ErrHeadChanged
	}

	if _, err := tx.Exec(ctx, `INSERT INTO operations (did, cid, operation) VALUES ($1, $2, $3)`, didStr, cid, opJSON); err != nil {
		return fmt.Errorf("insert operation: %w", err)
	}

	if err := tx.Commit(ctx); err != nil {
		return fmt.Errorf("commit: %w", err)
	}
	return nil
}

func (s *PostgresStore) GetLatest(ctx context.Context, didStr string) (*OperationRecord, error) {
	query := `SELECT seq, did, cid, operation, created_at FROM operations WHERE did = $1 ORDER BY seq DESC LIMIT 1`

	var rec OperationRecord
	var opJSON []byte

	err := s.pool.QueryRow(ctx, query, didStr).Scan(&rec.Seq, &rec.DID, &rec.CID, &opJSON, &rec.CreatedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, errNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("query latest: %w", err)
	}

	if err := json.Unmarshal(opJSON, &rec.Operation); err != nil {
		return nil, fmt.Errorf("unmarshal operation: %w", err)
	}

	return &rec, nil
}

func (s *PostgresStore) GetLog(ctx context.Context, didStr string) ([]OperationRecord, error) {
	query := `SELECT seq, did, cid, operation, created_at FROM operations WHERE did = $1 ORDER BY seq ASC`

	rows, err := s.pool.Query(ctx, query, didStr)
	if err != nil {
		return nil, fmt.Errorf("query log: %w", err)
	}
	defer rows.Close()

	var records []OperationRecord
	for rows.Next() {
		var rec OperationRecord
		var opJSON []byte
		if err := rows.Scan(&rec.Seq, &rec.DID, &rec.CID, &opJSON, &rec.CreatedAt); err != nil {
			return nil, fmt.Errorf("scan row: %w", err)
		}
		if err := json.Unmarshal(opJSON, &rec.Operation); err != nil {
			return nil, fmt.Errorf("unmarshal operation: %w", err)
		}
		records = append(records, rec)
	}

	if records == nil {
		records = []OperationRecord{}
	}

	return records, rows.Err()
}

func (s *PostgresStore) Exists(ctx context.Context, didStr string) (bool, error) {
	query := `SELECT EXISTS(SELECT 1 FROM operations WHERE did = $1)`
	var exists bool
	err := s.pool.QueryRow(ctx, query, didStr).Scan(&exists)
	return exists, err
}

func (s *PostgresStore) Export(ctx context.Context, afterSeq int64, limit int) ([]OperationRecord, error) {
	query := `SELECT seq, did, cid, operation, created_at FROM operations WHERE seq > $1 ORDER BY seq ASC LIMIT $2`

	rows, err := s.pool.Query(ctx, query, afterSeq, limit)
	if err != nil {
		return nil, fmt.Errorf("query export: %w", err)
	}
	defer rows.Close()

	var records []OperationRecord
	for rows.Next() {
		var rec OperationRecord
		var opJSON []byte
		if err := rows.Scan(&rec.Seq, &rec.DID, &rec.CID, &opJSON, &rec.CreatedAt); err != nil {
			return nil, fmt.Errorf("scan row: %w", err)
		}
		if err := json.Unmarshal(opJSON, &rec.Operation); err != nil {
			return nil, fmt.Errorf("unmarshal operation: %w", err)
		}
		records = append(records, rec)
	}

	if records == nil {
		records = []OperationRecord{}
	}

	return records, rows.Err()
}

func (s *PostgresStore) Close() error {
	s.pool.Close()
	return nil
}

// MemoryStore implements Store using in-memory maps. It is the default when
// DATABASE_URL is unset, so it is a production code path and not only a test
// fixture: Fiber serves every request in its own goroutine, and mu is what keeps
// concurrent appends from losing a sequence number or tripping Go's
// unrecoverable "concurrent map writes".
type MemoryStore struct {
	mu      sync.RWMutex
	records []OperationRecord
	byDID   map[string][]int // did -> indices into records
	seq     int64
}

// NewMemoryStore creates a new in-memory store.
func NewMemoryStore() *MemoryStore {
	return &MemoryStore{
		records: make([]OperationRecord, 0),
		byDID:   make(map[string][]int),
	}
}

func (s *MemoryStore) AppendAfter(_ context.Context, didStr string, expectedHead string, cid string, op *did.Operation) error {
	// Handlers pass Fiber params, which alias a reused request buffer; the store
	// must own its copies.
	didStr = strings.Clone(didStr)
	cid = strings.Clone(cid)
	expectedHead = strings.Clone(expectedHead)

	s.mu.Lock()
	defer s.mu.Unlock()

	var head string
	if indices := s.byDID[didStr]; len(indices) > 0 {
		head = s.records[indices[len(indices)-1]].CID
	}
	if head != expectedHead {
		return ErrHeadChanged
	}

	s.seq++
	rec := OperationRecord{
		DID:       didStr,
		CID:       cid,
		Operation: *op,
		CreatedAt: time.Now().UTC(),
		Seq:       s.seq,
	}
	idx := len(s.records)
	s.records = append(s.records, rec)
	s.byDID[didStr] = append(s.byDID[didStr], idx)
	return nil
}

func (s *MemoryStore) GetLatest(_ context.Context, didStr string) (*OperationRecord, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	indices, ok := s.byDID[didStr]
	if !ok || len(indices) == 0 {
		return nil, errNotFound
	}
	rec := s.records[indices[len(indices)-1]]
	return &rec, nil
}

func (s *MemoryStore) GetLog(_ context.Context, didStr string) ([]OperationRecord, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	indices, ok := s.byDID[didStr]
	if !ok {
		return []OperationRecord{}, nil
	}
	var records []OperationRecord
	for _, idx := range indices {
		records = append(records, s.records[idx])
	}
	return records, nil
}

func (s *MemoryStore) Exists(_ context.Context, didStr string) (bool, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	indices, ok := s.byDID[didStr]
	return ok && len(indices) > 0, nil
}

func (s *MemoryStore) Export(_ context.Context, afterSeq int64, limit int) ([]OperationRecord, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	var records []OperationRecord
	for _, rec := range s.records {
		if rec.Seq > afterSeq {
			records = append(records, rec)
			if len(records) >= limit {
				break
			}
		}
	}
	if records == nil {
		records = []OperationRecord{}
	}
	return records, nil
}

func (s *MemoryStore) Close() error {
	return nil
}
