package store

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/DIMO-Network/did-directory/pkg/repo"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/rs/zerolog"
)

// PostgresStore implements Store using PostgreSQL.
type PostgresStore struct {
	pool *pgxpool.Pool
	log  zerolog.Logger
}

// NewPostgresStore connects to connStr and ensures the schema exists.
func NewPostgresStore(ctx context.Context, connStr string, log zerolog.Logger) (*PostgresStore, error) {
	pool, err := pgxpool.New(ctx, connStr)
	if err != nil {
		return nil, fmt.Errorf("pgxpool new: %w", err)
	}
	if err := pool.Ping(ctx); err != nil {
		return nil, fmt.Errorf("pgxpool ping: %w", err)
	}
	s := &PostgresStore{pool: pool, log: log.With().Str("component", "orghost_postgres_store").Logger()}
	if err := s.ensureSchema(ctx); err != nil {
		return nil, fmt.Errorf("ensure schema: %w", err)
	}
	return s, nil
}

// The schema follows plan §4. The commit's record is kept as the canonical JSON
// text that was signed, since a signature has to be checked against the bytes it
// was made over and jsonb does not promise to give those back; record_json is
// derived from it for the resolver's queries and indexes.
func (s *PostgresStore) ensureSchema(ctx context.Context) error {
	query := `
		CREATE TABLE IF NOT EXISTS orgs (
			did             TEXT PRIMARY KEY,
			signing_key_enc BYTEA NOT NULL,
			created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
		);
		CREATE TABLE IF NOT EXISTS commits (
			org          TEXT NOT NULL REFERENCES orgs(did),
			seq          BIGINT NOT NULL,
			cid          TEXT NOT NULL,
			prev         TEXT NOT NULL,
			rev          TEXT NOT NULL,
			op           TEXT NOT NULL,
			collection   TEXT NOT NULL,
			rkey         TEXT NOT NULL,
			record       TEXT,
			record_json  JSONB GENERATED ALWAYS AS (record::jsonb) STORED,
			committed_by TEXT NOT NULL,
			approved_by  TEXT[] NOT NULL,
			committed_at TIMESTAMPTZ NOT NULL,
			sig          TEXT NOT NULL,
			PRIMARY KEY (org, seq),
			UNIQUE (org, cid),
			UNIQUE (org, collection, rkey, rev)
		);
		CREATE TABLE IF NOT EXISTS heads (
			org           TEXT NOT NULL,
			collection    TEXT NOT NULL,
			rkey          TEXT NOT NULL,
			record_seq    BIGINT NOT NULL,
			tombstone_seq BIGINT,
			PRIMARY KEY (org, collection, rkey),
			FOREIGN KEY (org, record_seq) REFERENCES commits(org, seq),
			FOREIGN KEY (org, tombstone_seq) REFERENCES commits(org, seq)
		);
		CREATE TABLE IF NOT EXISTS parties (
			did      TEXT PRIMARY KEY,
			kind     TEXT NOT NULL,
			operator BOOLEAN NOT NULL,
			set_at   TIMESTAMPTZ NOT NULL
		);
		CREATE TABLE IF NOT EXISTS pending (
			org          TEXT NOT NULL REFERENCES orgs(did),
			id           TEXT NOT NULL,
			collection   TEXT NOT NULL,
			rkey         TEXT NOT NULL,
			record       TEXT NOT NULL,
			committed_by TEXT NOT NULL,
			reasons      TEXT[] NOT NULL,
			created_at   TIMESTAMPTZ NOT NULL,
			PRIMARY KEY (org, id)
		);

		-- The resolver's lookups (plan §3.3), as partial expression indexes over
		-- the derived jsonb. They index every version of a record; the join to
		-- heads is what picks the current one.
		CREATE INDEX IF NOT EXISTS commits_membership_idx ON commits (org, (record_json->>'tag'), (record_json->>'vehicle'))
			WHERE collection = 'network.dimo.org.tagMembership';
		CREATE INDEX IF NOT EXISTS commits_custody_idx ON commits ((record_json->>'vehicle'), (record_json->>'holder'))
			WHERE collection = 'network.dimo.org.custody';
		-- Delegations and roles are ODRL policies: to is the assignee, covers is
		-- the one permission's target, basis and exclusive are profile terms.
		CREATE INDEX IF NOT EXISTS commits_role_assignee_idx ON commits (org, (record_json->>'assignee'))
			WHERE collection = 'network.dimo.org.role';
		CREATE INDEX IF NOT EXISTS commits_exclusive_target_idx ON commits ((record_json->'permission'->0->>'target'))
			WHERE collection = 'network.dimo.delegation' AND jsonb_typeof(record_json->'dimo:exclusive') = 'array';
		CREATE INDEX IF NOT EXISTS commits_target_idx ON commits (org, (record_json->'permission'->0->>'target'))
			WHERE collection = 'network.dimo.delegation';
		CREATE INDEX IF NOT EXISTS commits_author_idx ON commits (org, committed_by, committed_at);
		CREATE INDEX IF NOT EXISTS commits_dimo_basis_idx ON commits USING GIN ((record_json->'dimo:basis'))
			WHERE collection = 'network.dimo.delegation';
	`
	// Two instances starting at once would race to create the same tables,
	// which Postgres reports as a duplicate type rather than tolerating.
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback(ctx) }()
	if _, err := tx.Exec(ctx, `SELECT pg_advisory_xact_lock(hashtext('org_host_schema'))`); err != nil {
		return err
	}
	if _, err := tx.Exec(ctx, query); err != nil {
		return err
	}
	return tx.Commit(ctx)
}

func (s *PostgresStore) CreateOrg(ctx context.Context, org Org) error {
	if org.CreatedAt.IsZero() {
		org.CreatedAt = time.Now().UTC()
	}
	tag, err := s.pool.Exec(ctx,
		`INSERT INTO orgs (did, signing_key_enc, created_at) VALUES ($1, $2, $3) ON CONFLICT (did) DO NOTHING`,
		org.DID, org.KeyEnc, org.CreatedAt)
	if err != nil {
		return fmt.Errorf("insert org: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return ErrOrgExists
	}
	return nil
}

func (s *PostgresStore) GetOrg(ctx context.Context, did string) (*Org, error) {
	var org Org
	err := s.pool.QueryRow(ctx, `SELECT did, signing_key_enc, created_at FROM orgs WHERE did = $1`, did).
		Scan(&org.DID, &org.KeyEnc, &org.CreatedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("query org: %w", err)
	}
	org.CreatedAt = org.CreatedAt.UTC()
	return &org, nil
}

func (s *PostgresStore) Head(ctx context.Context, org string) (Head, error) {
	return s.head(ctx, s.pool, org)
}

type querier interface {
	QueryRow(ctx context.Context, sql string, args ...any) pgx.Row
}

func (s *PostgresStore) head(ctx context.Context, q querier, org string) (Head, error) {
	var exists bool
	if err := q.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM orgs WHERE did = $1)`, org).Scan(&exists); err != nil {
		return Head{}, fmt.Errorf("query org: %w", err)
	}
	if !exists {
		return Head{}, ErrNotFound
	}
	var h Head
	err := q.QueryRow(ctx, `SELECT seq, cid, rev FROM commits WHERE org = $1 ORDER BY seq DESC LIMIT 1`, org).
		Scan(&h.Seq, &h.CID, &h.Rev)
	if errors.Is(err, pgx.ErrNoRows) {
		return Head{}, nil
	}
	if err != nil {
		return Head{}, fmt.Errorf("query head: %w", err)
	}
	return h, nil
}

func (s *PostgresStore) AppendAfter(ctx context.Context, expectedHead Head, commits ...repo.Committed) error {
	if len(commits) == 0 {
		return nil
	}
	org := commits[0].DID
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return fmt.Errorf("begin: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()

	// Serialize writers for this org. The conflict is between two rows that do
	// not exist yet, so no row lock can catch it; the primary key on (org, seq)
	// would, but only after both writers had signed rival commits.
	if _, err := tx.Exec(ctx, `SELECT pg_advisory_xact_lock(hashtextextended($1, 0))`, org); err != nil {
		return fmt.Errorf("lock org: %w", err)
	}
	head, err := s.head(ctx, tx, org)
	if err != nil {
		return err
	}
	if head != expectedHead {
		return ErrHeadChanged
	}
	if err := chained(expectedHead, commits); err != nil {
		return err
	}

	for _, c := range commits {
		var record *string
		if len(c.Record) > 0 {
			r := string(c.Record)
			record = &r
		}
		approved := c.ApprovedBy
		if approved == nil {
			approved = []string{}
		}
		if _, err := tx.Exec(ctx, `
			INSERT INTO commits (org, seq, cid, prev, rev, op, collection, rkey, record, committed_by, approved_by, committed_at, sig)
			VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13)`,
			c.DID, c.Seq, c.CID, c.Prev, c.Rev, c.Op, c.Collection, c.RKey, record, c.CommittedBy, approved, c.CommittedAt, c.Sig,
		); err != nil {
			return fmt.Errorf("insert commit: %w", err)
		}

		var upsert string
		switch c.Op {
		case repo.OpTombstone:
			upsert = `UPDATE heads SET tombstone_seq = $4 WHERE org = $1 AND collection = $2 AND rkey = $3`
		default:
			upsert = `INSERT INTO heads (org, collection, rkey, record_seq, tombstone_seq) VALUES ($1, $2, $3, $4, NULL)
				ON CONFLICT (org, collection, rkey) DO UPDATE SET record_seq = EXCLUDED.record_seq, tombstone_seq = NULL`
		}
		tag, err := tx.Exec(ctx, upsert, c.DID, c.Collection, c.RKey, c.Seq)
		if err != nil {
			return fmt.Errorf("update head: %w", err)
		}
		if tag.RowsAffected() != 1 {
			return fmt.Errorf("update head: %s of %s/%s touched %d rows", c.Op, c.Collection, c.RKey, tag.RowsAffected())
		}
	}

	if err := tx.Commit(ctx); err != nil {
		return fmt.Errorf("commit: %w", err)
	}
	return nil
}

const storedColumns = `
	r.org, r.seq, r.cid, r.rev, r.collection, r.rkey, r.record, r.committed_by, r.approved_by, r.committed_at,
	t.seq, t.cid, t.committed_by, t.committed_at`

const storedFrom = `
	FROM heads h
	JOIN commits r ON r.org = h.org AND r.seq = h.record_seq
	LEFT JOIN commits t ON t.org = h.org AND t.seq = h.tombstone_seq`

type rowScanner interface {
	Scan(dest ...any) error
}

func scanStored(row rowScanner) (*Stored, error) {
	var (
		st        Stored
		org       string
		record    *string
		tSeq      *int64
		tCID, tBy *string
		tAt       *time.Time
	)
	if err := row.Scan(&org, &st.Seq, &st.CID, &st.Rev, &st.Collection, &st.RKey, &record, &st.CommittedBy, &st.ApprovedBy, &st.CommittedAt,
		&tSeq, &tCID, &tBy, &tAt); err != nil {
		return nil, err
	}
	st.URI = "at://" + org + "/" + st.Collection + "/" + st.RKey
	if record != nil {
		st.Record = []byte(*record)
	}
	if len(st.ApprovedBy) == 0 {
		st.ApprovedBy = nil
	}
	st.CommittedAt = st.CommittedAt.UTC()
	if tSeq != nil {
		st.Tombstone = &Tombstone{At: tAt.UTC(), By: *tBy, Seq: *tSeq, CID: *tCID}
	}
	return &st, nil
}

func (s *PostgresStore) Current(ctx context.Context, org, collection, rkey string) (*Stored, error) {
	row := s.pool.QueryRow(ctx, `SELECT `+storedColumns+storedFrom+` WHERE h.org = $1 AND h.collection = $2 AND h.rkey = $3`,
		org, collection, rkey)
	st, err := scanStored(row)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("query record: %w", err)
	}
	return st, nil
}

func (s *PostgresStore) List(ctx context.Context, org, collection, afterRKey string, limit int) ([]Stored, error) {
	if _, err := s.head(ctx, s.pool, org); err != nil {
		return nil, err
	}
	if limit <= 0 {
		limit = 1 << 30
	}
	rows, err := s.pool.Query(ctx, `SELECT `+storedColumns+storedFrom+`
		WHERE h.org = $1 AND h.collection = $2 AND h.rkey > $3 AND h.tombstone_seq IS NULL
		ORDER BY h.rkey ASC LIMIT $4`, org, collection, afterRKey, limit)
	if err != nil {
		return nil, fmt.Errorf("query records: %w", err)
	}
	defer rows.Close()
	out := []Stored{}
	for rows.Next() {
		st, err := scanStored(rows)
		if err != nil {
			return nil, fmt.Errorf("scan record: %w", err)
		}
		out = append(out, *st)
	}
	return out, rows.Err()
}

// queryStored runs a query over the current view of records. where is applied
// to the head row h and the record commit r, with args numbered from $1.
func (s *PostgresStore) queryStored(ctx context.Context, where string, args ...any) ([]Stored, error) {
	rows, err := s.pool.Query(ctx, `SELECT `+storedColumns+storedFrom+` WHERE `+where+` ORDER BY r.org, r.seq`, args...)
	if err != nil {
		return nil, fmt.Errorf("query records: %w", err)
	}
	defer rows.Close()
	out := []Stored{}
	for rows.Next() {
		st, err := scanStored(rows)
		if err != nil {
			return nil, fmt.Errorf("scan record: %w", err)
		}
		out = append(out, *st)
	}
	return out, rows.Err()
}

// memberAtSQL is the SQL for "membership commit m's interval contains $at".
func memberAtSQL(at string) string {
	return `(m.record_json->>'joinedAt')::timestamptz <= ` + at + `
		AND (m.record_json->>'leftAt' IS NULL OR (m.record_json->>'leftAt')::timestamptz > ` + at + `)`
}

func (s *PostgresStore) Memberships(ctx context.Context, org, tag, vehicle string) ([]Stored, error) {
	if _, err := s.head(ctx, s.pool, org); err != nil {
		return nil, err
	}
	return s.queryStored(ctx, `h.org = $1 AND h.collection = 'network.dimo.org.tagMembership' AND h.tombstone_seq IS NULL
		AND r.record_json->>'tag' = $2 AND r.record_json->>'vehicle' = $3`, org, tag, vehicle)
}

func (s *PostgresStore) TagSize(ctx context.Context, org, tag string, at time.Time) (int, error) {
	if _, err := s.head(ctx, s.pool, org); err != nil {
		return 0, err
	}
	var n int
	err := s.pool.QueryRow(ctx, `
		SELECT COUNT(DISTINCT m.record_json->>'vehicle')
		FROM heads h JOIN commits m ON m.org = h.org AND m.seq = h.record_seq
		WHERE h.org = $1 AND h.collection = 'network.dimo.org.tagMembership' AND h.tombstone_seq IS NULL
			AND m.record_json->>'tag' = $2 AND `+memberAtSQL("$3"), org, tag, at).Scan(&n)
	if err != nil {
		return 0, fmt.Errorf("count tag: %w", err)
	}
	return n, nil
}

func (s *PostgresStore) Custody(ctx context.Context, org, vehicle, holder string) ([]Stored, error) {
	return s.queryStored(ctx, `h.org = $1 AND h.collection = 'network.dimo.org.custody' AND h.tombstone_seq IS NULL
		AND r.record_json->>'vehicle' = $2 AND r.record_json->>'holder' = $3`, org, vehicle, holder)
}

func (s *PostgresStore) Roles(ctx context.Context, org, member string) ([]Stored, error) {
	if _, err := s.head(ctx, s.pool, org); err != nil {
		return nil, err
	}
	return s.queryStored(ctx, `h.org = $1 AND h.collection = 'network.dimo.org.role' AND r.record_json->>'assignee' = $2`, org, member)
}

func (s *PostgresStore) Exclusives(ctx context.Context, vehicle string, at time.Time) ([]Stored, error) {
	return s.queryStored(ctx, `h.collection = 'network.dimo.delegation' AND h.tombstone_seq IS NULL
		AND jsonb_typeof(r.record_json->'dimo:exclusive') = 'array' AND jsonb_array_length(r.record_json->'dimo:exclusive') > 0
		AND (r.record_json->'permission'->0->>'target' = $1 OR r.record_json->'permission'->0->>'target' IN (
			SELECT m.record_json->>'tag'
			FROM heads mh JOIN commits m ON m.org = mh.org AND m.seq = mh.record_seq
			WHERE mh.collection = 'network.dimo.org.tagMembership' AND mh.tombstone_seq IS NULL
				AND m.record_json->>'vehicle' = $1 AND `+memberAtSQL("$2")+`))`, vehicle, at)
}

func (s *PostgresStore) DelegationsOverTag(ctx context.Context, org, tag string) ([]Stored, error) {
	if _, err := s.head(ctx, s.pool, org); err != nil {
		return nil, err
	}
	return s.queryStored(ctx, `h.org = $1 AND h.collection = 'network.dimo.delegation' AND h.tombstone_seq IS NULL
		AND r.record_json->'permission'->0->>'target' = $2`, org, tag)
}

func (s *PostgresStore) DelegationsWithBasis(ctx context.Context, uri string) ([]Stored, error) {
	return s.queryStored(ctx, `h.collection = 'network.dimo.delegation' AND h.tombstone_seq IS NULL
		AND jsonb_typeof(r.record_json->'dimo:basis') = 'array' AND r.record_json->'dimo:basis' ? $1`, uri)
}

func (s *PostgresStore) Authored(ctx context.Context, org, member string, since time.Time) ([]Stored, error) {
	if _, err := s.head(ctx, s.pool, org); err != nil {
		return nil, err
	}
	return s.queryStored(ctx, `h.org = $1 AND h.tombstone_seq IS NULL AND r.committed_by = $2 AND r.committed_at > $3`, org, member, since)
}

func (s *PostgresStore) AddPending(ctx context.Context, p Pending) error {
	if p.CreatedAt.IsZero() {
		p.CreatedAt = time.Now().UTC()
	}
	reasons := p.Reasons
	if reasons == nil {
		reasons = []string{}
	}
	_, err := s.pool.Exec(ctx, `INSERT INTO pending (org, id, collection, rkey, record, committed_by, reasons, created_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8)`,
		p.Org, p.ID, p.Collection, p.RKey, string(p.Record), p.CommittedBy, reasons, p.CreatedAt)
	if err != nil {
		if isForeignKeyViolation(err) {
			return ErrNotFound
		}
		return fmt.Errorf("insert pending: %w", err)
	}
	return nil
}

const pendingColumns = `org, id, collection, rkey, record, committed_by, reasons, created_at`

func scanPending(row rowScanner) (*Pending, error) {
	var p Pending
	var record string
	if err := row.Scan(&p.Org, &p.ID, &p.Collection, &p.RKey, &record, &p.CommittedBy, &p.Reasons, &p.CreatedAt); err != nil {
		return nil, err
	}
	p.Record = []byte(record)
	p.CreatedAt = p.CreatedAt.UTC()
	return &p, nil
}

func (s *PostgresStore) GetPending(ctx context.Context, org, id string) (*Pending, error) {
	p, err := scanPending(s.pool.QueryRow(ctx, `SELECT `+pendingColumns+` FROM pending WHERE org = $1 AND id = $2`, org, id))
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("query pending: %w", err)
	}
	return p, nil
}

func (s *PostgresStore) ListPending(ctx context.Context, org string) ([]Pending, error) {
	if _, err := s.head(ctx, s.pool, org); err != nil {
		return nil, err
	}
	rows, err := s.pool.Query(ctx, `SELECT `+pendingColumns+` FROM pending WHERE org = $1 ORDER BY created_at, id`, org)
	if err != nil {
		return nil, fmt.Errorf("query pending: %w", err)
	}
	defer rows.Close()
	out := []Pending{}
	for rows.Next() {
		p, err := scanPending(rows)
		if err != nil {
			return nil, fmt.Errorf("scan pending: %w", err)
		}
		out = append(out, *p)
	}
	return out, rows.Err()
}

func (s *PostgresStore) DeletePending(ctx context.Context, org, id string) error {
	tag, err := s.pool.Exec(ctx, `DELETE FROM pending WHERE org = $1 AND id = $2`, org, id)
	if err != nil {
		return fmt.Errorf("delete pending: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	return nil
}

// isForeignKeyViolation reports a Postgres foreign_key_violation.
func isForeignKeyViolation(err error) bool {
	var pgErr *pgconn.PgError
	return errors.As(err, &pgErr) && pgErr.Code == "23503"
}

func (s *PostgresStore) SetParty(ctx context.Context, p Party) error {
	if p.SetAt.IsZero() {
		p.SetAt = time.Now().UTC()
	}
	_, err := s.pool.Exec(ctx, `INSERT INTO parties (did, kind, operator, set_at) VALUES ($1, $2, $3, $4)
		ON CONFLICT (did) DO UPDATE SET kind = EXCLUDED.kind, operator = EXCLUDED.operator, set_at = EXCLUDED.set_at`,
		p.DID, p.Kind, p.Operator, p.SetAt)
	if err != nil {
		return fmt.Errorf("upsert party: %w", err)
	}
	return nil
}

func (s *PostgresStore) GetParty(ctx context.Context, did string) (*Party, error) {
	var p Party
	err := s.pool.QueryRow(ctx, `SELECT did, kind, operator, set_at FROM parties WHERE did = $1`, did).
		Scan(&p.DID, &p.Kind, &p.Operator, &p.SetAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("query party: %w", err)
	}
	p.SetAt = p.SetAt.UTC()
	return &p, nil
}

func (s *PostgresStore) Commits(ctx context.Context, org string, afterSeq int64, limit int) ([]repo.Committed, error) {
	if _, err := s.head(ctx, s.pool, org); err != nil {
		return nil, err
	}
	if limit <= 0 {
		limit = 1 << 30
	}
	return s.queryCommits(ctx, `org = $1 AND seq > $2 ORDER BY seq ASC LIMIT $3`, org, afterSeq, limit)
}

func (s *PostgresStore) KeyCommits(ctx context.Context, org, collection, rkey string) ([]repo.Committed, error) {
	if _, err := s.head(ctx, s.pool, org); err != nil {
		return nil, err
	}
	return s.queryCommits(ctx, `org = $1 AND collection = $2 AND rkey = $3 ORDER BY seq ASC`, org, collection, rkey)
}

func (s *PostgresStore) queryCommits(ctx context.Context, where string, args ...any) ([]repo.Committed, error) {
	rows, err := s.pool.Query(ctx, `
		SELECT org, seq, cid, prev, rev, op, collection, rkey, record, committed_by, approved_by, committed_at, sig
		FROM commits WHERE `+where, args...)
	if err != nil {
		return nil, fmt.Errorf("query commits: %w", err)
	}
	defer rows.Close()
	out := []repo.Committed{}
	for rows.Next() {
		var c repo.Committed
		var record *string
		if err := rows.Scan(&c.DID, &c.Seq, &c.CID, &c.Prev, &c.Rev, &c.Op, &c.Collection, &c.RKey, &record,
			&c.CommittedBy, &c.ApprovedBy, &c.CommittedAt, &c.Sig); err != nil {
			return nil, fmt.Errorf("scan commit: %w", err)
		}
		if record != nil {
			c.Record = []byte(*record)
		}
		if len(c.ApprovedBy) == 0 {
			c.ApprovedBy = nil
		}
		c.CommittedAt = c.CommittedAt.UTC()
		out = append(out, c)
	}
	return out, rows.Err()
}

func (s *PostgresStore) Close() error {
	s.pool.Close()
	return nil
}
