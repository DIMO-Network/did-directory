package store

import (
	"context"
	"fmt"
	"net/url"
	"os"
	"testing"
	"time"

	"github.com/DIMO-Network/did-directory/pkg/repo"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/rs/zerolog"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// A host that ran before the KMS signer has an orgs table whose sealed key is
// NOT NULL and no signing_key_ref. Starting the store must migrate it in
// place: the old rows still load, and a KMS row (no sealed key) can be written.
func TestPostgres_MigratesAPreKMSOrgsTable(t *testing.T) {
	dbURL := os.Getenv(TestDatabaseURLEnv)
	if dbURL == "" {
		t.Skip("no " + TestDatabaseURLEnv)
	}
	ctx := context.Background()
	admin, err := pgxpool.New(ctx, dbURL)
	require.NoError(t, err)
	t.Cleanup(admin.Close)

	// A schema of its own, so the shared test tables are not touched.
	schema := fmt.Sprintf("orghost_migration_%d", time.Now().UnixNano())
	_, err = admin.Exec(ctx, "CREATE SCHEMA "+schema)
	require.NoError(t, err)
	t.Cleanup(func() { _, _ = admin.Exec(context.Background(), "DROP SCHEMA "+schema+" CASCADE") })
	_, err = admin.Exec(ctx, `CREATE TABLE `+schema+`.orgs (
		did             TEXT PRIMARY KEY,
		signing_key_enc BYTEA NOT NULL,
		created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
	)`)
	require.NoError(t, err)
	created := time.Date(2026, 10, 1, 12, 0, 0, 0, time.UTC)
	_, err = admin.Exec(ctx, `INSERT INTO `+schema+`.orgs (did, signing_key_enc, created_at) VALUES ($1, $2, $3)`,
		"did:dimo:legacy", []byte("sealed"), created)
	require.NoError(t, err)

	u, err := url.Parse(dbURL)
	require.NoError(t, err)
	q := u.Query()
	q.Set("search_path", schema)
	u.RawQuery = q.Encode()

	// Twice: the migration is idempotent across restarts.
	for i := range 2 {
		s, err := NewPostgresStore(ctx, u.String(), zerolog.Nop())
		require.NoError(t, err, "start %d", i)

		org, err := s.GetOrg(ctx, "did:dimo:legacy")
		require.NoError(t, err)
		assert.Equal(t, []byte("sealed"), org.KeyEnc)
		assert.Empty(t, org.KeyRef)
		assert.Equal(t, created, org.CreatedAt)

		kms := fmt.Sprintf("did:dimo:kms%d", i)
		const arn = "arn:aws:kms:us-east-1:111122223333:key/abc"
		require.NoError(t, s.CreateOrg(ctx, Org{DID: kms, KeyRef: arn}), "a KMS row has no sealed key")
		org, err = s.GetOrg(ctx, kms)
		require.NoError(t, err)
		assert.Equal(t, arn, org.KeyRef)
		assert.Empty(t, org.KeyEnc)

		has, err := s.HasLocalOrgs(ctx)
		require.NoError(t, err)
		assert.True(t, has, "the legacy row is a local org")

		// The rest of the schema landed beside the migrated table, and a
		// commit for the legacy org goes in against it.
		head, err := s.Head(ctx, "did:dimo:legacy")
		require.NoError(t, err)
		c := commit("did:dimo:legacy", head, repo.OpCreate, "network.dimo.org.tag", fmt.Sprintf("t%d", i), `{"name":"fleet"}`, "")
		require.NoError(t, s.AppendAfter(ctx, head, c))
		got, err := s.Current(ctx, "did:dimo:legacy", "network.dimo.org.tag", fmt.Sprintf("t%d", i))
		require.NoError(t, err)
		assert.JSONEq(t, `{"name":"fleet"}`, string(got.Record))
		require.NoError(t, s.Close())
	}

	var nullable string
	require.NoError(t, admin.QueryRow(ctx, `SELECT is_nullable FROM information_schema.columns
		WHERE table_schema = $1 AND table_name = 'orgs' AND column_name = 'signing_key_enc'`, schema).Scan(&nullable))
	assert.Equal(t, "YES", nullable)
	var tables int
	require.NoError(t, admin.QueryRow(ctx, `SELECT count(*) FROM information_schema.tables WHERE table_schema = $1`, schema).Scan(&tables))
	assert.Equal(t, 5, tables, "orgs, commits, heads, parties, pending")
}
