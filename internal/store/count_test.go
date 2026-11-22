package store

import (
	"context"
	"fmt"
	"os"
	"testing"
	"time"

	"github.com/DIMO-Network/did-directory/internal/did"
	"github.com/rs/zerolog"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// testDatabaseURLEnv names a Postgres database the store tests also run
// against when it is set; without it they run on the memory store only.
const testDatabaseURLEnv = "DID_DIRECTORY_TEST_DATABASE_URL"

func testStores(t *testing.T) map[string]Store {
	t.Helper()
	out := map[string]Store{"memory": NewMemoryStore()}
	if url := os.Getenv(testDatabaseURLEnv); url != "" {
		pg, err := NewPostgresStore(context.Background(), url, zerolog.Nop())
		require.NoError(t, err)
		t.Cleanup(func() { _ = pg.Close() })
		out["postgres"] = pg
	}
	return out
}

// Count answers how many operations a DID's log holds without reading them,
// so the operation cap can refuse a full log unread.
func TestCount(t *testing.T) {
	for name, st := range testStores(t) {
		t.Run(name, func(t *testing.T) {
			ctx := context.Background()
			// Fresh DIDs per run: a Postgres database keeps rows between runs.
			stamp := time.Now().UnixNano()
			a, b := fmt.Sprintf("did:dimo:counta%d", stamp), fmt.Sprintf("did:dimo:countb%d", stamp)

			n, err := st.Count(ctx, a)
			require.NoError(t, err)
			assert.Zero(t, n, "a DID the store does not hold")

			head := ""
			for i := range 3 {
				cid := fmt.Sprintf("cid-%d-%d", stamp, i)
				require.NoError(t, st.AppendAfter(ctx, a, head, cid, &did.Operation{Type: did.OpTypeCreate}))
				head = cid
			}
			require.NoError(t, st.AppendAfter(ctx, b, "", fmt.Sprintf("cid-b-%d", stamp), &did.Operation{Type: did.OpTypeCreate}))

			n, err = st.Count(ctx, a)
			require.NoError(t, err)
			assert.Equal(t, 3, n)
			n, err = st.Count(ctx, b)
			require.NoError(t, err)
			assert.Equal(t, 1, n, "other DIDs are not counted")

			log, err := st.GetLog(ctx, a)
			require.NoError(t, err)
			assert.Len(t, log, 3, "Count agrees with the log")
		})
	}
}
