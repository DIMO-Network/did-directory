package store

import (
	"context"
	"testing"
	"unsafe"

	"github.com/DIMO-Network/did-directory/internal/did"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Fiber route params alias a request buffer that is reused after the handler
// returns. The memory store must not retain those bytes.
func TestMemoryStore_AppendCopiesAliasedStrings(t *testing.T) {
	buf := []byte("did:dimo:aaaaaaaaaaaaaaaaaaaaaaaa")
	aliased := unsafe.String(&buf[0], len(buf))

	s := NewMemoryStore()
	require.NoError(t, s.Append(context.Background(), aliased, "cid", &did.Operation{Type: did.OpTypeCreate}))

	copy(buf, "export?after=0&limit=100xxxxxxxxx")

	ok, err := s.Exists(context.Background(), "did:dimo:aaaaaaaaaaaaaaaaaaaaaaaa")
	require.NoError(t, err)
	assert.True(t, ok)
	recs, err := s.Export(context.Background(), 0, 10)
	require.NoError(t, err)
	assert.Equal(t, "did:dimo:aaaaaaaaaaaaaaaaaaaaaaaa", recs[0].DID)
}
