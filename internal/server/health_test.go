package server

import (
	"context"
	"errors"
	"net/http/httptest"
	"testing"

	"github.com/DIMO-Network/did-directory/internal/config"
	"github.com/DIMO-Network/did-directory/internal/store"
	"github.com/rs/zerolog"
	"github.com/stretchr/testify/require"
)

type pingStore struct {
	store.Store
	err error
}

func (p pingStore) Ping(context.Context) error { return p.err }

func TestHealthFailsWhenStoreDown(t *testing.T) {
	cfg := &config.Settings{ExportPageSize: 100}

	down := New(cfg, pingStore{Store: store.NewMemoryStore(), err: errors.New("db down")}, zerolog.Nop())
	resp, err := down.Test(httptest.NewRequest("GET", "/health", nil))
	require.NoError(t, err)
	require.Equal(t, 503, resp.StatusCode)

	// Liveness must not depend on the store.
	resp, err = down.Test(httptest.NewRequest("GET", "/ping", nil))
	require.NoError(t, err)
	require.Equal(t, 200, resp.StatusCode)

	up := New(cfg, pingStore{Store: store.NewMemoryStore()}, zerolog.Nop())
	resp, err = up.Test(httptest.NewRequest("GET", "/health", nil))
	require.NoError(t, err)
	require.Equal(t, 200, resp.StatusCode)
}
