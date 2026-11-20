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

type busyStore struct {
	store.Store
	busy bool
	err  error
}

func (b busyStore) Busy() bool                 { return b.busy }
func (b busyStore) Ping(context.Context) error { return b.err }

func TestHealthReadyWhenPoolSaturated(t *testing.T) {
	cfg := &config.Settings{ExportPageSize: 100}

	// Every connection busy: a Ping would fail or queue, but busy proves the DB is up.
	app := New(cfg, busyStore{Store: store.NewMemoryStore(), busy: true, err: errors.New("pool exhausted")}, zerolog.Nop())
	resp, err := app.Test(httptest.NewRequest("GET", "/health", nil))
	require.NoError(t, err)
	require.Equal(t, 200, resp.StatusCode)

	// Not saturated: the ping decides.
	app = New(cfg, busyStore{Store: store.NewMemoryStore(), err: errors.New("db down")}, zerolog.Nop())
	resp, err = app.Test(httptest.NewRequest("GET", "/health", nil))
	require.NoError(t, err)
	require.Equal(t, 503, resp.StatusCode)
}

// hangStore's Ping blocks until the probe's context expires, as a stuck DB does.
type hangStore struct {
	store.Store
	busy bool
}

func (h hangStore) Busy() bool { return h.busy }
func (h hangStore) Ping(ctx context.Context) error {
	<-ctx.Done()
	return ctx.Err()
}

func TestHealthStuckSaturatedPoolFailsOnPing(t *testing.T) {
	cfg := &config.Settings{ExportPageSize: 100}
	// Saturated with a flat AcquireCount: Busy is false, so Ping runs and times out.
	app := New(cfg, hangStore{Store: store.NewMemoryStore()}, zerolog.Nop())
	resp, err := app.Test(httptest.NewRequest("GET", "/health", nil), 5000)
	require.NoError(t, err)
	require.Equal(t, 503, resp.StatusCode)

	// Saturated and cycling: ready without touching Ping.
	app = New(cfg, hangStore{Store: store.NewMemoryStore(), busy: true}, zerolog.Nop())
	resp, err = app.Test(httptest.NewRequest("GET", "/health", nil))
	require.NoError(t, err)
	require.Equal(t, 200, resp.StatusCode)
}
