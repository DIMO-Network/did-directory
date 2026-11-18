package client

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestTypedErrors(t *testing.T) {
	calls := map[string]func(c *Client) error{
		"Resolve":  func(c *Client) error { _, err := c.Resolve(context.Background(), "did:x:1"); return err },
		"Control":  func(c *Client) error { _, err := c.Control(context.Background(), "did:x:1"); return err },
		"AuditLog": func(c *Client) error { _, err := c.AuditLog(context.Background(), "did:x:1"); return err },
	}
	for name, call := range calls {
		t.Run(name, func(t *testing.T) {
			status := 0
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(status)
				_, _ = w.Write([]byte("body"))
			}))
			defer srv.Close()
			c := New(srv.URL)

			status = 404
			assert.ErrorIs(t, call(c), ErrNotFound)

			status = 410
			err := call(c)
			assert.ErrorIs(t, err, ErrGone)
			var se *StatusError
			assert.False(t, errors.As(err, &se))

			for _, code := range []int{400, 503} {
				status = code
				err = call(c)
				require.ErrorAs(t, err, &se)
				assert.Equal(t, code, se.Status)
				assert.Equal(t, "body", se.Body)
				assert.NotErrorIs(t, err, ErrNotFound)
				assert.NotErrorIs(t, err, ErrGone)
			}
		})
	}
}
