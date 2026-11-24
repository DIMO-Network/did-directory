package server

import (
	"bufio"
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/DIMO-Network/did-directory/internal/config"
	dimocrypto "github.com/DIMO-Network/did-directory/internal/crypto"
	"github.com/DIMO-Network/did-directory/internal/did"
	"github.com/DIMO-Network/did-directory/internal/store"
	"github.com/rs/zerolog"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// countingStore counts the store calls a request makes.
type countingStore struct {
	store.Store
	calls atomic.Int64
}

func (s *countingStore) Exists(ctx context.Context, d string) (bool, error) {
	s.calls.Add(1)
	return s.Store.Exists(ctx, d)
}

func (s *countingStore) GetLog(ctx context.Context, d string) ([]store.OperationRecord, error) {
	s.calls.Add(1)
	return s.Store.GetLog(ctx, d)
}

func (s *countingStore) GetLatest(ctx context.Context, d string) (*store.OperationRecord, error) {
	s.calls.Add(1)
	return s.Store.GetLatest(ctx, d)
}

// errBodyTooLarge is what app.Test returns when fasthttp refuses a body over
// the limit: it answers 413 on the wire (TestSubmit_OversizedBodyIs413OnTheWire)
// but app.Test hands back the server's error instead of the response.
const errBodyTooLarge = "body size exceeds the given limit"

func postRaw(t *testing.T, st store.Store, path string, body []byte) (int, string, error) {
	t.Helper()
	app := New(&config.Settings{ExportPageSize: 100}, st, zerolog.Nop())
	req := httptest.NewRequest(http.MethodPost, path, bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	resp, err := app.Test(req, -1)
	if err != nil {
		return 0, "", err
	}
	defer resp.Body.Close()
	var buf bytes.Buffer
	_, _ = buf.ReadFrom(resp.Body)
	return resp.StatusCode, buf.String(), nil
}

// R3-F1, the reviewer's probe: an anonymous genesis whose one rotation key is
// "did:key:z" and a million base58 digits (about 1 MB) used to cost 3 s of
// CPU. The body is refused before the handler reads it.
func TestSubmit_OneMegabyteBodyRefusedBeforeDecoding(t *testing.T) {
	op := map[string]any{
		"type":                "plc_operation",
		"rotationKeys":        []string{"did:key:z" + strings.Repeat("2", 1_000_000)},
		"verificationMethods": map[string]string{"a": "x"},
		"alsoKnownAs":         []string{},
		"services":            map[string]any{},
		"prev":                nil,
		"sig":                 "x",
	}
	body, err := json.Marshal(op)
	require.NoError(t, err)
	require.Greater(t, len(body), 1_000_000)

	st := &countingStore{Store: store.NewMemoryStore()}
	start := time.Now()
	_, _, err = postRaw(t, st, "/did:dimo:aaaaaaaaaaaaaaaaaaaaaaaa", body)
	assert.ErrorContains(t, err, errBodyTooLarge)
	assert.Zero(t, st.calls.Load(), "the handler never ran")
	assert.Less(t, time.Since(start), time.Second)
}

// R3-F1, the other probe shape: 15,000 copies of a real key and a junk sig
// (900 KB) are refused by size too.
func TestSubmit_ManyRotationKeysRefused(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	dk, err := dimocrypto.EncodeDIDKey(&key.PublicKey)
	require.NoError(t, err)
	keys := make([]string, 15_000)
	for i := range keys {
		keys[i] = dk
	}
	op := &did.Operation{Type: did.OpTypeCreate, RotationKeys: keys, VerificationMethods: map[string]string{"signing": dk},
		AlsoKnownAs: []string{}, Services: map[string]did.Service{}, Sig: strings.Repeat("A", 86)}
	id, err := did.DeriveFromGenesis(op)
	require.NoError(t, err)
	body, err := json.Marshal(op)
	require.NoError(t, err)

	st := &countingStore{Store: store.NewMemoryStore()}
	_, _, err = postRaw(t, st, "/"+id, body)
	assert.ErrorContains(t, err, errBodyTooLarge)
	assert.Zero(t, st.calls.Load())

	// Under the body limit, six keys are refused by count before any decoding.
	op.RotationKeys = keys[:6]
	id, err = did.DeriveFromGenesis(op)
	require.NoError(t, err)
	body, err = json.Marshal(op)
	require.NoError(t, err)
	status, text, err := postRaw(t, st, "/"+id, body)
	require.NoError(t, err)
	assert.Equal(t, http.StatusBadRequest, status)
	assert.Contains(t, text, "at most 5 rotation keys")
}

// The limit is 64 KiB: a valid genesis padded with whitespace to just under it
// is read and accepted, and one byte over is refused.
func TestSubmit_BodyLimitIs64KiB(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	dk, err := dimocrypto.EncodeDIDKey(&key.PublicKey)
	require.NoError(t, err)
	op := &did.Operation{Type: did.OpTypeCreate, RotationKeys: []string{dk}, VerificationMethods: map[string]string{"signing": dk},
		AlsoKnownAs: []string{}, Services: map[string]did.Service{}}
	data, err := json.Marshal(op.ToUnsigned())
	require.NoError(t, err)
	op.Sig, err = dimocrypto.SignOperation(key, data)
	require.NoError(t, err)
	id, err := did.DeriveFromGenesis(op)
	require.NoError(t, err)
	raw, err := json.Marshal(op)
	require.NoError(t, err)

	over := append(bytes.Repeat([]byte(" "), 64<<10+1-len(raw)), raw...)
	_, _, err = postRaw(t, store.NewMemoryStore(), "/"+id, over)
	assert.ErrorContains(t, err, errBodyTooLarge)

	at := append(bytes.Repeat([]byte(" "), 64<<10-len(raw)), raw...)
	status, text, err := postRaw(t, store.NewMemoryStore(), "/"+id, at)
	require.NoError(t, err)
	assert.Equal(t, http.StatusOK, status, text)
}

// On the wire the refusal is a 413, sent from the headers alone: the server
// does not wait for (or read) a body its Content-Length puts over the limit.
func TestSubmit_OversizedBodyIs413OnTheWire(t *testing.T) {
	app := New(&config.Settings{ExportPageSize: 100}, store.NewMemoryStore(), zerolog.Nop())
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	go func() { _ = app.Listener(ln) }()
	t.Cleanup(func() { _ = app.ShutdownWithTimeout(time.Second) })

	for _, length := range []int{64<<10 + 1, 1_000_138} {
		t.Run(fmt.Sprint(length), func(t *testing.T) {
			conn, err := net.Dial("tcp", ln.Addr().String())
			require.NoError(t, err)
			defer func() { _ = conn.Close() }()
			require.NoError(t, conn.SetDeadline(time.Now().Add(3*time.Second)))
			_, err = fmt.Fprintf(conn, "POST /did:dimo:aaaaaaaaaaaaaaaaaaaaaaaa HTTP/1.1\r\nHost: directory.test\r\n"+
				"Content-Type: application/json\r\nContent-Length: %d\r\n\r\n", length)
			require.NoError(t, err)
			resp, err := http.ReadResponse(bufio.NewReader(conn), nil)
			require.NoError(t, err, "no answer before the body was sent")
			defer func() { _ = resp.Body.Close() }()
			assert.Equal(t, http.StatusRequestEntityTooLarge, resp.StatusCode)
		})
	}
}

// R3-F2, the reviewer's probe through the server: MAX_OPERATIONS_PER_DID=3
// took 11 operations. The cap set in config now holds.
func TestServer_MaxOperationsPerDIDFromConfig(t *testing.T) {
	app := New(&config.Settings{ExportPageSize: 100, MaxOperationsPerDID: 3}, store.NewMemoryStore(), zerolog.Nop())
	f := &flow{t: t, app: app}
	key, dk := f.key()
	gen := f.sign(key, &did.Operation{Type: did.OpTypeCreate, RotationKeys: []string{dk},
		VerificationMethods: map[string]string{"signing": dk}, AlsoKnownAs: []string{}, Services: map[string]did.Service{}})
	id, err := did.DeriveFromGenesis(gen)
	require.NoError(t, err)
	status, out := f.submit(id, gen)
	require.Equal(t, http.StatusOK, status, out)
	prev := out["cid"].(string)

	accepted := 1
	for i := range 10 {
		p := prev
		op := f.sign(key, &did.Operation{Type: did.OpTypeCreate, RotationKeys: []string{dk},
			VerificationMethods: map[string]string{"signing": dk}, AlsoKnownAs: []string{fmt.Sprintf("at://%d", i)},
			Services: map[string]did.Service{}, Prev: &p})
		status, out := f.submit(id, op)
		if status != http.StatusOK {
			assert.Equal(t, http.StatusUnprocessableEntity, status, out)
			continue
		}
		accepted++
		prev = out["cid"].(string)
	}
	assert.Equal(t, 3, accepted)

	var entries []map[string]any
	require.Equal(t, http.StatusOK, f.get("/"+id+"/log/audit", &entries))
	assert.Len(t, entries, 3)
}
