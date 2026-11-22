package handlers

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/json"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
	"testing"

	dimocrypto "github.com/DIMO-Network/did-directory/internal/crypto"
	"github.com/DIMO-Network/did-directory/internal/did"
	"github.com/DIMO-Network/did-directory/internal/store"
	"github.com/DIMO-Network/did-directory/pkg/control"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// countingStore counts how a request reads the log: one row, or all of it.
type countingStore struct {
	store.Store
	latest, log atomic.Int64
}

func (s *countingStore) GetLatest(ctx context.Context, d string) (*store.OperationRecord, error) {
	s.latest.Add(1)
	return s.Store.GetLatest(ctx, d)
}

func (s *countingStore) GetLog(ctx context.Context, d string) ([]store.OperationRecord, error) {
	s.log.Add(1)
	return s.Store.GetLog(ctx, d)
}

func (s *countingStore) reset() { s.latest.Store(0); s.log.Store(0) }

func plainUpdate(o *owned, alias ...string) *did.Operation {
	if alias == nil {
		alias = []string{}
	}
	return &did.Operation{Type: did.OpTypeCreate, RotationKeys: []string{o.dk},
		VerificationMethods: map[string]string{"signing": o.dk}, AlsoKnownAs: alias, Services: map[string]did.Service{}}
}

// R3-F2, the reviewer's and V2's probe: with MAX_OPERATIONS_PER_DID at 3, the
// directory took 11 (and, against Postgres, 101) operations. The cap now
// holds: the update that would make a fourth is refused 422.
func TestSubmit_OperationCapEnforced(t *testing.T) {
	f := newFixtureWith(t, store.NewMemoryStore(), 3)
	o := f.ownedDID()

	for i := range 2 {
		status, body := o.submit(f, plainUpdate(o, "at://"+strings.Repeat("a", i+1)))
		require.Equal(t, http.StatusOK, status, "update %d: %s", i, body)
	}
	for _, typ := range []string{"plain", "another plain"} {
		status, body := o.submit(f, plainUpdate(o, "at://over-"+typ))
		assert.Equal(t, http.StatusUnprocessableEntity, status, string(body))
		assert.Contains(t, string(body), "operation log is full")
	}
	log, err := f.st.GetLog(context.Background(), o.did)
	require.NoError(t, err)
	assert.Len(t, log, 3)

	// Deactivation stays possible on a full log: a tombstone is terminal, so it
	// can add at most one operation past the cap.
	status, body := o.submit(f, &did.Operation{Type: did.OpTypeTombstone})
	require.Equal(t, http.StatusOK, status, string(body))
	log, err = f.st.GetLog(context.Background(), o.did)
	require.NoError(t, err)
	assert.Len(t, log, 4)
}

// R3-F2: an operation's stored (JSON) encoding is capped at 16 KiB, on a
// genesis and on an update, so no log row can be large.
func TestSubmit_OperationSizeCapped(t *testing.T) {
	f := newFixture(t)
	big := "at://" + strings.Repeat("a", did.MaxOperationBytes)

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	dk, err := dimocrypto.EncodeDIDKey(&key.PublicKey)
	require.NoError(t, err)
	gen := &did.Operation{Type: did.OpTypeCreate, RotationKeys: []string{dk}, VerificationMethods: map[string]string{"signing": dk},
		AlsoKnownAs: []string{big}, Services: map[string]did.Service{}}
	data, err := json.Marshal(gen.ToUnsigned())
	require.NoError(t, err)
	gen.Sig, err = dimocrypto.SignOperation(key, data)
	require.NoError(t, err)
	id, err := did.DeriveFromGenesis(gen)
	require.NoError(t, err)
	raw, err := json.Marshal(gen)
	require.NoError(t, err)
	status, body := f.post("/"+id, raw)
	assert.Equal(t, http.StatusRequestEntityTooLarge, status, string(body))
	assert.Contains(t, string(body), "16384")

	o := f.ownedDID()
	status, body = o.submit(f, plainUpdate(o, big))
	assert.Equal(t, http.StatusRequestEntityTooLarge, status, string(body))

	status, body = o.submit(f, plainUpdate(o, "at://"+strings.Repeat("a", 15_000)))
	assert.Equal(t, http.StatusOK, status, string(body))
}

// R3-F2: the head-only paths read one row for an uncontrolled DID (person and
// org DIDs, which dauth resolves at every sign-in) and for a tombstone. Only a
// controlled DID's era history needs the log.
func TestResolve_HeadOnlyPathsReadOneRow(t *testing.T) {
	st := &countingStore{Store: store.NewMemoryStore()}
	f := newFixtureWith(t, st, 0)
	o := f.ownedDID()
	status, body := o.submit(f, plainUpdate(o, "at://alice.dimo.zone"))
	require.Equal(t, http.StatusOK, status, string(body))

	for _, path := range []string{"", "/data", "/control"} {
		st.reset()
		status, body := f.get("/" + o.did + path)
		require.Equal(t, http.StatusOK, status, "%s: %s", path, body)
		assert.Zero(t, st.log.Load(), "%s read the whole log", path)
		assert.Equal(t, int64(1), st.latest.Load(), path)
	}
	var data map[string]any
	_, body = f.get("/" + o.did + "/data")
	require.NoError(t, json.Unmarshal(body, &data))
	assert.Equal(t, o.head, data["cid"])
	assert.Equal(t, []any{}, data["eras"])
	assert.Equal(t, []any{"at://alice.dimo.zone"}, data["alsoKnownAs"])

	status, body = o.submit(f, &did.Operation{Type: did.OpTypeTombstone})
	require.Equal(t, http.StatusOK, status, string(body))
	for _, path := range []string{"", "/data"} {
		st.reset()
		status, _ := f.get("/" + o.did + path)
		assert.Equal(t, http.StatusGone, status, path)
		assert.Zero(t, st.log.Load(), "%s read the whole log", path)
	}

	st.reset()
	status, _ = f.get("/did:dimo:aaaaaaaaaaaaaaaaaaaaaaaa")
	assert.Equal(t, http.StatusNotFound, status)
	status, _ = f.get("/did:dimo:aaaaaaaaaaaaaaaaaaaaaaaa/data")
	assert.Equal(t, http.StatusNotFound, status)
	assert.Zero(t, st.log.Load())
}

// A controlled DID still answers from its era history.
func TestResolve_ControlledDIDReadsTheLog(t *testing.T) {
	st := &countingStore{Store: store.NewMemoryStore()}
	f := newFixtureWith(t, st, 0)
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	dk, err := dimocrypto.EncodeDIDKey(&key.PublicKey)
	require.NoError(t, err)
	salt, err := control.NewSalt()
	require.NoError(t, err)
	commitment, err := control.Commit(control.Opening{Controller: "did:dimo:avis", Era: 0, Salt: salt})
	require.NoError(t, err)
	gen := &did.Operation{Type: did.OpTypeCreate, RotationKeys: []string{dk}, AlsoKnownAs: []string{},
		Services: map[string]did.Service{}, ControlCommitment: &commitment}
	data, err := json.Marshal(gen.ToUnsigned())
	require.NoError(t, err)
	gen.Sig, err = dimocrypto.SignOperation(key, data)
	require.NoError(t, err)
	id, err := did.DeriveFromGenesis(gen)
	require.NoError(t, err)
	raw, err := json.Marshal(gen)
	require.NoError(t, err)
	status, body := f.post("/"+id, raw)
	require.Equal(t, http.StatusOK, status, string(body))

	st.reset()
	status, body = f.get("/" + id)
	require.Equal(t, http.StatusOK, status, string(body))
	var doc did.DIDDocument
	require.NoError(t, json.Unmarshal(body, &doc))
	require.NotNil(t, doc.DimoControl)
	assert.Equal(t, commitment, doc.DimoControl.ControlCommitment)
	assert.Equal(t, int64(1), st.log.Load())

	_, body = f.get("/" + id + "/data")
	var out map[string]any
	require.NoError(t, json.Unmarshal(body, &out))
	assert.Len(t, out["eras"], 1)
}

// V2's probe: a junk update loaded the whole log before its signature was
// checked. The head alone decides the tombstone, prev and signature checks.
func TestSubmit_UnsignedUpdateReadsOnlyTheHead(t *testing.T) {
	st := &countingStore{Store: store.NewMemoryStore()}
	f := newFixtureWith(t, st, 0)
	o := f.ownedDID()

	intruder, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	op := plainUpdate(o)
	op.Prev = &o.head
	data, err := json.Marshal(op.ToUnsigned())
	require.NoError(t, err)
	op.Sig, err = dimocrypto.SignOperation(intruder, data)
	require.NoError(t, err)
	raw, err := json.Marshal(op)
	require.NoError(t, err)

	st.reset()
	status, body := f.post("/"+o.did, raw)
	assert.Equal(t, http.StatusBadRequest, status, string(body))
	assert.Contains(t, string(body), "invalid signature")
	assert.Zero(t, st.log.Load())

	stale := "bafyreistale"
	op.Prev = &stale
	raw, err = json.Marshal(op)
	require.NoError(t, err)
	st.reset()
	status, body = f.post("/"+o.did, raw)
	assert.Equal(t, http.StatusConflict, status, string(body))
	assert.Zero(t, st.log.Load())
}

// racingStore lands an operation from another writer the first time GetLog
// runs after inject is set: between handleUpdate's read of the head and its
// read of the log.
type racingStore struct {
	store.Store
	mu     sync.Mutex
	inject func() error
	err    error
}

func (s *racingStore) GetLog(ctx context.Context, d string) ([]store.OperationRecord, error) {
	s.mu.Lock()
	inject := s.inject
	s.inject = nil
	s.mu.Unlock()
	if inject != nil {
		if err := inject(); err != nil {
			s.mu.Lock()
			s.err = err
			s.mu.Unlock()
		}
	}
	return s.Store.GetLog(ctx, d)
}

// The signature is checked against the head's rotation keys. If another
// writer rotates them (K1 to K2) between that check and the append, an
// operation K1 signed against the old head must not land after the rotation.
func TestSubmit_HeadMovedBetweenReadsIs409(t *testing.T) {
	st := &racingStore{Store: store.NewMemoryStore()}
	f := newFixtureWith(t, st, 0)
	o := f.ownedDID() // K1 is the rotation key
	genesis := o.head

	k2, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	dk2, err := dimocrypto.EncodeDIDKey(&k2.PublicKey)
	require.NoError(t, err)
	rotation := &did.Operation{Type: did.OpTypeCreate, RotationKeys: []string{dk2},
		VerificationMethods: map[string]string{"signing": dk2}, AlsoKnownAs: []string{}, Services: map[string]did.Service{}, Prev: &genesis}
	data, err := json.Marshal(rotation.ToUnsigned())
	require.NoError(t, err)
	rotation.Sig, err = dimocrypto.SignOperation(o.key, data)
	require.NoError(t, err)
	rotationCID, err := did.ComputeCID(rotation)
	require.NoError(t, err)
	st.inject = func() error {
		return st.Store.AppendAfter(context.Background(), o.did, genesis, rotationCID, rotation)
	}

	// K1 signs it and its prev is the genesis: both pass against the head as
	// handleUpdate first reads it.
	status, body := o.submit(f, plainUpdate(o, "at://stale"))
	require.NoError(t, st.err)
	assert.Equal(t, http.StatusConflict, status, string(body))

	log, err := st.Store.GetLog(context.Background(), o.did)
	require.NoError(t, err)
	require.Len(t, log, 2, "only the rotation landed")
	assert.Equal(t, rotationCID, log[1].CID)
}

// R3-F2 follow-up: a full log is refused from a count, without reading the
// log, so a replayed signed update costs one row and a COUNT each time.
func TestSubmit_FullLogRefusedWithoutReadingIt(t *testing.T) {
	st := &countingStore{Store: store.NewMemoryStore()}
	f := newFixtureWith(t, st, 2)
	o := f.ownedDID()
	status, body := o.submit(f, plainUpdate(o, "at://one"))
	require.Equal(t, http.StatusOK, status, string(body))

	raw := o.signed(f, plainUpdate(o, "at://two"))
	for range 3 {
		st.reset()
		status, body := f.post("/"+o.did, raw)
		assert.Equal(t, http.StatusUnprocessableEntity, status, string(body))
		assert.Contains(t, string(body), "operation log is full")
		assert.Zero(t, st.log.Load(), "the full log was read")
	}

	// The tombstone exemption still holds.
	status, body = o.submit(f, &did.Operation{Type: did.OpTypeTombstone})
	assert.Equal(t, http.StatusOK, status, string(body))
}
