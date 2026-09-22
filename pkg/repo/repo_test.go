package repo

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/json"
	"sort"
	"testing"
	"time"

	dimocrypto "github.com/DIMO-Network/did-directory/internal/crypto"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type keySigner struct{ key *ecdsa.PrivateKey }

func (s keySigner) Sign(_ context.Context, _ string, data []byte) (string, error) {
	return dimocrypto.SignOperation(s.key, data)
}

func (s keySigner) PublicKey(context.Context, string) (string, error) {
	return dimocrypto.EncodeDIDKey(&s.key.PublicKey)
}

func didKeyOf(t *testing.T, key *ecdsa.PrivateKey) string {
	t.Helper()
	didKey, err := dimocrypto.EncodeDIDKey(&key.PublicKey)
	require.NoError(t, err)
	return didKey
}

func newKey(t *testing.T) *ecdsa.PrivateKey {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	return key
}

func TestCanonical(t *testing.T) {
	// Keys sort, whitespace goes, numbers keep their text, HTML is not escaped.
	in := []byte(`{"z": 1, "a": {"y": [3, 2.50, 31536000000000000], "b": "<&>"}, "m": null}`)
	got, err := CanonicalRecord(in)
	require.NoError(t, err)
	assert.Equal(t, `{"a":{"b":"<&>","y":[3,2.50,31536000000000000]},"m":null,"z":1}`, string(got))

	// Fixed point.
	again, err := Canonical(json.RawMessage(got))
	require.NoError(t, err)
	assert.Equal(t, string(got), string(again))

	// Structs canonicalise through their JSON form, so field order in the
	// struct does not leak into the bytes.
	type s struct {
		Z int    `json:"z"`
		A string `json:"a"`
	}
	got, err = Canonical(s{Z: 1, A: "x"})
	require.NoError(t, err)
	assert.Equal(t, `{"a":"x","z":1}`, string(got))

	for _, bad := range []string{`[]`, `null`, `"x"`, `{"a":1} {"b":2}`, `{"a":`} {
		_, err := CanonicalRecord([]byte(bad))
		assert.Error(t, err, bad)
	}
}

func TestTID(t *testing.T) {
	a := NewTID()
	b := NewTID()
	require.NoError(t, ValidateTID(a))
	require.NoError(t, ValidateTID(b))
	assert.Less(t, a, b, "TIDs issued in order sort in order")

	// Many in a tight loop still strictly increase.
	prev := ""
	for range 1000 {
		tid := NewTID()
		assert.Greater(t, tid, prev)
		prev = tid
	}

	// A TID encodes its time to the microsecond. The time is in the future so
	// the monotonic guard, which never lets a TID sort below an earlier one from
	// this process, has nothing to bump.
	at := time.Now().Add(time.Hour).UTC().Truncate(time.Microsecond)
	got, err := TIDTime(tidAt(at))
	require.NoError(t, err)
	assert.Equal(t, at, got)

	for _, bad := range []string{"", "short", "3jzfcijpj2z2aa", "3jzfcijpj2z21", "zzzzzzzzzzzzz"} {
		assert.Error(t, ValidateTID(bad), bad)
	}
}

func signedLog(t *testing.T, key *ecdsa.PrivateKey, did string) []Committed {
	t.Helper()
	ctx := context.Background()
	signer := keySigner{key}
	now := time.Date(2026, 9, 22, 12, 0, 0, 0, time.UTC)
	steps := []struct {
		op, coll, rkey string
		record         string
		by             string
	}{
		{OpCreate, "network.dimo.org.tag", "fleet", `{"name":"Fleet"}`, ""},
		{OpCreate, "network.dimo.delegation", "3jzfcijpj2z2a", `{"$type":"network.dimo.delegation","from":"did:dimo:org"}`, "did:dimo:alice"},
		{OpUpdate, "network.dimo.org.tag", "fleet", `{"description":"All cars","name":"Fleet"}`, "did:dimo:alice"},
		{OpTombstone, "network.dimo.delegation", "3jzfcijpj2z2a", "", "did:dimo:bob"},
		{OpCreate, "network.dimo.delegation", "3jzfcijpj2z2a", `{"$type":"network.dimo.delegation","from":"did:dimo:org","v":2}`, "did:dimo:alice"},
	}
	var log []Committed
	prev := ""
	for i, s := range steps {
		c := Commit{
			DID: did, Seq: int64(i + 1), Prev: prev, Rev: NewTID(), Op: s.op,
			Collection: s.coll, RKey: s.rkey, CommittedBy: s.by,
			CommittedAt: now.Add(time.Duration(i) * time.Minute),
		}
		if s.record != "" {
			c.Record = json.RawMessage(s.record)
		}
		require.NoError(t, Sign(ctx, signer, &c))
		cid, err := c.CID()
		require.NoError(t, err)
		log = append(log, Committed{Commit: c, CID: cid})
		prev = cid
	}
	return log
}

func TestVerifyLog(t *testing.T) {
	key := newKey(t)
	const did = "did:dimo:org"
	log := signedLog(t, key, did)

	heads, err := VerifyLog(did, log, didKeyOf(t, key))
	require.NoError(t, err)
	assert.Equal(t, Head{Seq: 3, Live: true}, heads["network.dimo.org.tag/fleet"])
	assert.Equal(t, Head{Seq: 5, Live: true}, heads["network.dimo.delegation/3jzfcijpj2z2a"])

	// Serving the log as JSON and reading it back verifies the same way, which
	// is what an offline verifier does with the host's /commits output.
	data, err := json.Marshal(log)
	require.NoError(t, err)
	var decoded []Committed
	require.NoError(t, json.Unmarshal(data, &decoded))
	_, err = VerifyLog(did, decoded, didKeyOf(t, key))
	require.NoError(t, err)

	// Another key does not verify it.
	_, err = VerifyLog(did, log, didKeyOf(t, newKey(t)))
	assert.ErrorContains(t, err, "invalid signature")

	tamper := func(name string, f func(l []Committed) []Committed, want string) {
		t.Run(name, func(t *testing.T) {
			l := append([]Committed(nil), signedLog(t, key, did)...)
			_, err := VerifyLog(did, f(l), didKeyOf(t, key))
			assert.ErrorContains(t, err, want)
		})
	}
	tamper("record edited", func(l []Committed) []Committed {
		l[0].Record = json.RawMessage(`{"name":"Fleet2"}`)
		return l
	}, "invalid signature")
	tamper("committedBy edited", func(l []Committed) []Committed {
		l[1].CommittedBy = "did:dimo:mallory"
		return l
	}, "invalid signature")
	tamper("commit dropped", func(l []Committed) []Committed {
		return append(l[:1], l[2:]...)
	}, "seq 3 follows seq 1")
	tamper("commits swapped", func(l []Committed) []Committed {
		l[1], l[2] = l[2], l[1]
		return l
	}, "seq 3 follows seq 1")
	tamper("prev broken", func(l []Committed) []Committed {
		l[2].Prev = l[0].CID
		return l
	}, "prev is")
	tamper("served CID lies", func(l []Committed) []Committed {
		l[3].CID = l[2].CID
		return l
	}, "served CID")
	tamper("tombstone of nothing", func(l []Committed) []Committed {
		return l[3:4]
	}, "seq 4 follows seq 0")
	tamper("non-canonical record", func(l []Committed) []Committed {
		// Re-sign with a record whose bytes are valid JSON but not canonical.
		c := l[0].Commit
		c.Record = json.RawMessage(`{"name": "Fleet"}`)
		require.NoError(t, Sign(context.Background(), keySigner{key}, &c))
		cid, _ := c.CID()
		l[0] = Committed{Commit: c, CID: cid}
		l[1].Prev = cid
		return l[:2]
	}, "not in canonical form")

	// A log for another DID, however well signed, is not this org's.
	_, err = VerifyLog("did:dimo:other", log, didKeyOf(t, key))
	assert.ErrorContains(t, err, "belongs to")

	// Replay contradictions: a create over a live record, an update of a dead one.
	resign := func(c Commit, prev string, seq int64) Committed {
		c.Prev, c.Seq = prev, seq
		require.NoError(t, Sign(context.Background(), keySigner{key}, &c))
		cid, err := c.CID()
		require.NoError(t, err)
		return Committed{Commit: c, CID: cid}
	}
	dup := resign(log[0].Commit, log[len(log)-1].CID, 6)
	_, err = VerifyLog(did, append(append([]Committed(nil), log...), dup), didKeyOf(t, key))
	assert.ErrorContains(t, err, "create over live record")

	upd := log[2].Commit
	upd.Collection, upd.RKey = "network.dimo.delegation", "3jzfcijpj2z2a"
	l := append([]Committed(nil), log[:4]...)
	l = append(l, resign(upd, log[3].CID, 5))
	_, err = VerifyLog(did, l, didKeyOf(t, key))
	assert.ErrorContains(t, err, "which is not live")

	// The head map lists every key touched, tombstoned ones included.
	l = append([]Committed(nil), log[:4]...)
	heads, err = VerifyLog(did, l, didKeyOf(t, key))
	require.NoError(t, err)
	keys := make([]string, 0, len(heads))
	for k := range heads {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	assert.Equal(t, []string{"network.dimo.delegation/3jzfcijpj2z2a", "network.dimo.org.tag/fleet"}, keys)
	assert.Equal(t, Head{Seq: 2, Live: false, TombstoneSeq: 4}, heads["network.dimo.delegation/3jzfcijpj2z2a"])
}

func TestCommitSigningExcludesSig(t *testing.T) {
	key := newKey(t)
	c := Commit{DID: "did:dimo:org", Seq: 1, Rev: NewTID(), Op: OpCreate, Collection: "c", RKey: "k",
		Record: json.RawMessage(`{"a":1}`), CommittedAt: time.Now().UTC().Truncate(time.Microsecond)}
	before, err := c.SigningBytes()
	require.NoError(t, err)
	require.NoError(t, Sign(context.Background(), keySigner{key}, &c))
	after, err := c.SigningBytes()
	require.NoError(t, err)
	assert.Equal(t, before, after)
	assert.NotContains(t, string(before), `"sig"`)
	require.NoError(t, Verify(&c, didKeyOf(t, key)))

	// The CID does cover the signature.
	cid1, _ := c.CID()
	c.Sig = "AAAA"
	cid2, _ := c.CID()
	assert.NotEqual(t, cid1, cid2)
}
