package proof

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/json"
	"testing"
	"time"

	dimocrypto "github.com/DIMO-Network/did-directory/internal/crypto"
	"github.com/DIMO-Network/did-directory/pkg/control"
	"github.com/DIMO-Network/did-directory/pkg/delegation"
	"github.com/DIMO-Network/did-directory/pkg/repo"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const (
	org     = "did:dimo:avis"
	car     = "did:dimo:car"
	insurer = "did:dimo:insurer"
	staff   = "did:dimo:staff"
)

func day(d int) time.Time       { return time.Date(2026, 1, d, 0, 0, 0, 0, time.UTC) }
func tp(t time.Time) *time.Time { return &t }

type keySigner struct{ key *ecdsa.PrivateKey }

func (s keySigner) Sign(_ context.Context, _ string, data []byte) (string, error) {
	return dimocrypto.SignOperation(s.key, data)
}

func (s keySigner) PublicKey(context.Context, string) (string, error) {
	return dimocrypto.EncodeDIDKey(&s.key.PublicKey)
}

// log builds an org's commit log the way a host would: signed, chained,
// canonical.
type log struct {
	t      *testing.T
	org    string
	signer keySigner
	key    string
	head   repo.Committed
	all    []repo.Committed
}

func newLog(t *testing.T, org string) *log {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	didKey, err := dimocrypto.EncodeDIDKey(&key.PublicKey)
	require.NoError(t, err)
	return &log{t: t, org: org, signer: keySigner{key: key}, key: didKey}
}

func (l *log) commit(op, collection, rkey string, record any, by string, at time.Time, approved ...string) repo.Committed {
	l.t.Helper()
	c := repo.Committed{Commit: repo.Commit{
		DID: l.org, Seq: l.head.Seq + 1, Prev: l.head.CID, Rev: repo.NewTID(), Op: op,
		Collection: collection, RKey: rkey, CommittedBy: by, ApprovedBy: approved, CommittedAt: at,
	}}
	if record != nil {
		raw, err := json.Marshal(record)
		require.NoError(l.t, err)
		c.Record, err = repo.CanonicalRecord(raw)
		require.NoError(l.t, err)
	}
	require.NoError(l.t, repo.Sign(context.Background(), l.signer, &c.Commit))
	var err error
	c.CID, err = c.Commit.CID()
	require.NoError(l.t, err)
	l.head = c
	l.all = append(l.all, c)
	return c
}

// fixture is one org, controller of one car, with a root grant to the insurer
// written by a staff member under a role, and a proof of that grant on day 20.
type fixture struct {
	log     *log
	opening control.Opening
	state   *control.State
	grant   string
	proof   *Proof
}

func newFixture(t *testing.T) *fixture {
	t.Helper()
	l := newLog(t, org)
	salt, err := control.NewSalt()
	require.NoError(t, err)
	opening := control.Opening{Controller: org, Era: 0, Salt: salt}
	commitment, err := control.Commit(opening)
	require.NoError(t, err)
	state := &control.State{DID: car, Eras: []control.Era{{Number: 0, Commitment: commitment}}}

	l.commit(repo.OpCreate, delegation.CollectionVehicleControl, car, opening, "", day(1))
	role := delegation.Record{
		Type: delegation.TypeRole, From: org, To: staff, Covers: delegation.Covers{Inherit: true},
		Abilities:  []string{"delegation:create", "events:read"},
		Validity:   delegation.Window{From: tp(day(1))},
		Redelegate: delegation.Redelegate{Mode: delegation.RedelegateNone}, CreatedAt: day(1),
	}
	l.commit(repo.OpCreate, delegation.CollectionRole, "staff", role, "", day(1))
	grant := delegation.Record{
		Type: delegation.TypeDelegation, From: org, To: insurer, Covers: delegation.Covers{Vehicle: car},
		Abilities:  []string{"events:read"},
		DataWindow: delegation.Window{From: tp(day(5)), To: tp(day(15))},
		Validity:   delegation.Window{From: tp(day(5))},
		Redelegate: delegation.Redelegate{Mode: delegation.RedelegateNone}, CreatedAt: day(2),
	}
	l.commit(repo.OpCreate, delegation.CollectionDelegation, "insurer", grant, staff, day(2))

	uri := "at://" + org + "/" + delegation.CollectionDelegation + "/insurer"
	p := &Proof{
		Delegation: uri, Vehicle: car, At: day(20),
		Keys:    map[string]string{org: l.key},
		Commits: l.all,
		Control: state,
		Parties: map[string]Party{org: {Kind: KindOrg, Operator: true}},
	}
	cov, err := Evaluate(context.Background(), p, Anchors{})
	require.NoError(t, err)
	p.Coverage = cov
	return &fixture{log: l, opening: opening, state: state, grant: uri, proof: p}
}

// roundTrip is what a proof looks like to the party that holds it: JSON.
func roundTrip(t *testing.T, p *Proof) *Proof {
	t.Helper()
	raw, err := json.Marshal(p)
	require.NoError(t, err)
	var out Proof
	require.NoError(t, json.Unmarshal(raw, &out))
	return &out
}

func TestProofVerifies(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	p := roundTrip(t, f.proof)

	cov, err := Verify(ctx, p, Anchors{})
	require.NoError(t, err)
	assert.Equal(t, []string{f.grant}, cov.Chain)
	w := cov.Historical["events:read"]
	assert.True(t, w.Contains(day(10)))
	assert.False(t, w.Contains(day(16)), "the data window ends on day 15")
	assert.Empty(t, cov.Live)

	// Against anchors the verifier fetched itself.
	_, err = Verify(ctx, p, Anchors{Keys: map[string]string{org: f.log.key}, Control: f.state})
	require.NoError(t, err)
}

func TestProofRefusesTampering(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()

	t.Run("edited record", func(t *testing.T) {
		p := roundTrip(t, f.proof)
		for i := range p.Commits {
			if p.Commits[i].RKey == "insurer" {
				var rec map[string]any
				require.NoError(t, json.Unmarshal(p.Commits[i].Record, &rec))
				rec["abilities"] = []string{"events:read", "location:precise"}
				raw, _ := json.Marshal(rec)
				p.Commits[i].Record, _ = repo.CanonicalRecord(raw)
			}
		}
		_, err := Verify(ctx, p, Anchors{})
		assert.ErrorIs(t, err, ErrInvalid, "the signature no longer matches")
	})

	t.Run("wrong org key", func(t *testing.T) {
		p := roundTrip(t, f.proof)
		other := newLog(t, org)
		_, err := Verify(ctx, p, Anchors{Keys: map[string]string{org: other.key}, Control: f.state})
		assert.ErrorIs(t, err, ErrInvalid)
	})

	t.Run("commit moved in the chain", func(t *testing.T) {
		p := roundTrip(t, f.proof)
		p.Commits[2].Seq = 7
		_, err := Verify(ctx, p, Anchors{})
		assert.ErrorIs(t, err, ErrInvalid, "seq is inside the signature")
	})

	t.Run("claim the records do not give", func(t *testing.T) {
		p := roundTrip(t, f.proof)
		p.Coverage.Historical["events:read"] = delegation.Span(tp(day(1)), nil)
		_, err := Verify(ctx, p, Anchors{})
		assert.ErrorIs(t, err, ErrMismatch)
	})

	t.Run("record that is not canonical", func(t *testing.T) {
		p := roundTrip(t, f.proof)
		// Re-sign a non-canonical body: the signature is fine, the form is not.
		c := &p.Commits[0]
		c.Record = json.RawMessage(`{ "controller": "` + f.opening.Controller + `", "era": 0, "salt": "` + f.opening.Salt + `" }`)
		require.NoError(t, repo.Sign(ctx, f.log.signer, &c.Commit))
		c.CID, _ = c.Commit.CID()
		_, err := Verify(ctx, p, Anchors{})
		assert.ErrorIs(t, err, ErrInvalid)
	})
}

func TestProofNeedsWhatTheEvaluationReads(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()

	t.Run("party attributes", func(t *testing.T) {
		p := roundTrip(t, f.proof)
		delete(p.Parties, org)
		_, err := Verify(ctx, p, Anchors{})
		assert.ErrorIs(t, err, ErrIncomplete)
	})

	t.Run("the author's role", func(t *testing.T) {
		p := roundTrip(t, f.proof)
		p.Commits = []repo.Committed{p.Commits[0], p.Commits[2]}
		_, err := Verify(ctx, p, Anchors{})
		require.Error(t, err)
		assert.NotErrorIs(t, err, ErrIncomplete, "a missing role is an author without authority, which the evaluator refuses")
	})

	t.Run("the opening", func(t *testing.T) {
		p := roundTrip(t, f.proof)
		p.Commits = p.Commits[1:]
		_, err := Verify(ctx, p, Anchors{})
		assert.ErrorIs(t, err, delegation.ErrNotCovered, "without the opening the org is not the controller of record")
	})

	t.Run("an org key", func(t *testing.T) {
		p := roundTrip(t, f.proof)
		p.Keys = nil
		_, err := Verify(ctx, p, Anchors{})
		assert.ErrorIs(t, err, ErrIncomplete)
	})

	t.Run("control state", func(t *testing.T) {
		p := roundTrip(t, f.proof)
		p.Control = nil
		_, err := Verify(ctx, p, Anchors{})
		assert.ErrorIs(t, err, ErrIncomplete)
		p.Control = &control.State{DID: "did:dimo:other"}
		_, err = Verify(ctx, p, Anchors{})
		assert.ErrorIs(t, err, ErrInvalid)
	})

	t.Run("no claim", func(t *testing.T) {
		p := roundTrip(t, f.proof)
		p.Coverage = nil
		_, err := Verify(ctx, p, Anchors{})
		assert.ErrorIs(t, err, ErrInvalid)
		cov, err := Evaluate(ctx, p, Anchors{})
		require.NoError(t, err, "Evaluate answers without a claim to compare")
		assert.Equal(t, []string{f.grant}, cov.Chain)
	})
}

// The directory is the anchor that matters: a proof verifies against the era
// log it holds, so a transfer since the proof was issued, or a commitment the
// opening does not open, ends it.
func TestProofAgainstTheDirectory(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	p := roundTrip(t, f.proof)

	salt, err := control.NewSalt()
	require.NoError(t, err)
	other, err := control.Commit(control.Opening{Controller: org, Era: 0, Salt: salt})
	require.NoError(t, err)
	rotated := &control.State{DID: car, Eras: []control.Era{{Number: 0, Commitment: other}}}
	_, err = Verify(ctx, p, Anchors{Control: rotated})
	assert.ErrorIs(t, err, delegation.ErrNotCovered, "an opening that does not open the directory's commitment proves nothing")

	// A tombstone the host later wrote, added to the bundle, revokes the grant
	// as of its commit time: the proof is the evaluation at At.
	f.log.commit(repo.OpTombstone, delegation.CollectionDelegation, "insurer", nil, "", day(12))
	p.Commits = f.log.all
	_, err = Verify(ctx, p, Anchors{})
	assert.ErrorIs(t, err, delegation.ErrRevoked)
	p.At = day(11)
	_, err = Evaluate(ctx, p, Anchors{})
	require.NoError(t, err, "before the tombstone the grant was in force")
}

func TestPartyRoundTrip(t *testing.T) {
	for _, p := range []delegation.Party{{}, {Kind: delegation.KindPerson}, {Kind: delegation.KindOrg, Operator: true}, {Kind: delegation.KindPerson, Operator: true}} {
		assert.Equal(t, p, PartyOf(p).Delegation())
	}
}
