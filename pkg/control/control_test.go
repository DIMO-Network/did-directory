package control

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func testOpening(t *testing.T) Opening {
	t.Helper()
	salt, err := NewSalt()
	require.NoError(t, err)
	return Opening{Controller: "did:dimo:avis", Era: 0, Salt: salt}
}

func TestCommitVerify(t *testing.T) {
	o := testOpening(t)
	c, err := Commit(o)
	require.NoError(t, err)
	require.NoError(t, ValidateFormat(c))
	assert.NoError(t, Verify(c, o))
}

func TestCommit_Deterministic(t *testing.T) {
	o := testOpening(t)
	a, err := Commit(o)
	require.NoError(t, err)
	b, err := Commit(o)
	require.NoError(t, err)
	assert.Equal(t, a, b)
}

func TestVerify_RejectsWrongFields(t *testing.T) {
	o := testOpening(t)
	c, err := Commit(o)
	require.NoError(t, err)

	wrongController := o
	wrongController.Controller = "did:dimo:hertz"
	assert.Error(t, Verify(c, wrongController))

	wrongEra := o
	wrongEra.Era = 1
	assert.Error(t, Verify(c, wrongEra))

	otherSalt, err := NewSalt()
	require.NoError(t, err)
	wrongSalt := o
	wrongSalt.Salt = otherSalt
	assert.Error(t, Verify(c, wrongSalt))
}

func TestCommit_LengthPrefixPreventsAmbiguity(t *testing.T) {
	salt, err := NewSalt()
	require.NoError(t, err)
	a, err := Commit(Opening{Controller: "did:dimo:a", Era: 0, Salt: salt})
	require.NoError(t, err)
	b, err := Commit(Opening{Controller: "did:dimo:a\x00", Era: 0, Salt: salt})
	require.NoError(t, err)
	assert.NotEqual(t, a, b)
}

func TestCommit_RejectsBadSalt(t *testing.T) {
	_, err := Commit(Opening{Controller: "a", Salt: "c2hvcnQ"})
	assert.ErrorContains(t, err, "salt must be")
}

func TestValidateFormat(t *testing.T) {
	assert.Error(t, ValidateFormat("did:dimo:avis"))
	assert.Error(t, ValidateFormat("sha256:not-base64!!"))
	assert.Error(t, ValidateFormat("sha256:AAAA"))
}

func TestState_EraAt(t *testing.T) {
	t1 := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	t2 := time.Date(2026, 6, 1, 0, 0, 0, 0, time.UTC)
	s := &State{Eras: []Era{
		{Number: 0, End: &t1},
		{Number: 1, Start: &t1, End: &t2},
		{Number: 2, Start: &t2},
	}}

	assert.Equal(t, uint64(0), s.EraAt(t1.Add(-time.Hour)).Number)
	assert.Equal(t, uint64(1), s.EraAt(t1).Number)
	assert.Equal(t, uint64(2), s.EraAt(t2.Add(time.Hour)).Number)
	assert.Equal(t, uint64(2), s.Current().Number)
	assert.Nil(t, (&State{}).Current())
}

func TestEra_Revoked(t *testing.T) {
	from := time.Date(2026, 9, 1, 0, 0, 0, 0, time.UTC)
	to := from.Add(48 * time.Hour)
	e := &Era{Revocations: []Revocation{{From: from, To: to}}}

	assert.False(t, e.Revoked(from.Add(-time.Second)))
	assert.True(t, e.Revoked(from))
	assert.True(t, e.Revoked(to), "a grant racing the revocation fails closed")
	assert.False(t, e.Revoked(to.Add(time.Second)), "grants after the revocation was issued are valid again")
}
