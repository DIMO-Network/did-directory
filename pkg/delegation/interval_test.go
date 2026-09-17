package delegation

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func day(d int) time.Time { return time.Date(2026, 1, d, 0, 0, 0, 0, time.UTC) }

func tp(t time.Time) *time.Time { return &t }

func TestSet_UnionMergesOverlapsAndAdjacency(t *testing.T) {
	s := Span(tp(day(1)), tp(day(5))).Union(Span(tp(day(5)), tp(day(8)))).Union(Span(tp(day(20)), tp(day(22))))
	require.Len(t, s, 2)
	assert.Equal(t, day(1), s[0].Start)
	assert.Equal(t, day(8), s[0].End)
}

func TestSet_Intersect(t *testing.T) {
	a := Span(tp(day(1)), tp(day(10))).Union(Span(tp(day(15)), nil))
	b := Span(tp(day(5)), tp(day(20)))
	got := a.Intersect(b)
	require.Len(t, got, 2)
	assert.Equal(t, Interval{Start: day(5), End: day(10)}, got[0])
	assert.Equal(t, Interval{Start: day(15), End: day(20)}, got[1])
	assert.True(t, Span(tp(day(1)), tp(day(2))).Intersect(Span(tp(day(3)), nil)).IsEmpty())
}

func TestSet_ContainsHalfOpen(t *testing.T) {
	s := Span(tp(day(1)), tp(day(2)))
	assert.True(t, s.Contains(day(1)))
	assert.False(t, s.Contains(day(2)))
	assert.True(t, All().Contains(day(1)))
}

func TestSet_Covers(t *testing.T) {
	outer := Span(tp(day(1)), nil)
	assert.True(t, outer.Covers(Span(tp(day(2)), tp(day(3)))))
	assert.False(t, outer.Covers(All()))
	assert.True(t, All().Covers(outer))
	assert.True(t, outer.Covers(nil))
}

func TestInterval_JSON(t *testing.T) {
	data, err := json.Marshal(Span(tp(day(1)), nil))
	require.NoError(t, err)
	assert.JSONEq(t, `[["2026-01-01T00:00:00Z", null]]`, string(data))

	var s Set
	require.NoError(t, json.Unmarshal(data, &s))
	assert.Equal(t, Span(tp(day(1)), nil), s)
}
