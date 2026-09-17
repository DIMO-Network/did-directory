package delegation

import (
	"encoding/json"
	"slices"
	"time"
)

var (
	// negInf and posInf stand in for unbounded interval ends.
	negInf = time.Time{}
	posInf = time.Date(9999, 12, 31, 23, 59, 59, 0, time.UTC)
)

// Interval is a half-open time range [Start, End). Unbounded ends are encoded as
// null in JSON.
type Interval struct {
	Start time.Time
	End   time.Time
}

// MarshalJSON encodes the interval as [start|null, end|null].
func (i Interval) MarshalJSON() ([]byte, error) {
	var start, end *time.Time
	if !i.Start.Equal(negInf) {
		start = &i.Start
	}
	if !i.End.Equal(posInf) {
		end = &i.End
	}
	return json.Marshal([2]*time.Time{start, end})
}

// UnmarshalJSON decodes [start|null, end|null].
func (i *Interval) UnmarshalJSON(b []byte) error {
	var pair [2]*time.Time
	if err := json.Unmarshal(b, &pair); err != nil {
		return err
	}
	*i = span(pair[0], pair[1])
	return nil
}

// Set is a sorted list of non-overlapping, non-empty intervals.
type Set []Interval

// All returns the unbounded set.
func All() Set { return Set{{Start: negInf, End: posInf}} }

// Span returns the set [start, end) where nil means unbounded.
func Span(start, end *time.Time) Set { return normalize([]Interval{span(start, end)}) }

func span(start, end *time.Time) Interval {
	i := Interval{Start: negInf, End: posInf}
	if start != nil {
		i.Start = start.UTC()
	}
	if end != nil {
		i.End = end.UTC()
	}
	return i
}

// IsEmpty reports whether the set covers no time.
func (s Set) IsEmpty() bool { return len(s) == 0 }

// Contains reports whether t falls inside the set.
func (s Set) Contains(t time.Time) bool {
	for _, i := range s {
		if !t.Before(i.Start) && t.Before(i.End) {
			return true
		}
	}
	return false
}

// Union returns s ∪ o.
func (s Set) Union(o Set) Set {
	return normalize(append(slices.Clone(s), o...))
}

// Intersect returns s ∩ o.
func (s Set) Intersect(o Set) Set {
	var out []Interval
	for _, a := range s {
		for _, b := range o {
			start, end := a.Start, a.End
			if b.Start.After(start) {
				start = b.Start
			}
			if b.End.Before(end) {
				end = b.End
			}
			if start.Before(end) {
				out = append(out, Interval{Start: start, End: end})
			}
		}
	}
	return normalize(out)
}

// Covers reports whether s ⊇ o.
func (s Set) Covers(o Set) bool {
	return slices.Equal(s.Intersect(o), normalize(o))
}

func normalize(in []Interval) Set {
	ivs := make([]Interval, 0, len(in))
	for _, i := range in {
		if i.Start.Before(i.End) {
			ivs = append(ivs, i)
		}
	}
	slices.SortFunc(ivs, func(a, b Interval) int { return a.Start.Compare(b.Start) })

	var out Set
	for _, i := range ivs {
		if n := len(out); n > 0 && !i.Start.After(out[n-1].End) {
			if i.End.After(out[n-1].End) {
				out[n-1].End = i.End
			}
			continue
		}
		out = append(out, i)
	}
	return out
}
