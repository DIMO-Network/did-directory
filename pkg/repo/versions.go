package repo

import "time"

// Version is one create or update of a record key, and how long it stood.
//
// A record's history matters wherever authority is judged at a past moment:
// a grant's author held the role version in force when the grant was
// committed, not whatever the role says now, and a control opening for an
// earlier era stays a proof of that era after the record moves on.
type Version struct {
	Committed
	// Superseded is when the next create or update of the key replaced this
	// version; nil while it is current, or when a tombstone ended it.
	Superseded *time.Time
	// Tombstone is the tombstone commit that ended this version, if one did.
	Tombstone *Committed
}

// Versions splits one record key's commits, in seq order, into its versions.
// A tombstone ends the version before it; a create after a tombstone starts a
// new one without superseding the old, which the tombstone already ended.
func Versions(commits []Committed) []Version {
	var out []Version
	for i := range commits {
		c := commits[i]
		switch c.Op {
		case OpTombstone:
			if n := len(out); n > 0 && out[n-1].Tombstone == nil && out[n-1].Superseded == nil {
				out[n-1].Tombstone = &c
			}
		default:
			if n := len(out); n > 0 && out[n-1].Tombstone == nil && out[n-1].Superseded == nil {
				at := c.CommittedAt
				out[n-1].Superseded = &at
			}
			out = append(out, Version{Committed: c})
		}
	}
	return out
}

// SinceCreated is the versions after the key's last tombstone: the record as
// it has stood since it was last created. A version from before a tombstone is
// history the tombstone ended, whether or not an update superseded it first.
func SinceCreated(versions []Version) []Version {
	start := 0
	for i := range versions {
		if versions[i].Tombstone != nil {
			start = i + 1
		}
	}
	return versions[start:]
}
