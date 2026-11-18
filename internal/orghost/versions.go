package orghost

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/DIMO-Network/did-directory/internal/orghost/store"
	"github.com/DIMO-Network/did-directory/pkg/control"
	"github.com/DIMO-Network/did-directory/pkg/delegation"
	"github.com/DIMO-Network/did-directory/pkg/odrl"
	"github.com/DIMO-Network/did-directory/pkg/repo"
)

// The resolver answers the evaluator's historical questions from a record's
// versions, not its current state: the role a grant's author held when the
// grant was committed, the membership interval the last author entitled to
// state it stated, and the opening of an era the record has since moved on
// from. Each reader here returns the commits it used, so a coverage proof
// carries them too.

// keyVersions reads one record key's history as versions.
func keyVersions(ctx context.Context, st store.Store, org, collection, rkey string) ([]repo.Version, []repo.Committed, error) {
	commits, err := st.KeyCommits(ctx, org, collection, rkey)
	if err != nil {
		return nil, nil, err
	}
	return repo.Versions(commits), commits, nil
}

// storedVersion is one version of a delegation or role as the evaluator reads
// it. A tombstone the org wrote itself has no author on the commit and is
// handed over as the org, since revokedAt compares it to from.
func storedVersion(org string, v *repo.Version) (*delegation.Stored, error) {
	rec, err := odrl.Decode(v.Record)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", v.URI(), err)
	}
	out := &delegation.Stored{
		URI: v.URI(), Record: *rec, CommittedAt: v.CommittedAt, CommittedBy: v.CommittedBy,
		ApprovedBy: v.ApprovedBy, Superseded: v.Superseded,
	}
	if t := v.Tombstone; t != nil {
		by := t.CommittedBy
		if by == "" {
			by = org
		}
		out.Tombstone = &delegation.Tombstone{At: t.CommittedAt, By: by}
	}
	return out, nil
}

// roleVersions is every version of every role org issued to member.
func roleVersions(ctx context.Context, st store.Store, org, member string) ([]delegation.Stored, []repo.Committed, error) {
	heads, err := st.Roles(ctx, org, member)
	if err != nil {
		return nil, nil, err
	}
	var out []delegation.Stored
	var used []repo.Committed
	for i := range heads {
		versions, commits, err := keyVersions(ctx, st, org, heads[i].Collection, heads[i].RKey)
		if err != nil {
			return nil, nil, err
		}
		used = append(used, commits...)
		for j := range versions {
			s, err := storedVersion(org, &versions[j])
			if err != nil {
				return nil, nil, err
			}
			// A version written to somebody else before the record was
			// readdressed is not a role this member held.
			if s.Record.To == member {
				out = append(out, *s)
			}
		}
	}
	return out, used, nil
}

// membershipVersions is every version of every live membership record of
// vehicle in tag since the record was last created, with CreatedBy the
// commit's witnessed author (plan §7).
func membershipVersions(ctx context.Context, st store.Store, org, tag, vehicle string) ([]delegation.Membership, []repo.Committed, error) {
	heads, err := st.Memberships(ctx, org, tag, vehicle)
	if err != nil {
		return nil, nil, err
	}
	var out []delegation.Membership
	var used []repo.Committed
	for i := range heads {
		versions, commits, err := keyVersions(ctx, st, org, heads[i].Collection, heads[i].RKey)
		if err != nil {
			return nil, nil, err
		}
		used = append(used, commits...)
		versions = repo.SinceCreated(versions)
		for j := range versions {
			v := &versions[j]
			var m delegation.MembershipRecord
			if err := json.Unmarshal(v.Record, &m); err != nil {
				return nil, nil, fmt.Errorf("%s: %w", v.URI(), err)
			}
			if m.Tag != tag || m.Vehicle != vehicle {
				continue
			}
			out = append(out, delegation.Membership{
				URI: v.URI(), Tag: m.Tag, Vehicle: m.Vehicle, JoinedAt: m.JoinedAt, LeftAt: m.LeftAt,
				CreatedBy: v.CommittedBy, CommittedAt: v.CommittedAt,
			})
		}
	}
	return out, used, nil
}

// openingVersion finds controller's opening of vehicle for era in any version
// of its vehicleControl record, newest first. The evaluator checks it against
// the era's commitment, so a version the record has moved on from proves its
// era as well as it ever did.
func openingVersion(ctx context.Context, st store.Store, vehicle string, era uint64, controller string) (*control.Opening, []repo.Committed, error) {
	versions, commits, err := keyVersions(ctx, st, controller, delegation.CollectionVehicleControl, vehicle)
	if err != nil {
		return nil, nil, err
	}
	for i := len(versions) - 1; i >= 0; i-- {
		var o control.Opening
		if err := json.Unmarshal(versions[i].Record, &o); err != nil {
			return nil, nil, fmt.Errorf("%s: %w", versions[i].URI(), err)
		}
		if o.Era == era && o.Controller == controller {
			return &o, commits, nil
		}
	}
	return nil, commits, nil
}
