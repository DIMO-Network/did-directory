package delegation

import (
	"errors"
	"fmt"
	"time"
)

// Repository collections an org host stores (plan §3.1). Delegations and roles
// are Record; TypeDelegation and TypeRole double as their collection names.
const (
	CollectionDelegation     = TypeDelegation
	CollectionRole           = TypeRole
	CollectionTagMembership  = "network.dimo.org.tagMembership"
	CollectionVehicleControl = "network.dimo.org.vehicleControl"
	CollectionCustody        = "network.dimo.org.custody"
)

// Tag is a network.dimo.org.tag record. Its record key is the tag slug.
type Tag struct {
	Name        string `json:"name"`
	Description string `json:"description,omitempty"`
}

// Validate checks a tag's structure.
func (t *Tag) Validate() error {
	if t.Name == "" {
		return errors.New("name must not be empty")
	}
	return nil
}

// MembershipRecord is a network.dimo.org.tagMembership record: one interval of
// a vehicle in a tag. The author and commit time live on the commit, not here,
// which is why the evaluator's Membership carries them separately: CreatedBy
// inside the signed bytes would let a member choose whose authority the
// interval counts under (§9.2).
type MembershipRecord struct {
	Tag      string     `json:"tag"`
	Vehicle  string     `json:"vehicle"`
	JoinedAt time.Time  `json:"joinedAt"`
	LeftAt   *time.Time `json:"leftAt,omitempty"`
}

// Validate checks the interval's structure. org is the repository the record is
// written to; the tag must belong to it, since a membership in another org's
// tag is that org's to write.
func (m *MembershipRecord) Validate(org string) error {
	authority, err := TagAuthority(m.Tag)
	if err != nil {
		return err
	}
	if authority != org {
		return fmt.Errorf("tag %s belongs to %s, not to this repository", m.Tag, authority)
	}
	if !isDID(m.Vehicle) {
		return errors.New("vehicle must be a DID")
	}
	if m.JoinedAt.IsZero() {
		return errors.New("joinedAt is required")
	}
	if m.LeftAt != nil && !m.LeftAt.After(m.JoinedAt) {
		return errors.New("leftAt must be after joinedAt")
	}
	return nil
}

// Validate checks a custody period's structure.
func (p *CustodyPeriod) Validate() error {
	if !isDID(p.Vehicle) {
		return errors.New("vehicle must be a DID")
	}
	if !isDID(p.Holder) {
		return errors.New("holder must be a DID")
	}
	if p.From.IsZero() {
		return errors.New("from is required")
	}
	if p.Until != nil && !p.Until.After(p.From) {
		return errors.New("until must be after from")
	}
	return nil
}
