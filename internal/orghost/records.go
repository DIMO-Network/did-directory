package orghost

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/DIMO-Network/did-directory/pkg/control"
	"github.com/DIMO-Network/did-directory/pkg/delegation"
)

// checkRecord is the structural check every write passes before anything is
// signed (plan §6 step 2): the collection is one the host stores, the record
// parses as that collection's type and validates, the key has the shape the
// collection needs, and the record does not claim an author the host did not
// witness. Role and policy checks come in step 4.
func checkRecord(org, collection, rkey string, record json.RawMessage, committedBy string) error {
	if err := delegation.ValidateRKey(rkey); err != nil {
		return err
	}
	strict := func(v any) error {
		dec := json.NewDecoder(bytes.NewReader(record))
		dec.DisallowUnknownFields()
		if err := dec.Decode(v); err != nil {
			return fmt.Errorf("record does not parse as %s: %w", collection, err)
		}
		return nil
	}

	switch collection {
	case delegation.CollectionDelegation, delegation.CollectionRole:
		var rec delegation.Record
		if err := strict(&rec); err != nil {
			return err
		}
		if rec.Type != collection {
			return fmt.Errorf("$type is %q, collection is %s", rec.Type, collection)
		}
		if rec.From != org {
			return fmt.Errorf("from is %s, but this is %s's repository", rec.From, org)
		}
		if err := rec.Validate(); err != nil {
			return err
		}
		return checkAuthor(rec.CreatedBy, org, committedBy)

	case delegation.CollectionTag:
		var tag delegation.Tag
		if err := strict(&tag); err != nil {
			return err
		}
		return tag.Validate()

	case delegation.CollectionTagMembership:
		var m delegation.MembershipRecord
		if err := strict(&m); err != nil {
			return err
		}
		return m.Validate(org)

	case delegation.CollectionVehicleControl:
		var o control.Opening
		if err := strict(&o); err != nil {
			return err
		}
		if o.Controller != org {
			return fmt.Errorf("opening names controller %s, but this is %s's repository", o.Controller, org)
		}
		if _, err := control.Commit(o); err != nil {
			return err
		}
		// The key is the vehicle DID, so the record is found by the vehicle it
		// opens control of.
		if !isDID(rkey) {
			return errors.New("vehicleControl record key must be the vehicle DID")
		}
		return nil

	case delegation.CollectionCustody:
		var p delegation.CustodyPeriod
		if err := strict(&p); err != nil {
			return err
		}
		return p.Validate()

	default:
		return fmt.Errorf("unknown collection %s", collection)
	}
}

// checkAuthor refuses a record whose createdBy the evaluator would refuse
// (delegation.Stored.CommittedBy): it may name the witnessed author, the org
// when the org itself wrote it, or nothing.
func checkAuthor(createdBy, org, committedBy string) error {
	switch {
	case createdBy == "":
		return nil
	case committedBy == "" && createdBy == org:
		return nil
	case createdBy == committedBy:
		return nil
	case committedBy == "":
		return fmt.Errorf("createdBy claims %s but the write is by the org itself", createdBy)
	default:
		return fmt.Errorf("createdBy claims %s but the write is by %s", createdBy, committedBy)
	}
}

func isDID(s string) bool {
	return len(s) > len("did:") && s[:len("did:")] == "did:"
}
