package delegation

import (
	"errors"
	"fmt"
	"strings"
)

// DefaultApprovalThreshold is the vehicle count above which a delegation needs a
// policy approval (2-of-n org admins) before it can be committed.
const DefaultApprovalThreshold = 500

// ErrApprovalRequired is returned when a write needs a policy approval.
var ErrApprovalRequired = errors.New("policy approval required")

// CommitContext describes a pending repository write.
type CommitContext struct {
	// FromKind is the kind of the issuing principal.
	FromKind Kind
	// CoveredVehicles is the number of vehicles the record covers once committed.
	CoveredVehicles int
	// Approved reports whether the write carries a policy approval.
	Approved bool
	// Threshold overrides DefaultApprovalThreshold when positive.
	Threshold int
}

// ApprovalReasons lists why committing rec would need a policy approval.
func ApprovalReasons(rec *Record, coveredVehicles, threshold int) []string {
	if threshold <= 0 {
		threshold = DefaultApprovalThreshold
	}
	var reasons []string
	if coveredVehicles > threshold {
		reasons = append(reasons, fmt.Sprintf("covers %d vehicles (threshold %d)", coveredVehicles, threshold))
	}
	for _, a := range rec.Abilities {
		if ClassOf(a) == Live {
			reasons = append(reasons, "grants live ability "+a)
		}
	}
	if rec.revocableBy() == RevocableByTo {
		reasons = append(reasons, "cannot be revoked by the issuer")
	}
	return reasons
}

// CheckCommit validates a delegation or role before an org host commits it.
// Evaluation re-checks everything; this gives writers an early, explicit error.
func CheckCommit(rec *Record, cc CommitContext) error {
	if err := rec.Validate(); err != nil {
		return err
	}
	if rec.revocableBy() == RevocableByTo && cc.FromKind != KindOrg {
		return ErrLienNotAllowed
	}
	if rec.Type == TypeRole && cc.FromKind != KindOrg {
		return errors.New("only an org can issue roles")
	}
	if reasons := ApprovalReasons(rec, cc.CoveredVehicles, cc.Threshold); len(reasons) > 0 && !cc.Approved {
		return fmt.Errorf("%w: %s", ErrApprovalRequired, strings.Join(reasons, "; "))
	}
	return nil
}

// CheckMembershipGrowth checks a tag membership write against the delegations
// that cover the tag: pushing any of them past the threshold needs approval, so a
// tag cannot quietly grow a small delegation into a fleet-wide one.
func CheckMembershipGrowth(covering []Record, newCount int, approved bool, threshold int) error {
	if approved {
		return nil
	}
	if threshold <= 0 {
		threshold = DefaultApprovalThreshold
	}
	if newCount <= threshold {
		return nil
	}
	for i := range covering {
		if covering[i].Type == TypeDelegation {
			return fmt.Errorf("%w: tag would cover %d vehicles under an existing delegation (threshold %d)", ErrApprovalRequired, newCount, threshold)
		}
	}
	return nil
}
