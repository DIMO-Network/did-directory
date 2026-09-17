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

// Policy holds the rules in force for a write or an evaluation.
//
// These are not universal truths. Whether a consumer may sign away their right
// to revoke a lender's access, how many vehicles one signature may cover, and
// what an operator may see during a rental all vary by jurisdiction. The engine
// enforces; the policy decides. Callers select a policy from the agreement's
// governing law and pass the same one to CheckCommit and to the Evaluator.
type Policy struct {
	// Name identifies the profile, e.g. "default" or "eu-consumer". A zero Name
	// means the default profile.
	Name string
	// VehicleApprovalThreshold is the vehicle count above which a write needs a
	// second approval.
	VehicleApprovalThreshold int
	// ApprovalForLiveAbilities requires a second approval for abilities that
	// actuate the vehicle. Data writes are live too, but a device pairing is not
	// the thing a pair of admins is protecting against.
	ApprovalForLiveAbilities bool
	// AllowIrrevocableFromNonOperator lets a party without attested operator
	// status issue a grant only its recipient can revoke. Off by default:
	// consumers keep the right to revoke.
	AllowIrrevocableFromNonOperator bool
	// MaxChainDepth bounds delegation chain length, root included.
	MaxChainDepth int
}

// DefaultPolicy returns the profile used when none is supplied.
func DefaultPolicy() Policy {
	return Policy{
		Name:                     "default",
		VehicleApprovalThreshold: DefaultApprovalThreshold,
		ApprovalForLiveAbilities: true,
		MaxChainDepth:            MaxChainDepth,
	}
}

func (p Policy) orDefault() Policy {
	if p.Name == "" {
		return DefaultPolicy()
	}
	if p.MaxChainDepth <= 0 {
		p.MaxChainDepth = MaxChainDepth
	}
	if p.VehicleApprovalThreshold <= 0 {
		p.VehicleApprovalThreshold = DefaultApprovalThreshold
	}
	return p
}

// CommitContext describes a pending repository write.
type CommitContext struct {
	// From is the issuing principal's policy attributes.
	From Party
	// CoveredVehicles is the number of vehicles the record covers once committed.
	CoveredVehicles int
	// Role is the role record the author is writing under, when the author is not
	// the issuing principal itself. Its constraints bound the shape of the write.
	// Nil means the principal authored it directly, or holds no role that limits
	// what it may issue.
	Role *Record
	// Approved reports whether the write carries a second approval.
	Approved bool
	// Policy in force; zero means DefaultPolicy.
	Policy Policy
}

// ApprovalReasons lists why committing rec would need a second approval.
func ApprovalReasons(rec *Record, coveredVehicles int, policy Policy) []string {
	policy = policy.orDefault()

	var reasons []string
	if coveredVehicles > policy.VehicleApprovalThreshold {
		reasons = append(reasons, fmt.Sprintf("covers %d vehicles (threshold %d)", coveredVehicles, policy.VehicleApprovalThreshold))
	}
	if policy.ApprovalForLiveAbilities {
		for _, a := range rec.Abilities {
			if IsActuating(a) {
				reasons = append(reasons, "grants live ability "+a)
			}
		}
	}
	if rec.revocableBy() == RevocableByTo {
		reasons = append(reasons, "cannot be revoked by the issuer")
	}
	if rec.CreatedBy != "" && rec.CreatedBy == rec.To {
		reasons = append(reasons, "author is the recipient")
	}
	return reasons
}

// CheckCommit validates a delegation or role before an org host commits it.
// Evaluation re-checks everything; this gives writers an early, explicit error.
func CheckCommit(rec *Record, cc CommitContext) error {
	if err := rec.Validate(); err != nil {
		return err
	}
	policy := cc.Policy.orDefault()

	if rec.revocableBy() == RevocableByTo && !cc.From.Operator && !policy.AllowIrrevocableFromNonOperator {
		return ErrLienNotAllowed
	}
	if rec.Type == TypeRole && !cc.From.CanHaveMembers() {
		return errors.New("only a party that can have members may issue roles")
	}
	// A constrained role is the only bound on an unattended issuer such as a
	// booking service, so the shape of what it writes is checked here as well as
	// at evaluation: this is the error the writer sees, not the silent refusal
	// weeks later.
	if cc.Role != nil {
		if err := cc.Role.Constraints.check(rec, cc.CoveredVehicles); err != nil {
			return err
		}
	}
	if reasons := ApprovalReasons(rec, cc.CoveredVehicles, policy); len(reasons) > 0 && !cc.Approved {
		return fmt.Errorf("%w: %s", ErrApprovalRequired, strings.Join(reasons, "; "))
	}
	return nil
}

// CheckMembershipGrowth checks a tag membership write against the delegations
// that cover the tag: pushing any of them past the threshold needs approval, so a
// tag cannot quietly grow a small delegation into a fleet-wide one.
func CheckMembershipGrowth(covering []Record, newCount int, approved bool, policy Policy) error {
	if approved {
		return nil
	}
	policy = policy.orDefault()
	if newCount <= policy.VehicleApprovalThreshold {
		return nil
	}
	for i := range covering {
		if covering[i].Type == TypeDelegation {
			return fmt.Errorf("%w: tag would cover %d vehicles under an existing delegation (threshold %d)", ErrApprovalRequired, newCount, policy.VehicleApprovalThreshold)
		}
	}
	return nil
}
