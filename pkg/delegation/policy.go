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
//
// A Policy a caller builds by hand is the policy in force. Only the wholly zero
// Policy means "no profile was chosen"; anything with a field set is taken at
// face value, field by field, so a caller who narrows one rule does not silently
// widen the rest. Because Go cannot tell an unset bool from a false one, a
// profile that means to keep the default rules starts from DefaultPolicy and
// adjusts, rather than writing a fresh literal.
type Policy struct {
	// Name identifies the profile, e.g. "default" or "eu-consumer". It is a label
	// for logs and disputes; it does not select any behaviour.
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
	if p == (Policy{}) {
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
	// CommittedBy is the principal the host authenticated for this write, which
	// is what Stored.CommittedBy will record. Empty means the issuing principal
	// wrote it itself. It is not read from the record: Record.CreatedBy is the
	// record's own claim about its author, and a record must not be able to
	// choose the authority it is checked against.
	CommittedBy string
	// Approved reports whether the write carries a second approval.
	Approved bool
	// Policy in force; zero means DefaultPolicy.
	Policy Policy
}

// author returns who this write is attributed to: the principal the host
// authenticated, or the record's own claim, or the issuer itself.
//
// The claim is consulted only after the witness, and only because at commit time
// a claim can add an approval requirement but never lift one — the witness wins
// wherever the two disagree, and CheckCommit refuses a record whose claim
// contradicts it outright.
func (cc CommitContext) author(rec *Record) string {
	switch {
	case cc.CommittedBy != "":
		return cc.CommittedBy
	case rec.CreatedBy != "":
		return rec.CreatedBy
	default:
		return rec.From
	}
}

// ApprovalReasons lists why committing rec would need a second approval.
func ApprovalReasons(rec *Record, cc CommitContext) []string {
	policy := cc.Policy.orDefault()

	var reasons []string
	if cc.CoveredVehicles > policy.VehicleApprovalThreshold {
		reasons = append(reasons, fmt.Sprintf("covers %d vehicles (threshold %d)", cc.CoveredVehicles, policy.VehicleApprovalThreshold))
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
	if cc.author(rec) == rec.To {
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
	// createdBy is an audit copy of something the host already knows. Committing
	// one that names somebody else would leave a record whose own account of who
	// wrote it is false, and evaluation refuses those, so refuse it here where
	// the writer can still fix it.
	if cc.CommittedBy != "" && rec.CreatedBy != "" && rec.CreatedBy != cc.CommittedBy {
		return fmt.Errorf("createdBy says %s but %s is writing this record", rec.CreatedBy, cc.CommittedBy)
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
	cc.Policy = policy
	if reasons := ApprovalReasons(rec, cc); len(reasons) > 0 && !cc.Approved {
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
