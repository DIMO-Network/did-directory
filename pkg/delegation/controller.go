package delegation

import (
	"context"
	"errors"
	"slices"
	"time"
)

// ControlURI is the record a controller's opening for vehicle lives at in
// org's repository. It stands at the head of a controller's chain, since the
// opening is what proves the root (§10).
func ControlURI(org, vehicle string) string {
	return "at://" + org + "/" + CollectionVehicleControl + "/" + vehicle
}

// AuthorizeController checks that caller may use vehicle as its controller,
// with no delegation to name: "a root is implicit for the controller" (§7).
// The parties caller may act for are itself and the orgs in acting; in an org
// it acts through a live role covering the vehicle with every ability asked
// for, as a member exercising a grant to the org does (useRole). The first of
// them that controlled the vehicle answers.
//
// The controller reads every era it held, its opening proving each one, as a
// root with afterTransfer retainHistory would: a seller keeps the history of
// the years it owned the car and nothing after the sale. Live abilities are
// usable only in the current era, and a custody hold suspends them as it
// suspends any grant the holder's chain does not derive from (§12.2). Admin
// abilities are not data and are never in a coverage.
func (e *Evaluator) AuthorizeController(ctx context.Context, caller string, acting []string, vehicle string, abilities []string, at time.Time) (*Coverage, error) {
	parties := append([]string{caller}, acting...)
	for i, org := range parties {
		if i > 0 && (org == caller || slices.Contains(parties[:i], org)) {
			continue
		}
		if org != caller {
			ok, err := e.useRole(ctx, org, caller, vehicle, abilities, at)
			if err != nil {
				return nil, err
			}
			if !ok {
				continue
			}
		}
		cov, err := e.controllerCoverage(ctx, org, vehicle, abilities, at)
		if errors.Is(err, ErrNotCovered) {
			continue
		}
		return cov, err
	}
	return nil, ErrNotCovered
}

// controllerCoverage is what org holds over vehicle as its controller, limited
// to abilities: ErrNotCovered when org never controlled it, an
// ExclusiveHoldError when everything asked for is held by someone driving it.
func (e *Evaluator) controllerCoverage(ctx context.Context, org, vehicle string, abilities []string, at time.Time) (*Coverage, error) {
	var asked []string
	for _, a := range abilities {
		if ClassOf(a) != Admin && !slices.Contains(asked, a) {
			asked = append(asked, a)
		}
	}
	// The implicit root, as the record it would be if it were written down. It
	// was committed now: a controller inside one of its own revocation windows
	// (§8) cannot act as one until the window closes.
	root := &Stored{
		URI: ControlURI(org, vehicle),
		Record: Record{
			Type: TypeDelegation, From: org, To: org, Covers: Covers{Vehicle: vehicle},
			Abilities: asked, AfterTransfer: RetainHistory,
		},
		CommittedAt: at,
	}
	hist, live, err := e.root(ctx, root, vehicle, at)
	if err != nil {
		return nil, err
	}
	cov := &Coverage{Vehicle: vehicle, Historical: map[string]Set{}, Chain: []string{root.URI}}
	for _, a := range asked {
		switch {
		case ClassOf(a) == Historical:
			if !hist[a].IsEmpty() {
				cov.Historical[a] = hist[a]
			}
		case live[a]:
			cov.Live = append(cov.Live, a)
		}
	}
	if cov.Empty() {
		return nil, ErrNotCovered
	}
	if len(cov.Live) == 0 {
		return cov, nil
	}
	if err := e.applyExclusives(ctx, root, vehicle, at, cov); err != nil {
		return nil, err
	}
	if cov.Empty() {
		return nil, &ExclusiveHoldError{Suspended: cov.Suspended}
	}
	return cov, nil
}
