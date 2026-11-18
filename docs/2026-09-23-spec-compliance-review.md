# Spec compliance review — September 23, 2026

## Scope and assessment

Reviewed the checked-out `org-host-step-7` branches in `did-directory`, sibling `../dauth`, and sibling `../dq`, including existing uncommitted work. This is a review of those working trees, not just their committed branch tips.

Branch tips at review time: `did-directory` at `003f253`, `dauth` at `703cdfb`, and `dq` at `7936990`.

The architecture is coherent and substantially implements the narrowed [September 22 org host plan](superpowers/plans/2026-09-22-org-host-plan.md). It does not yet satisfy all the security and history guarantees in the [delegation design spec](superpowers/specs/2026-09-16-dimo-orgs-fleets-delegation-design.md). Five material issues were identified, including two authorization bypasses.

The central design concern is that the append-only commit log is queried through current-record views where authorization requires historical versions. Role authority and control openings are two concrete consequences.

## Findings

### 1. [P1] Renters can fabricate custody through their own repository

**Code:** [`internal/orghost/access.go`](../internal/orghost/access.go), `checkWrite` and `requireRole`; [`internal/orghost/store/postgres.go`](../internal/orghost/store/postgres.go), `Custody`; the memory store has the same host-wide lookup.

Custody writes accept the repository owner without checking its authority over the vehicle. Custody lookup then combines records from every repository on the host.

**Reproduced through the host HTTP test harness:**

1. Avis issues a custody-narrowed historical grant to a renter; no custody record exists.
2. Authorization returns 403.
3. The renter registers its own repository and writes a custody record naming itself as holder of Avis's vehicle.
4. Authorization of the Avis grant returns 200, with the fabricated custody interval contributing coverage.

This defeats the custody-only restriction in spec §12.3. Plan §7 acknowledges host-wide custody, but its assumption that write checks sufficiently constrain it does not hold. The bypass widens coverage within the grant's other bounds; it does not create a grant where none exists.

**Recommended fix:** Require vehicle authority for custody writes and bind accepted custody evidence to the relevant controller/delegation. Apply the same provenance rules during evaluation and proof verification.

### 2. [P1] PUT bypasses lender-only revocation

**Code:** [`internal/orghost/server.go`](../internal/orghost/server.go), `write`; [`internal/orghost/repository.go`](../internal/orghost/repository.go), `Put`; [`internal/orghost/access.go`](../internal/orghost/access.go), `checkRecordWrite` and `checkTombstone`.

Updates validate the replacement record without enforcing the existing record's protections.

**Reproduced through the host HTTP test harness:**

1. Create and approve a grant with `revocableBy: "to"`.
2. The issuer attempts DELETE: 403.
3. The issuer PUTs the same record with `revocableBy: "from"`: 200.
4. The issuer attempts DELETE again: 200.

This contradicts the lender-protected lien requirement in spec §§1 and 7. Restricting DELETE is insufficient when replacement can remove the restriction.

**Recommended fix:** Authorize transitions against the existing record, including recipient-controlled restrictions, within the commit operation. Cover both direct and approved writes, and ensure concurrent updates cannot invalidate the transition check.

### 3. [P1] dq latest, snapshot and summary reads can expose data outside authorized windows

**Code in sibling dq:** [`internal/auth/directives.go`](../../dq/internal/auth/directives.go), `Checker.check`; [`internal/graph/privilege_filter.go`](../../dq/internal/graph/privilege_filter.go), `abilitiesFromCtx`; [`internal/graph/base.resolvers.go`](../../dq/internal/graph/base.resolvers.go), `DataSummary` and `SignalsSnapshot`; [`internal/repositories/signals.go`](../../dq/internal/repositories/signals.go).

For queries without a range, dq checks whether an ability's window contains now rather than checking returned data timestamps. Latest reads do not pass the authorized windows into the query. Snapshot filtering checks abilities but not each signal's timestamp. Summary reads fetch historical counts and timestamps, then filter by ability rather than time.

**Concrete failure scenario:** A buyer whose coverage starts today can receive yesterday's last-known location if no newer reading exists. A summary can similarly reveal counts and timestamps from before the buyer's ownership or renter's pickup.

This violates the historical-data rule in spec §§5.1, 8 and 11.4. The plan documents the current-time check, but that behavior weakens the underlying data-window requirement.

**Evidence:** Code inspection. This finding was not reproduced against a running DuckLake instance during this review.

**Recommended fix:** Enforce per-ability windows on returned readings and on the underlying data used to compute summaries. Include stale latest values and ownership/pickup boundaries in integration tests.

### 4. [P1] Updating a role invalidates grants previously authored under it

**Code:** [`internal/orghost/store/memory.go`](../internal/orghost/store/memory.go), `Roles`; [`internal/orghost/store/postgres.go`](../internal/orghost/store/postgres.go), `Roles`; [`pkg/delegation/evaluate.go`](../pkg/delegation/evaluate.go), `roleActive`.

Historical author checks receive only the current role version. `roleActive` rejects a role whose current commit timestamp is later than the time at which the author needed authority.

**Reproduced through the host HTTP test harness:**

1. Create a role allowing a member to issue a telemetry grant.
2. The member issues the grant; authorization succeeds.
3. Later, PUT an unchanged copy of the role to the same URI.
4. The existing grant now returns 403: `author ... lacked authority when committed`.

This breaks the durable organizational authority intended by spec §6.3. Even a no-op role rewrite should not retroactively remove the authority under which a valid organizational grant was issued.

**Recommended fix:** Resolve the role version effective at the grant's commit time. Preserve subsequent revocation semantics separately from the historical author-authority check.

### 5. [P1] A new control opening loses earlier-era coverage for the same controller

**Code:** [`internal/orghost/resolver.go`](../internal/orghost/resolver.go), `Opening` and `openingOf`; [`internal/orghost/proof.go`](../internal/orghost/proof.go), `recorder.Opening`.

Openings are stored under the vehicle DID, and the resolver reads only the current record. Publishing an era-1 opening for the same controller replaces the accessible era-0 opening, although the old commit remains in the log.

**Reproduced through the host HTTP test harness:** Model a same-controller era transition, publish the new opening, and authorize an existing historical grant. Coverage starts at era 1; the earlier era disappears from its retained coverage.

This affects `revokeSince` and a vehicle returning to a previous controller, contrary to spec §8's history-retention guarantees. The reproduction modeled the directory era state directly; it did not execute a real `revokeSince` CLI operation.

**Recommended fix:** Retrieve openings by controller, vehicle and era, including in coverage proofs, rather than relying on the current vehicleControl record alone.

## Spec alignment and intentional scope reductions

| Area | Assessment |
| --- | --- |
| Signed commits, witnessed authorship, approvals, delegation evaluation, booking compiler | Substantially implemented, with a useful separation of responsibilities. The findings above qualify their correctness at authorization and history boundaries. |
| dauth exchange | Matches the narrowed plan: explicit grant/capacity, host authorization, per-ability window grouping and DPoP-bound access tokens. This is not a claim that every security property was exhaustively tested. |
| Fleet tokens, coverage index, self-hosting, Turnkey and countersignatures | Explicitly deferred by the implementation plan; not counted as implementation bugs in this review. |
| ODRL wire format | Spec §5 and decision 12 require ODRL, but the host accepts/stores `delegation.Record` JSON and the booking SDK sends that form. `pkg/odrl` exists but is not integrated into this boundary. Either integrate the codec or explicitly revise the wire-format decision. |
| Multiple disjoint windows | dq refuses queries spanning gaps rather than returning merged segments. This is a documented v1 deviation that fails closed. |
| Coverage proofs | Useful evaluation transcripts, with documented limits around omitted records and asserted metadata. They should not be described as independently proving complete repository state. |

## Validation and limits

The following existing test commands passed:

```sh
# did-directory
go test ./...

# ../dauth
go test ./internal/exchange ./internal/signin/... ./pkg/...

# ../dq
go test ./internal/auth ./internal/graph ./internal/fetch/rpc
```

Existing package results were largely served from the Go test cache. Four additional temporary tests ran uncached against the in-memory host HTTP harness and confirmed findings 1, 2, 4 and 5. They asserted the observed defective behavior and passed; they were removed after the review. They were named `TestReviewForeignCustody`, `TestReviewLienOverwrite`, `TestReviewRoleUpdateErasesAuthority` and `TestReviewOldEraOpeningLost`.

The full demo and a separate Postgres-backed test run were not executed. The dq timestamp finding is based on code inspection, not a live data-store reproduction. No implementation fixes were made, and pre-existing working-tree changes were preserved.
