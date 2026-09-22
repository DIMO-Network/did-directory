# Org host plan

**Date:** 2026-09-22
**Status:** Draft for review. Replaces the lost `docs/org-store-plan.md`.
**Spec:** `../specs/2026-09-16-dimo-orgs-fleets-delegation-design.md` (§6, §7, §9, §11, §12 in particular; decisions in §16 and §19).

The org host is the service that holds every org's private records and is the only thing that writes them. Nothing in the delegation model runs end to end without it: `pkg/delegation` is a pure evaluator behind a `Resolver` interface, `pkg/agreement` is a pure compiler, and until 2026-09-22 the only runnable flow was the SACD path, which is now gone.

## 1. Decisions needed before building

These change the shape of the work. Everything below assumes the recommended answer, marked ▶.

| # | Question | Options | ▶ Recommendation |
|---|---|---|---|
| A | Who runs the evaluator? | (1) dauth embeds `delegation.Evaluator` and implements `Resolver` by calling the org host over HTTP. (2) The org host runs the evaluator against its own database and exposes `POST /authorize`; dauth calls that once and mints. | **(2).** An `Authorize` call touches records, roles, memberships, custody, openings and exclusives, often across two or three orgs. With DIMO hosting every org in one instance, that is one process and one database. dauth stays a thin issuer. Self-hosted orgs come later and would federate at the same `/authorize` boundary. |
| B | How does a member authenticate to the org host for writes? | (1) A dauth-issued identity token with `sub` = member DID. (2) The org host runs its own challenge/response DID sign-in. | **(1).** One sign-in for the whole platform, and the host never sees a key. Needs dauth to issue plain identity tokens, which it does today for DID login. |
| C | Who signs commits in v1? | (1) An org signing key generated and held by the host, encrypted at rest. (2) Turnkey from day one. | **(1)** for v1, behind a `Signer` interface so Turnkey is a swap. The org DID document gets the public half as `#dimo_org`. |
| D | What is a second approval in v1? | (1) A second authenticated member with the same authority approving a pending write. (2) Turnkey policy approval. | **(1).** It exercises `Stored.ApprovedBy` and `CommitContext.Approved` exactly as the evaluator expects. Turnkey replaces the mechanism, not the semantics. |
| E | Where do party attributes (operator status, consumer protection) come from? | (1) A DIMO-administered table in the host. (2) A verifiable credential. | **(1)** for v1. It is the one thing in the system that is DIMO's say-so, and a table is honest about that. |
| F | Who compiles agreements? | (1) The booking service compiles client-side with `pkg/agreement` and posts grants. (2) The booking service posts the agreement and the host compiles. | **(2).** The compiler is the thing that turns "the duty is paid" into "the door opens", so it belongs in the trusted process. The catalog is a record per org. The booking service only ever sends state changes. |
| G | Does the org host live in this repo? | Confirmed as a separate binary with its own database. Repo placement is convenience. | Keep `cmd/org-host` here until dauth is the second consumer of `pkg/delegation`, then decide. |

## 2. Scope of v1

**In:** one host instance serving every org; records, tags, memberships, roles, custody periods, agreements and catalogs as signed hash-chained commits; write-time checks; two-person approval; `/authorize` for dauth; coverage proofs; descendants listing for consent; tombstones and `revokeAuthoredBy`; membership growth checks.

**Out, deferred on 2026-09-21:** the `ORG_COVERAGE` stream and coverage index, fleet tokens and `coverageRef`, the dq fleet query. Also out: self-hosting, Turnkey, countersignatures, lender notification, the MST. None of these change the record model.

## 3. Components

### 3.1 Repository

One repository per org DID. A repository is an append-only commit log:

```
commit {
  seq, prev (hash of previous commit), rev (TID),
  op: create | update | tombstone,
  collection, rkey, record (canonical JSON or CBOR),
  committedBy (member DID the host authenticated, "" for the org itself),
  approvedBy [DID], committedAt,
  sig (over everything above, by the org's #dimo_org key)
}
```

The hash chain is the v1 stand-in for the MST (spec §6.2). `committedAt` is the host clock and is what every `Stored.CommittedAt` and `Membership.CommittedAt` reads. Records are addressed as `at://<orgDID>/<collection>/<rkey>`; every rkey passes `delegation.ValidateRKey`.

Collections, all under the org's authority:

| Collection | rkey | Record | Notes |
|---|---|---|---|
| `network.dimo.delegation` | TID, or a compiled grant key | `delegation.Record` | |
| `network.dimo.org.role` | TID | `delegation.Record` with `Type = role` | |
| `network.dimo.org.tag` | slug | `{name, description}` | |
| `network.dimo.org.tagMembership` | TID | `{tag, vehicle, joinedAt, leftAt?}` | one record per interval; `createdBy` is the commit's `committedBy` |
| `network.dimo.org.vehicleControl` | vehicle DID | `control.Opening` | never leaves the host except inside a coverage proof |
| `network.dimo.org.custody` | TID | `delegation.CustodyPeriod` | written by the booking service or synced from a device |
| `network.dimo.org.party` | counterparty DID | `delegation.Party` | DIMO-administered (decision E) |
| `network.dimo.agreement` | agreement ID | `agreement.Agreement` | compiled on every write (decision F) |
| `network.dimo.agreement.catalog` | `catalog` | `agreement.Catalog` | validated with `Catalog.Validate` at write |

### 3.2 Write path

Every write is `PUT /orgs/:org/:collection/:rkey` or `DELETE` for a tombstone, with a member identity token (decision B).

1. **Authenticate** the token; `committedBy` = its `sub`. A write by the org's own service DID is `committedBy = ""`.
2. **Resolve roles.** `Roles(org, member)` at now. No live role covering the write's scope with the ability the write needs (`delegation:create`, `tag:write`, `org:members`, `org:admin`) is refused.
3. **Check the record.** For delegations and roles, `delegation.CheckCommit(rec, CommitContext{From: party(org), CoveredVehicles: n, Role: role, CommittedBy: member, Approved: hasApproval, Policy: policyFor(org, rec)})`. For memberships, `CheckMembershipGrowth` over every delegation covering the tag, plus the §9.2 author-authority check. For agreements, `Agreement.Validate` then `agreement.Compile` under `agreement.CommitPolicy()`.
4. **Approval.** If `CheckCommit` returns `ErrApprovalRequired`, the write lands as **pending** with its reasons (`ApprovalReasons`). A second member with the same authority calls `POST /orgs/:org/pending/:id/approve`; the host re-runs step 3 with `Approved: true` and commits with `approvedBy`. The author cannot approve their own write.
5. **Commit.** Sign, append, return the URI, rev and CID.
6. **Compile side effects.** An agreement write upserts its compiled grants under their stable keys and tombstones grants the new compilation no longer produces. A custody write triggers recompilation of the agreement it belongs to.

Records are stored with `createdBy` exactly as sent. The evaluator refuses a record whose `createdBy` contradicts `committedBy`, so the host should reject that at write time too, with a clear message, rather than let it land and fail later.

### 3.3 Read path for the issuer

`POST /authorize` with `{uri, caller, clientId, vehicle, abilities, at?}` from dauth only (service-to-service auth). The host runs `Evaluator.Authorize` against a `Resolver` backed by its own database and the directory (`pkg/client.Control` for `ControlState`), and returns `delegation.Coverage` or a typed error (`not covered`, `exclusive hold` with the abilities, `unauthorized`). `at` defaults to now and is only honoured for callers allowed to ask about the past, which in v1 is nobody.

The `Resolver` implementation is the bulk of the host's read code:

| Method | Backed by |
|---|---|
| `Record` | records table, any org, by URI |
| `Memberships`, `TagSize` | tagMembership, indexed on `(tag, vehicle)` and `(tag, joinedAt, leftAt)` |
| `Custody` | custody, indexed on `(vehicle, holder)` |
| `Roles` | role records including tombstoned, indexed on `(org, to)` |
| `ControlState` | directory `GET /:did/control`, cached briefly |
| `Opening` | vehicleControl in the controller's repository |
| `Party` | party table |
| `Exclusives` | delegations with `exclusive` over the vehicle, live at `at`; `Since` from validity start or commit time |

### 3.4 Other reads

- `GET /orgs/:org/:collection[/:rkey]` for members with a read role or `org:admin`.
- `GET /orgs/:org/delegations/:rkey/proof?vehicle=` returns the §11.3 bundle: chain records with their commits, memberships, the opening, and the era log. Anyone holding the delegation's `to` may fetch it.
- `GET /orgs/:org/delegations/:rkey/descendants` for the delegation's `from`, resolved per vehicle. This is the consent transparency view (§9.3).
- `GET /orgs/:org/pending` for approvers.

### 3.5 Revocation

- `DELETE` a record: tombstone commit with `by = committedBy`. The evaluator ignores tombstones by a principal `revocableBy` does not allow, so the host refuses those at write time as UX.
- `POST /orgs/:org/revoke-authored-by {member, since}`: lists every record the member authored after `since`, returns it for review, and tombstones the reviewed set as one batch under one approval.

## 4. Data model

Postgres, one database, mirroring `internal/store` conventions:

```
orgs            (did pk, signing_key_enc, party jsonb, policy_name)
commits         (org, seq, prev, rev, op, collection, rkey, record jsonb,
                 committed_by, approved_by text[], committed_at, sig,
                 pk (org, seq), unique (org, collection, rkey, rev))
heads           (org, collection, rkey, seq, tombstoned_at, tombstoned_by)   -- current view
pending         (id, org, collection, rkey, record, committed_by, reasons, created_at)
```

Derived indexes for the resolver are plain btrees on `heads` joined to `commits`. No separate materialised coverage table in v1.

## 5. Changes elsewhere

**did-directory, before the host can exist:**
- The CLI can set `#dimo_org` and `#dimo_org_host` on an org DID. `create` only writes a `signing` verification method and `update` only touches services today.
- `pkg/client` gains nothing; the host uses `Control` and `Resolve`.

**dauth:**
- `/exchange` takes `{grant: at-uri, vehicle, abilities}` plus DPoP, calls the host's `/authorize` with the authenticated `sub` as `caller`, and mints the §11.1 token with `grants[0] = {subject, abilities, windows}` and the chain from `Coverage.Chain`. Lifetime 15 minutes if any live ability, else 2 hours.
- Issues identity tokens the host accepts (decision B).

**dq:**
- `DQClaim` reads `grants`; the vehicle check passes when `subject` matches; resolvers clamp the requested range to `windows`. Fleet query stays out.

## 6. Sequence

Each step ends with something runnable.

1. **CLI org keys.** `dimocli` can create an org DID with `#dimo_org` and set `#dimo_org_host`. Half a day.
2. **Repository core.** Commits, signing, heads, tombstones, `ValidateRKey` on every write, in-memory and Postgres stores, `GET` for members. No checks yet beyond structure. Test: write, read back, verify the chain and every signature offline.
3. **Resolver and `/authorize`.** Implement `delegation.Resolver` over the store and directory. Test: the Avis fixtures from `pkg/agreement/evaluate_test.go` replayed through HTTP produce the same coverage.
4. **Write-time checks and approval.** Roles, `CheckCommit`, `CheckMembershipGrowth`, pending writes, second approval, `revokeAuthoredBy`. Test: the spec §13.1 table, action by action.
5. **Agreements.** Catalog records, agreement writes compile and upsert, custody writes recompile. Test: booking → paid → picked up → returned through HTTP, then `/authorize` for the renter and the blocked operator.
6. **Proofs and descendants.** Coverage proof bundle plus an offline verifier in `pkg/proof`; descendants listing. Test: a proof verifies with the host down.
7. **dauth exchange**, then **dq clamping**, in their repos, against a running host.
8. **A new `scripts/demo.sh`** replacing the deleted one: org, fleet, three partners, one booking, one sale, tokens at each step. This is the first time the whole model runs.

## 7. Open questions carried

- **Cross-org chains and self-hosting.** A chain from Ford Pro's repo through Avis's repo is one database in v1. When an org self-hosts, `Record` and `Opening` have to fetch from another host, and that host has to decide whether to answer. Coverage proofs are the likely currency. Not designed.
- **Membership author authority (§9.2)** is checked by the evaluator from `Membership.CreatedBy`. The host must populate that from `committedBy`, not from the request body, for the same reason as `Stored.CommittedBy`.
- **Device-synced custody.** A custody period signed by the car's device arrives late and out of order. Whose write is it, under what role? Provisionally the operator's service account, with the device signature kept on the record for audit.
- **`revokeSince` ending the era** was motivated by bearer SACDs, which no longer exist (spec §19). Leave as is until someone needs the simpler behaviour.
- **What an app / `clientId` is.** Provisionally a DID with a role or grant. The `clientAllowlist` check needs dauth to attest it.
