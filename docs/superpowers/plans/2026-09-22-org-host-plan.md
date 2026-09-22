# Org host plan

**Date:** 2026-09-22
**Status:** Decisions settled with Dylan 2026-09-22 (§1). Replaces the lost `docs/org-store-plan.md`.
**Spec:** `../specs/2026-09-16-dimo-orgs-fleets-delegation-design.md` (§6, §7, §9, §11, §12 in particular; decisions in §16 and §19).

The org host is the service that holds every org's private records and is the only thing that writes them. Nothing in the delegation model runs end to end without it: `pkg/delegation` is a pure evaluator behind a `Resolver` interface, `pkg/agreement` is a pure compiler, and until 2026-09-22 the only runnable flow was the SACD path, which is now gone.

## 1. Decisions (settled 2026-09-22, recorded in spec §19)

| # | Question | Decision |
|---|---|---|
| A | Who runs the evaluator? | **The org host.** It runs `delegation.Evaluator` against its own database and exposes `POST /authorize`; dauth calls that once and mints. The split is "dauth authenticates, the org host authorizes". The host already has to run the role checks to gate its own writes, so a separate evaluator in dauth would be the same rule in two processes. Reversible: the request and response are `Evaluator.Authorize`'s signature and `Coverage`, so either service could host the call. What (2) protects that (1) would not: control openings never leave the host except inside a coverage proof, which is what lets a self-hosted org answer for itself later. |
| B | Member authentication for writes | **A dauth-issued identity token** with `sub` = member DID. One sign-in for the platform; the host never sees a key. |
| C | Commit signing in v1 | **A host-held org signing key**, encrypted at rest, behind a `Signer` interface. Turnkey is too heavy for demo-class development and is a swap later. The org DID document carries the public half as `#dimo_org`. |
| D | Second approval | **A protocol-level record fact, not a vendor feature.** A write that `CheckCommit` flags lands as pending; a second member holding the same authority approves; the commit carries `approvedBy` and the evaluator reads that field. Turnkey or any other signer policy is only a way of collecting the second signature and changes nothing the evaluator sees. |
| E | Party attributes | **A DIMO-administered table** of `{kind, operator}` per DID. It is DIMO's say-so and a table is honest about that. Can become a record in a DIMO-authority repository later without changing consumers. |
| F | Who compiles agreements? | **The booking service, client side**, as spec §12 already says. The host stays generic: it never learns what a booking is. `pkg/agreement` is an SDK the operator links; it posts plain delegation records under a constrained booking role, and the role constraints bound what it may write. Custody periods are still host records, because the evaluator narrows by them. The agreement itself stays with the operator; `terms` on every grant hashes the governing contract for disputes. |
| G | Where the code lives | **This repo, `cmd/org-host`, own database.** A separate service; repo placement is convenience until a second consumer of `pkg/delegation` exists. |

## 2. Scope of v1

**In:** one host instance serving every org; records, tags, memberships, roles and custody periods as signed hash-chained commits; write-time checks; two-person approval; `/authorize` for dauth; coverage proofs; descendants listing for consent; tombstones and `revokeAuthoredBy`; membership growth checks.

**Out, deferred on 2026-09-21:** the `ORG_COVERAGE` stream and coverage index, fleet tokens and `coverageRef`, the dq fleet query. Also out: self-hosting, Turnkey, countersignatures, lender notification, the MST, and any knowledge of agreements or catalogs (decision F). None of these change the record model.

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

As built (step 2): the commit also carries `did`, the org, inside the signature, so a commit cannot be replayed into another repository even if two orgs were published under one key. The record is stored as the canonical JSON that was signed (sorted keys, no whitespace, numbers verbatim) and only derived into jsonb for queries, because a signature has to be checked against the bytes it was made over and jsonb does not give those back. A commit's CID is the sha2-256 multihash of the signed commit, as the directory does for operations; `prev` names it. `committedAt` is UTC at microsecond precision so a timestamptz round trip does not change the signed bytes. `repo.VerifyLog` replays a whole log offline against `#dimo_org`.

Collections, all under the org's authority:

| Collection | rkey | Record | Notes |
|---|---|---|---|
| `network.dimo.delegation` | TID, or a compiled grant key | `delegation.Record` | |
| `network.dimo.org.role` | TID | `delegation.Record` with `Type = role` | |
| `network.dimo.org.tag` | slug | `{name, description}` | |
| `network.dimo.org.tagMembership` | TID | `{tag, vehicle, joinedAt, leftAt?}` | one record per interval; `createdBy` is the commit's `committedBy` |
| `network.dimo.org.vehicleControl` | vehicle DID | `control.Opening` | never leaves the host except inside a coverage proof |
| `network.dimo.org.custody` | TID | `delegation.CustodyPeriod` | written by the booking service under its role, or synced from a device |

Party attributes are not a collection: they live in a host-level table keyed by DID (decision E).

### 3.2 Write path

Every write is `PUT /orgs/:org/:collection/:rkey` or `DELETE` for a tombstone, with a member identity token (decision B).

1. **Authenticate** the token; `committedBy` = its `sub`. A write by the org's own service DID is `committedBy = ""`.
2. **Resolve roles.** `Roles(org, member)` at now. No live role covering the write's scope with the ability the write needs (`delegation:create`, `tag:write`, `org:members`, `org:admin`) is refused.
3. **Check the record.** For delegations and roles, `delegation.CheckCommit(rec, CommitContext{From: party(org), CoveredVehicles: n, Role: role, CommittedBy: member, Approved: hasApproval, Policy: policyFor(org, role)})`. The policy is chosen per org and per role, so a booking role commits under `agreement.CommitPolicy()` without the host knowing what a booking is. For memberships, `CheckMembershipGrowth` over every delegation covering the tag, plus the §9.2 author-authority check.
4. **Approval.** If `CheckCommit` returns `ErrApprovalRequired`, the write lands as **pending** with its reasons (`ApprovalReasons`). A second member with the same authority calls `POST /orgs/:org/pending/:id/approve`; the host re-runs step 3 with `Approved: true` and commits with `approvedBy`. The author cannot approve their own write.
5. **Commit.** Sign, append, return the URI, rev and CID. A `PUT` to an existing rkey is an update commit, which is how a booking service upserts a compiled grant under its stable key; it tombstones grants its next compilation no longer produces.

Records are stored with `createdBy` exactly as sent. The evaluator refuses a record whose `createdBy` contradicts `committedBy`, so the host should reject that at write time too, with a clear message, rather than let it land and fail later.

As built (step 4), what each write takes, all resolved through `Evaluator.RolesCovering`, which is the evaluator's own `hasRole`, so a write the host accepts is one evaluation honours:

| Write | Needs, over the record's scope |
|---|---|
| delegation | `delegation:create` plus every ability the record hands out (`delegation.AuthoringNeed`) |
| role | `org:members` plus every ability the role hands out. The evaluator now checks this too (`roleActive`): a member-written role is only a role if its author held that, and a role to oneself needs a second approval, so a host bug cannot mint authority. |
| tag | `tag:write` over the tag |
| tagMembership | `tag:write` over the tag, then `tag:write` plus D's abilities for every live delegation D over the tag (§9.2, `delegation.MembershipNeed`); a write some D would ignore is refused naming those D. |
| vehicleControl | `org:admin` over the vehicle, or the org itself |
| custody | `delegation:create` over the vehicle: custody narrows grants host-wide (§7), so it takes the same authority as a grant |

**The policy is per role, not per org.** A role names its profile in `constraints.policy` (`RoleConstraints.Policy`); the host holds a registry (`orghost.Policies`, the binary registers `agreement.CommitPolicy()` under its name) and refuses a role naming a profile it does not know. Naming one makes the constraints present, so a booking role also sets `allowExclusive`. The `policy_name` column on `orgs` in §4 was not built. A member holding several roles may commit under any one of them; when none passes, an approval requirement from any role wins over a refusal, since it is the more useful answer.

**The org's own writes park like anyone else's.** The second signature is a record fact (decision D), so nothing depends on who holds the org key or on a signer with its own policy; the blast-radius rules of spec §7 bind the org's service DID too. What makes that possible is **what an approver must hold: the ability that manages records of that kind over the scope** (`delegation:create`, `org:members` for a role, `tag:write` for a membership), not everything the record hands out. The author already holds those, or is the org. The evaluator's `approvedByAnother` applies the same rule. Requiring the approver to hold what a role hands out, as first built, made an org's first writes impossible to approve: before the first role nobody holds anything. Bootstrap is therefore: the org writes an admin role with no live abilities, which commits directly, and every later write the policy flags, the booking role included, waits for that admin. The org may approve a member's write and a member may approve the org's; nobody approves their own.

**Approval** re-runs steps 2 and 3 at approval time with `Approved: true`, so the author must still hold their authority then, which is what evaluation checks at the commit time. The approver must be neither the author nor the recipient. A pending write answers 202 with `{pending, uri, reasons}`; `GET /orgs/:org/pending` lists them for any member; `DELETE /orgs/:org/pending/:id` withdraws one, for its author or the org. Membership growth is counted only when the write adds a vehicle to the tag: re-writing a member's interval, or an interval that has already ended, grows nothing.

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

As built (step 3): `internal/orghost.Resolver` reads records from any repository on this host, so a chain from one org through another resolves as long as both live here. `Custody` and `Exclusives` are likewise host-wide, found by `(vehicle, holder)` and by `covers.vehicle`, plus `covers.tag` for a tag the vehicle has a raw live membership in at `at`; an exclusive claim whose coverage is `inherit` is not found, since finding it means evaluating its chain, which is what the deferred coverage index was for. Control state comes from the directory through `pkg/client.Control`, cached 30 seconds; a vehicle the directory does not hold has no eras. `Party` reads the `parties` table, set by `PUT /parties/:did` from a DID in `ADMIN_DIDS`; an org registered here with no row is `KindOrg` and not an operator, and any other unlisted DID is `KindUnknown`. `/authorize` is open to the DIDs in `ISSUER_DIDS`, refuses `at`, evaluates under `DefaultPolicy` at the host clock and returns the coverage plus `at`; refusals are 403 with a `code` naming the evaluator's error, and `exclusive_hold` carries the suspended abilities, for which `delegation.ExclusiveHoldError` now exists. A tombstone the org wrote itself has `by = ""` on the commit and is handed to the evaluator as the org DID, since `revokedAt` compares it to `from`.

### 3.4 Other reads

- `GET /orgs/:org/:collection[/:rkey]` for members with a read role or `org:admin`. As built (step 4): the org itself, or any member holding a live role, reads every collection but `vehicleControl`; the openings, and `GET /orgs/:org/commits` which carries them, take `org:admin`. Scoping a member's reads to their role's covers is not done.
- `GET /orgs/:org/delegations/:rkey/proof?vehicle=` returns the §11.3 bundle: chain records with their commits, memberships, the opening, and the era log. Anyone holding the delegation's `to` may fetch it.
- `GET /orgs/:org/delegations/:rkey/descendants` for the delegation's `from`, resolved per vehicle. This is the consent transparency view (§9.3).
- `GET /orgs/:org/pending` for approvers.

### 3.5 Revocation

- `DELETE` a record: tombstone commit with `by = committedBy`. The evaluator ignores tombstones by a principal `revocableBy` does not allow, so the host refuses those at write time as UX.
- `POST /orgs/:org/revoke-authored-by {member, since}`: lists every record the member authored after `since`, returns it for review, and tombstones the reviewed set as one batch under one approval.

As built (step 4): **a member's tombstone is the org's act.** The evaluator honours a tombstone written by a principal `revocableBy` names, or by a member of one who held, at tombstone time, a role covering the record with the ability that manages records of its kind (`delegation.ManageAbility`: `delegation:create`, or `org:members` for a role). Revoking takes less than authoring: the abilities the record hands out are not needed to take it away. Before this the plan as written meant only the org DID itself could revoke anything. The host's `DELETE` runs the same rule (`checkTombstone`), so a lien is the lender's, or its staff's, to release. The recursion through roles and tombstones is bounded by chain depth and a role cannot vouch for its own author. `revoke-authored-by` with `uris` checks every tombstone as a `DELETE` by the caller would be, before any is written, and answers 400 for a URI outside the listed set; "authored" means the record's current version was committed by the member after `since`.

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
- The CLI can set `#dimo_org` and `#dimo_org_host` on an org DID. **Done 2026-09-22:** `dimocli create --org [--org-key did:key] [--org-host URL]` publishes the commit key (generated into the keystore as `<did>.org.json`, or supplied by the host) and the `DimoOrgHost` service entry; `update --org-key | --new-org-key | --org-host` sets them on an existing DID; `rotate` keeps `#dimo_org`; `pubkey --org` prints it. Controlled DIDs refuse all three.
- `pkg/client` gains only `ErrNotFound`, so the host can tell an unknown vehicle from a directory outage; it uses `Control` and `Resolve`.
- `pkg/agreement` gains a small client: compile, then `PUT` each grant and custody period to the host under the booking role, and tombstone the keys that dropped out. This is the booking SDK (decision F). It may move to its own repo later; nothing here depends on it.

**dauth:**
- `/exchange` takes `{grant: at-uri, vehicle, abilities}` plus DPoP, calls the host's `/authorize` with the authenticated `sub` as `caller`, and mints the §11.1 token with `grants[0] = {subject, abilities, windows}` and the chain from `Coverage.Chain`. Lifetime 15 minutes if any live ability, else 2 hours.
- Issues identity tokens the host accepts (decision B).

**dq:**
- `DQClaim` reads `grants`; the vehicle check passes when `subject` matches; resolvers clamp the requested range to `windows`. Fleet query stays out.

## 6. Sequence

Each step ends with something runnable.

1. **CLI org keys.** `dimocli` can create an org DID with `#dimo_org` and set `#dimo_org_host`. Half a day. **Done 2026-09-22** (§5).
2. **Repository core.** Commits, signing, heads, tombstones, `ValidateRKey` on every write, in-memory and Postgres stores, `GET` for members. No checks yet beyond structure. Test: write, read back, verify the chain and every signature offline. **Done 2026-09-22:** `pkg/repo` (commit, canonical JSON, TIDs, `VerifyLog`), `internal/orghost` (sealed keys behind `repo.Signer`, JWKS identity tokens, structural checks, write path) and `internal/orghost/store` (memory and Postgres), served by `cmd/org-host`. Until step 4 any authenticated DID may read or write any repository; the commit records who did. See §3.1 for what the commit gained.
3. **Resolver and `/authorize`.** Implement `delegation.Resolver` over the store and directory. Test: the Avis fixtures from `pkg/agreement/evaluate_test.go` replayed through HTTP produce the same coverage. **Done 2026-09-22:** `internal/orghost.Resolver`, the store's resolver queries with partial expression indexes over the derived jsonb (memory and Postgres), the `parties` table and routes, `POST /authorize`, and `DIRECTORY_URL`, `ISSUER_DIDS`, `ADMIN_DIDS` settings. `TestCompiledGrantsAuthorizeOverHTTP` and `TestInsurerGrantAuthorizesOverHTTP` are the replay, driven at fixed host-clock times. See §3.3 for what was settled in the building.
4. **Write-time checks and approval.** Roles, `CheckCommit`, `CheckMembershipGrowth`, pending writes, second approval, `revokeAuthoredBy`. Test: the spec §13.1 table, action by action. **Done 2026-09-22:** `internal/orghost/access.go` (the per-collection role checks, `CheckCommit` under the role's named policy, §9.2 and growth checks on memberships, approver rules, tombstone and read checks), `pending.go` (pending list, approve, withdraw, `revoke-authored-by`), the `pending` table and the `Authored` and `DelegationsOverTag` queries in both stores. `pkg/delegation` gained `RolesCovering`, `HeldRoles`, `CoveredVehicles`, `ManageAbility`, `AuthoringNeed`, `MembershipNeed`, `Revokers`, `RoleConstraints.Policy`, the member-tombstone rule and the role-author check. `TestAvisActions` is the §13.1 table over HTTP against both stores. See §3.2, §3.4 and §3.5 for what was settled in the building.
5. **Booking SDK.** The `pkg/agreement` client from §5 against the running host. Test: booking → paid → picked up → returned driven from a test booking service, then `/authorize` for the renter and the blocked operator. The host's code does not change in this step.
6. **Proofs and descendants.** Coverage proof bundle plus an offline verifier in `pkg/proof`; descendants listing. Test: a proof verifies with the host down.
7. **dauth exchange**, then **dq clamping**, in their repos, against a running host.
8. **A new `scripts/demo.sh`** replacing the deleted one: org, fleet, three partners, one booking, one sale, tokens at each step. This is the first time the whole model runs.

## 7. Open questions carried

- **Cross-org chains and self-hosting.** A chain from Ford Pro's repo through Avis's repo is one database in v1. When an org self-hosts, `Record` and `Opening` have to fetch from another host, and that host has to decide whether to answer. Coverage proofs are the likely currency. Not designed.
- **Membership author authority (§9.2)** is checked by the evaluator from `Membership.CreatedBy`. The host must populate that from `committedBy`, not from the request body, for the same reason as `Stored.CommittedBy`.
- **Custody and exclusives are host-wide.** `Resolver.Custody(vehicle, holder)` and `Exclusives(vehicle, at)` carry no org, so they read every repository on the host. A custody record in org B's repository therefore widens a custody-narrowed grant from org A, up to A's own data window, and an exclusive claim in B suspends A's live abilities. Step 4's role checks bound who may write either; scoping them to the issuer's repository instead would need the `Resolver` to be told which grant is asking, or the record's controller to be found through the directory on every call. Left host-wide for now.
- **Device-synced custody.** A custody period signed by the car's device arrives late and out of order. Whose write is it, under what role? Provisionally the operator's booking service, with the device signature kept on the record for audit.
- **`revokeSince` ending the era** was motivated by bearer SACDs, which no longer exist (spec §19). Leave as is until someone needs the simpler behaviour.
- **What an app / `clientId` is.** Provisionally a DID with a role or grant. The `clientAllowlist` check needs dauth to attest it.
