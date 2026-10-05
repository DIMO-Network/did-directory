# DIMO Orgs, Fleets & Delegation

**Date:** 2026-09-16
**Status:** Decisions recorded (§16, §19). did-directory layer merged (PR #6) and trimmed of the SACD path on 2026-09-22 (§17). Org host, dauth and dq still to do; the org host plan is `docs/superpowers/plans/2026-09-22-org-host-plan.md`.
**Supersedes, in `2026-03-26-dimo-v2-identity-architecture-design.md`:** Layer 1.1 (Organizational Accounts), the grantor model of Layer 3 (SACDs), the epoch semantics of Layer 3.1, and "Fleet scaling" in Layer 5.
**Evolves:** the 2026-06-12 fleet sharing decision (org smart account holder, off-chain credential hierarchy, no on-chain org node). That decision still holds for NFT-era vehicles. This spec is the did:dimo form of it.

---

## 1. Problem

One rental car is shared with many parties at once, each on different terms:

| Party | Relationship | Scope | Lifetime |
|---|---|---|---|
| Avis (operator) | runs the fleet | everything | years |
| Ford Credit | lienholder | location and health, **must not be revocable by Avis** | life of the loan |
| Insurer | coverage agreement | telemetry and incident data | policy term |
| Ford Pro | fleet-management service | telemetry and commands | contract term |
| Rental franchisee / sub-org | runs part of the fleet | subset of cars, subset of abilities | years |
| Renter | rental contract | one car, unlock/lock and fuel, data from the rental only | days |

Dealers have the same shape, except the cars belong to customers. The dealer only has what each owner consented to.

The prototype can't express any of this at scale.

- **The vehicle is the grantor.** `did-directory/cmd/dimocli/sacd_grant.go` sets `Asset: *grantor` and signs with the vehicle DID's own key. Every share happens "as the car".
- **Grants multiply.** 10,000 cars × 5 parties = 50,000 signed documents. Adding a car means five more signatures, and dropping a partner means 10,000 revocations.
- **No roles.** Nobody can tell which person at Avis did what.
- **Every sale erases history.** An epoch bump on sale wipes every grant, including the insurer's access to the months it legitimately covered.
- **The dq token covers one car exactly.** `dq/internal/auth/directives.go` `NewVehicleTokenCheck` requires `claim.Asset == subject`. The token has no time window and no way to name a group of cars.

## 2. Why atproto Spaces is not the permission model

Per atproto Spaces (proposal 0016), a space is `(authority DID, type, key)`. The authority decides membership and mints a 2-hour credential bound to a key the app holds (DPoP). Read access is **all or nothing for the whole space**, with no roles, no nesting, no owner consent and no time scoping. Immediate revocation means deleting the space.

That model fits a private shared room. Our problem is authority over assets that other parties control. From Spaces we take:

- **Long-lived relationship, short-lived key-bound credential:** membership persists, and the credential is minted on demand and bound to the caller's key (DPoP).
- **Authority signing key and host in the DID document:** fields `#dimo_org` and `#dimo_org_host`, so DIMO can host by default and large orgs can self-host.
- **App allowlist:** an org can restrict which client apps may use its delegations.
- **Dissolve notice:** anyone holding synced data purges it when an agreement or org ends.
- **Spaces themselves, for private records:** each org's repository (§6) lives in a Space. Agreements can open shared Spaces for co-authored records such as inspections, damage reports and rental agreements. That is what Spaces is built for.

## 3. Principles

1. **A vehicle never signs a grant.** Authority to share comes from controlling the vehicle, and a controller signs as itself.
2. **One primitive.** Control, liens, consent, partner agreements, sub-orgs, employee roles and renter sessions are all a **delegation** that can only narrow as it passes down.
3. **Tags select, delegations authorize.** A tag is a set of cars over time. It grants nothing on its own.
4. **The org repository is the source of truth.** Delegations, tags and roles are records in the org's signed repository, so a grant is an act of the org, not of the employee who clicked the button.
5. **The issuer does the hard checking, edge services don't.** Chains are resolved once, when a credential is minted. dq and fetch verify one flat, short-lived token.
6. **Time applies to data as well as to grants.** Every delegation separates *when the grant is valid* from *which data timestamps it covers*.
7. **Fleet composition is private.** Nothing public tells an observer which cars an org controls.

---

## 4. Principals

| Principal | DID | Keys |
|---|---|---|
| Person | `did:dimo:…` | passkey + MPC recovery (v2 Layer 3.2) |
| Org | `did:dimo:…` | `rotationKeys`: org root (Turnkey sub-org, policy-gated). `#dimo_org`: repository commit signing key (Turnkey). Members are **not** listed in the DID document (§6.3). |
| Vehicle | `did:dimo:…` | `rotationKeys`: one per-vehicle key held by the controller of record. **No grant-signing verification method.** |
| Device / provider | `did:dimo:…` | sign data (v2 Layer 6), unchanged |
| Service account | `did:dimo:…` owned by an org | key in Turnkey or the customer's KMS |

**Vehicle keys.** The prototype generates a key for each vehicle (`did-directory/cmd/dimocli/create.go:44-50`) and keeps it as a secondary rotation key. That key goes away. A vehicle's identity updates are authorized only by its controller-held rotation key. Its data is signed by devices and providers.

---

## 5. The delegation record

**ODRL is the wire format; this record is the parsed form.** The fixed choices say permissions are ODRL with a DIMO profile, so what crosses a wire, lands in a repository or goes to a counterparty's lawyer is an ODRL policy, and what the evaluator works on is the record below. `pkg/odrl` is the codec, and the round trip is lossless:

| ODRL | Record |
|---|---|
| `assigner` / `assignee` | `from` / `to` |
| `target` — an `AssetCollection` for a tag, an `Asset` for a vehicle | `covers` |
| `action`, as `dimo:` profile IRIs | `abilities` |
| `constraint` `dateTime` | `validity` |
| `constraint` `dimo:dataTime` | `dataWindow` |
| `constraint` `purpose`, `dimo:client` | `purpose`, `clientAllowlist` |
| `duty` | what code cannot enforce: payment, retention, refunds |

Delegation, exclusivity, custody narrowing and issue constraints have no ODRL equivalent, so they are profile terms under `dimo:` rather than ODRL bent out of shape. A role is an ODRL `Set` (an org's own rule about its staff), a grant is an `Agreement`. Five rules keep the format honest, all the same rule in different places — *never quietly turn a document into more authority than it carries*:

1. An **unknown constraint is refused**, and so is any key the profile does not define, at any depth; dropping one grants more than the policy says. A `@context` other than ODRL's and the profile's is refused too, since a context can redefine a term for anyone reading the policy as JSON-LD.
2. Only `Agreement` and `Set` parse into a grant. An **`Offer` is a proposal**, a `Request` is someone asking, and a policy with no `@type` says nothing.
3. A **`prohibition`, or a `duty` attached to a permission, is refused** rather than dropped — both change what the permission means.
4. Durations cross as **seconds**; a duration the field cannot carry exactly is refused rather than truncated, since `0` means unlimited and truncation would remove a cap.
5. The round trip is **lossless**: a term nobody can read back is a term nobody agreed to.

**At the host (built 2026-09-24).** The org host accepts delegations and roles only as ODRL policies — an `Agreement` in `network.dimo.delegation`, a `Set` in `network.dimo.org.role` — and commits the codec's own rendering of what it parsed (`odrl.Normalize`), not the submitted bytes: nothing is signed that the codec cannot read back, and two spellings of one grant commit as one. The policy's `uid` is the record's at-uri; the host fills it in, and refuses a policy that names another. The policy is handled as JSON, not JSON-LD: it is signed with the same canonical JSON as every other record, and the profile IRI need not resolve. The booking SDK sends compiled grants as ODRL, coverage proofs carry the policies, and the store's lookups index the policy's own fields (`assignee`, the permission's `target`, `dimo:basis`, `dimo:exclusive`). Tags, memberships, openings and custody periods are facts rather than permissions and stay plain JSON. dauth and dq never see a policy; they see the claims the host computed from one.

Every relationship in §1 parses to a record of this shape, which is what the evaluator works on. The issuing principal's repository (§6) holds it as the ODRL policy:

```json
{
  "$type": "network.dimo.delegation",
  "from": "did:dimo:avis…",
  "to":   "did:dimo:fordcredit…",
  "basis": [],
  "covers": { "tag": "at://did:dimo:avis…/network.dimo.org.tag/fl-fleet" },
  "abilities": ["telemetry:read", "location:precise"],
  "dataWindow": { "from": "2026-09-16T00:00:00Z" },
  "validity":   { "from": "2026-09-16T00:00:00Z", "to": "2029-09-16T00:00:00Z" },
  "redelegate": { "mode": "attenuated", "maxDepth": 1 },
  "revocableBy": "from",
  "afterRemoval": "retainHistory",
  "afterTransfer": "retainHistory",
  "purpose": "fleet-financing",
  "terms": "sha256:9f2c…",
  "clientAllowlist": null,
  "createdBy": "did:dimo:alice…",
  "createdAt": "2026-09-16T14:02:11Z"
}
```

| Field | Meaning |
|---|---|
| `from` | Principal issuing the delegation. It must hold every ability being delegated, over everything covered, through `basis`. |
| `to` | Recipient: a person, org or service DID. |
| `basis` | Parent delegation(s) this one narrows. Empty means the delegation is a **root of control**: authority comes directly from `from` being the controller of record (§7). The Ford Credit example above is a root because Avis controls the cars. |
| `covers` | Exactly one of `{vehicle: DID}`, `{tag: at-uri}`, or `{inherit: true}` (same coverage as the parent). |
| `abilities` | Namespaced abilities (§5.1). |
| `dataWindow` | Range of **data timestamps** this delegation can read. Omit `to` for open-ended. |
| `validity` | When the delegation itself can be exercised. |
| `redelegate` | `none` \| `attenuated` (with `maxDepth`) \| `allowlist` (with `grantees: [DID]`). |
| `revocableBy` | `from` (default) \| `to` (lien-style: only the recipient can release it) \| `either`. |
| `afterRemoval` | When a car leaves the covering tag: `retainHistory` (default for historical abilities) or `drop`. |
| `afterTransfer` | When the vehicle's control era ends (§8): `retainHistory` (default) or `drop`. |
| `purpose`, `terms` | Human purpose plus a hash of the governing contract. Shown to owners (§9.3) and used in disputes. |
| `clientAllowlist` | Optional list of OAuth `client_id`s allowed to use this delegation (from Spaces `appAccess`). |
| `exclusive` | Live abilities this delegation holds **exclusively** while it is live: nobody else, the controller included, may exercise them over that vehicle (§12). A child may claim it only where its basis set `redelegate.exclusive`. |
| `recovery` | May act despite someone else's exclusive hold. Every such use is reported so the issuer logs it. |
| `createdBy` | Audit copy of the author. **Authority is checked against the repository's witnessed `committedBy`, never against this field** — a field inside the signed bytes hands authorship back to whoever writes them, and omitting it would otherwise beat declaring it. A record whose `createdBy` names an author the repository never witnessed is refused. The author must have held `delegation:create`, every ability in the record, and a role whose constraints admit its shape; their later departure invalidates nothing (§6.3). |
| `narrowToCustody` | Intersects historical coverage with the times the recipient actually held the vehicle (§12.3). |
| `constraints` | Roles only: bounds the **shape** of what the holder may issue (§6.3). |

### 5.1 Abilities

Abilities split into two classes because time works differently for each.

- **Historical abilities** (`telemetry:read`, `health:read`, `location:precise`, `location:approximate`, `events:read`, `documents:read`, `raw:read`). These are checked against **data timestamps**. The question is whether the data point at time *t* falls inside the covered windows.
- **Live abilities** (`command:lock`, `command:unlock`, `command:charge`, `stream:live`, and anything ending `:write` or `:deliver`). These are checked against **the time of the request**. A device sending a reading is doing it now; checking a write against a data window would ask whether it may write a reading it has not taken. They are never kept after removal or transfer.
- **Actuating abilities** (`command:*`) are the subset that makes the vehicle do something. Approval and custody suspension key off actuation, not off liveness, so pairing a device does not need two admins.
- **Administrative abilities** (`delegation:create`, `tag:write`, `org:members`, `org:admin`). These are used inside an org and are always scoped by `covers`.

v1 abilities map to the v2 Layer 5 permission table. Every privilege 1–8 gets a v2 name, and the issuer writes both names into the credential during the transition.

### 5.2 Narrowing rule

A child delegation *C* with basis *P* is valid at time *t* only if **all** of the following hold:

1. `C.from == P.to`, or `C.from` is a member of `P.to` holding `delegation:create` over the covered cars (§6.3).
2. `P.redelegate` allows it: `attenuated` with remaining depth, or `allowlist` containing `C.to`.
3. `C.abilities ⊆ P.abilities`.
4. `coverage(C, t) ⊆ coverage(P, t)`. A child can't reference a tag that belongs to a different org than its parent's coverage unless `covers: {inherit: true}`, or it can name a specific vehicle already covered.
5. `C.dataWindow ⊆ P.dataWindow` and `C.validity ⊆ P.validity`.
6. *P* is valid at *t*, checked recursively up to a root of control (§7).
7. Chain depth ≤ 5 (root → operator → sub-org → partner → vendor).

---

## 6. Org repository

### 6.1 Collections

| Collection | Record key | Content |
|---|---|---|
| `network.dimo.delegation` | TID | §5 |
| `network.dimo.org.tag` | tag slug | `{name, description}` |
| `network.dimo.org.tagMembership` | TID | `{tag, vehicle, joinedAt, leftAt?}`, one record per membership interval; its author is the commit's witnessed `committedBy`, never a field in the record |
| `network.dimo.org.role` | TID | a delegation from the org to a member (§6.3), stored separately so it can be listed |
| `network.dimo.org.vehicleControl` | vehicle DID | `{vehicle, salt, era, since}`, the private opening of the control commitment (§10) |

### 6.2 Signing and storage

- **Commits.** Every write is a commit signed by the org's `#dimo_org` key. v1 uses a hash-chained commit log per repository (same design as the v2 receipt chain). An MST replaces it when efficient partial sync is needed, as v2 already defers.
- **Visibility.** The repository is one Space with authority = org DID, readable only by org members holding `org:admin` or a scoped read role. Grantees never read the repository directly. They get **coverage proofs** (§11.3) for their own delegations.
- **Hosting.** DIMO hosts by default through the org host service, found via the `#dimo_org_host` service entry. Self-hosting is supported.
- **Revocation.** A revocation is a tombstone commit. A deleted record stays in the log, so disputes can prove what existed and when.

### 6.3 Members, roles and departures

Members are **not** listed in the org's DID document. A role is a delegation from the org to a member DID:

```json
{
  "$type": "network.dimo.org.role",
  "from": "did:dimo:avis…",
  "to":   "did:dimo:alice…",
  "basis": [],
  "covers": { "tag": "at://did:dimo:avis…/network.dimo.org.tag/fl-fleet" },
  "abilities": ["delegation:create", "tag:write", "telemetry:read"],
  "validity": { "from": "2026-01-10T00:00:00Z" },
  "redelegate": { "mode": "none" }
}
```

- **Writes are org acts.** A member writes by authenticating to the org host. The host checks the member's roles and commits under the org key. A delegation's validity rests on **the org's commit**, not on the member's key.
- **Departures don't invalidate anything.** When Alice leaves, her role is tombstoned. The 3-year agreements she authored stay valid because they were Avis's acts. `createdBy` stays for audit.
**Role constraints.** A role's abilities say what its holder may do; they say nothing about the shape of what it may hand out. A booking service needs `delegation:create` with `command:*` over a fleet to issue a custody grant at every pickup, unattended. Without a bound on shape, one compromised booking service writes itself a fleet-wide, permanent, command-bearing grant using exactly the authority it legitimately holds. A role therefore carries `constraints`:

| Constraint | Bounds |
|---|---|
| `maxVehicles` | how many vehicles one issued grant may cover. Counted **at evaluation**, so a tag that grows later carries an already-issued grant past its limit and it stops evaluating — fail-closed, and the org host should warn on membership writes that would do it. |
| `maxValidity` | the longest validity an issued grant may have. When set, an unbounded validity is refused: "forever" is the shape being guarded against. |
| `abilities` | what may be handed out, narrower than what the role itself holds. |
| `allowRedelegation` | off by default, so an issued grant is a leaf. |
| `allowExclusive` | custody needs exclusivity, and this gates recovery with it — recovery is exclusivity's override, so it needs at least the same permission. |
| `maxDataReach` | how far before its own validity an issued grant's data window may reach back. Without it the narrowest possible role still hands out every trip every prior renter took. Measured against the record's own validity, not a clock, so the answer does not drift between commit and evaluation. |

An absent `constraints` is unbounded, which is what every role written before them means. A **tag-scoped role covers a single vehicle that was in its tag** when the grant was authored, so a booking service scoped to one fleet can write per-car custody grants without an org-wide role.

- **Compromised member.** Tombstone the role, then run `revokeAuthoredBy(member, since)`. That tombstones every record the member authored after the suspected compromise time, as one reviewed batch.

---

## 7. Roots of control

A **root of control** is a delegation with empty `basis`. It is the only place authority enters the system. It is valid only if its `from` is the **controller of record** for the vehicle in the current era.

| How the controller of record is established | Proof the issuer checks |
|---|---|
| Native did:dimo vehicle | The vehicle DID's `controlCommitment` (§10) opens to `from`, and the vehicle's current rotation key is custodied by `from` |
| NFT-era vehicle | The on-chain holder address maps to `from` in the **holder registry** (org holder = ZeroDev kernel per the 2026-06-12 decision; person = their account) |

A root is implicit for the controller: the controller holds every ability over its own vehicles. Explicit root records exist only to split control:

| Relationship | Delegation |
|---|---|
| Title SPV → operator | Explicit root from the SPV's org DID to Avis, all abilities, `redelegate: attenuated`. Only needed when the entity holding title is modeled separately. Otherwise Avis is simply the controller. |
| Lien | Controller → lender, `abilities: [location:precise, health:read]`, `revocableBy: "to"`, `validity.to` = loan maturity, `afterTransfer: "drop"`. Released by the lender on payoff. |
| Owner consent (dealer) | Owner → dealer org, scoped abilities, `purpose`, `redelegate: {mode: "allowlist", grantees: [...]}` or `none` (§9.2) |
| Consumer app grant | Owner → developer DID, `covers: {vehicle}`. Same record type, no special consumer path. |

**Party attributes, not entity type.** Policy keys off attested status, never off whether a DID is a person or an org. A sole proprietor with six cars on a peer-to-peer platform is an **operator**; a large company renting one car is a **consumer** in that transaction; and the same person is routinely both, in different agreements, at the same time. `delegation.Party` carries `Operator`, and every rule below reads it. A `ConsumerProtected` flag was declared for jurisdictional consumer rules and removed on 2026-09-22 because nothing read it; it returns with its first rule.

**Thresholds are policy, not constants.** Whether a consumer may sign away their right to revoke, how many vehicles one signature may cover, and what an operator may see during a rental vary by jurisdiction. `delegation.Policy` is a profile chosen from the agreement's governing law and passed to both the commit check and the evaluator. The engine enforces; the profile decides.

**Nobody grants themselves.** Staff are customers too. A member may not author a grant where they are the recipient unless a second principal, who held the same authority at commit time, approved the write. Enforced at evaluation, and surfaced at commit time as an approval reason.

**Blast radius controls.** The org host refuses to commit any delegation that:
- covers more than N vehicles (default 500), or
- includes an actuating ability (`command:*`, §5.1), or
- sets `revocableBy: "to"`

unless the commit carries a second approval (`approvedBy`, decision 24), under the policy the authoring role names. Root rotation keys never sign routine writes. In v1 this is checked when the record is committed, not again when it is evaluated (decision 27): the evaluator does not know which policy a role committed under, and a booking role's policy deliberately lets custody commands through without a second admin (§12.5).

The vehicle count is checked at commit time and again whenever membership of a covering tag would push the count past N. A membership write that crosses the threshold needs the same approval, so a tag can't grow a small delegation into a fleet-wide one unnoticed.

---

## 8. Eras (replaces the SACD epoch)

The v2 `sacdEpoch` did two jobs, sale and compromise, with one blunt effect: wipe everything. It splits into two operations on the vehicle DID:

| Operation | Trigger | Effect |
|---|---|---|
| `transfer` | Control changes (sale, defleet, lease return) | `era += 1`, and the new era starts at time *t*. Delegations from earlier eras lose all live abilities and all data after *t*. Historical abilities keep data from **their own era's interval** if `afterTransfer: retainHistory`. The new controller **cannot** read earlier eras by default. |
| `revokeSince` | Controller key compromise | Records a compromise window **[*s*, *issued*]** and **ends the era**, opening era+1 under the **same** controller with a freshly salted commitment. The same operation may rotate the custody keys; nothing else may change. The window travels into the new era, so anything committed inside it stays void forever. |

**Why a revocation ends the era.** A window filters on *commit* time. A delegation has one the repository witnessed; an SACD does not — it is a detached document whose `effectiveAt` is chosen by whoever holds the signing key, so a stolen key can date a forged grant on either side of any window the controller can record. No comparison against an attacker-chosen number fixes that. Ending the era invalidates the capability itself, because an SACD names its era and its control proof must open that era's commitment.

The cost, stated plainly: **SACDs issued before the window die too**, not only those issued inside it. Delegations keep their pre-window history through era intervals, so for them the blunt old behaviour is genuinely replaced; for a bearer document it cannot be. After a revocation the controller re-issues its SACDs and publishes a new opening for the new era, or its delegations lose coverage from the window onward.

Deactivating a controlled DID likewise needs a signed `effectiveAt`, which closes its final era; the DID then has no controller of record and nothing verifies against it.

Both operations carry a signed timestamp (`effectiveAt`) that must be within ±5 minutes of the directory clock, so a controller can't backdate a transfer to strip grantees of history they were entitled to. A transfer's `effectiveAt` must also be after the current era's start, and a revocation window must start within the current era. Windows are closed at both ends, so a grant dated exactly at an era boundary fails — fail-closed, and worth knowing at second granularity.

Resulting behavior:
- **Insurer after defleet:** keeps claim-relevant history from Avis's era and sees nothing after the sale.
- **Buyer:** starts clean and can't see Avis-era data.
- **Lien with `afterTransfer: drop`:** ends at transfer. In practice payoff comes before the transfer.

---

## 9. Tags and coverage

### 9.1 Time-based coverage

A tag's membership is a set of intervals per vehicle. For delegation *D*, the covered data ranges for vehicle *V* are:

```
coverage(D, V) = (∪ membership intervals of V in D.covers.tag, ending at leftAt or now)
               ∩ D.dataWindow
               ∩ (∪ eras of V where D's root was the controller of record)
               ∩ coverage(parent, V)          // recursive
```

- **Car joins a tag:** access to its data starts at `joinedAt`, never earlier, even if `dataWindow.from` is older.
- **Car leaves a tag:** with `afterRemoval: retainHistory`, past intervals stay readable. Live abilities stop immediately.
- **Result.** dq receives a list of **intervals**, not a single window. A car can be in, out, then back in a tag.

### 9.2 Who can change a tag (tag edits are grants)

Adding a car to a tag widens every delegation that covers the tag, so tag writes get checked like grants:

- **Enforced at check time, so it can't be bypassed.** A membership interval counts toward delegation *D* only if the author the repository witnessed (`committedBy`) held `tag:write` on that tag **and** held authority ⊇ `D.abilities` over that vehicle when the record was committed. A low-privilege tag editor can't enlarge an agreement that an admin signed.
- **Also checked at write time, as UX.** The org host rejects membership writes that would be ignored and names the delegations that are blocking it.

### 9.3 Consented vehicles (dealer case)

When a dealer's authority over a car comes from an **owner-consent** delegation, everything the dealer creates for that car must narrow the consent (§5.2), and:

- **Allowlist.** `redelegate.mode: allowlist` restricts re-sharing to parties the owner saw at consent time, such as "your lender and the manufacturer's warranty program".
- **Transparency.** The org host exposes `listDescendants(rootDelegation)` to the root's `from`. The owner's app shows every party with access to their car through the dealer, including tag-based agreements, resolved per vehicle.
- **Owner revocation.** Tombstoning the consent cuts the dealer and every descendant in one step.

---

## 10. Privacy: control commitments

A public `controllers: [did:dimo:avis]` field would let anyone list Avis's fleet through the identity firehose (`IDENTITY_OPS`) and `/export`. The vehicle DID instead carries a **commitment**:

```json
{
  "id": "did:dimo:veh7xk2m…",
  "rotationKeys": ["did:key:zPerVehicleCustodyKey…"],
  "controlCommitment": "sha256:<base64url(digest)>",
  "verificationMethods": {},
  "services": { "dimo_storage": { "type": "DimoStorageNode", "endpoint": "https://node7.dimo.zone" } }
}
```

The digest is `sha256("dimo-control-commitment-v1" ‖ len32(controllerDID) ‖ controllerDID ‖ u64be(era) ‖ salt)`, with a 32-byte random salt. The current era, its start and any revocation windows are served in the document's `dimoControl` object. The full era history is at `GET /:did/control`.

- **The vehicle DID is not in the hash.** A did:dimo identifier is derived from its genesis operation, and that operation contains the commitment, so the hash can't include the DID it produces. The salt is unique per vehicle, and an opening only counts against the commitment in that vehicle's own operation log. Copying a commitment into another DID gains the copier nothing, because authority flows to the committed controller, not to whoever holds the DID.
- **Controlled DIDs have no verification methods.** The directory rejects any operation that gives a controlled DID a verification method. The vehicle can't sign anything, not even by mistake.
- **Plain updates can't change the commitment.** Changing the controller requires `dimo_transfer`; `dimo_revoke_since` also sets a new commitment, for the *same* controller at era+1.
- **Opening.** `salt` lives in the controller's private `network.dimo.org.vehicleControl` record. The issuer opens the commitment when checking a chain. Coverage proofs (§11.3) include the opening only for the vehicles the grantee covers.
- **Per-vehicle custody keys.** Keys are derived per vehicle inside the controller's Turnkey sub-org, so shared keys don't cluster vehicles.
- **Org key rotation touches no vehicle.** The commitment binds the controller's **DID**, not a key.
- **Transfers.** A transfer is a DID op signed by the old custody key that sets the new rotation key and a new commitment (§8).
- **Remaining leak.** Batch onboarding creates many DID ops at once. The org host staggers publication over a configurable window.
- **NFT-era vehicles.** Holder addresses are already public on-chain. This is unchanged, and migrating to did:dimo removes it.

---

## 11. Credentials and enforcement

### 11.1 Minting (dauth `/exchange`, extended)

1. The caller authenticates with its DID and proves possession of a DPoP key. Org service accounts authenticate as their own DID.
2. The caller requests `{vehicles | tag reference, abilities, audience}`.
3. The issuer finds candidate delegations through the **coverage index** (§11.2), resolves each chain to a root (§5.2, §7), opens commitments, and computes coverage (§9.1). Chains through `to: <org>` accept any member holding a role that narrows it.
4. The issuer checks `clientAllowlist` against the caller's client attestation, if present.
5. The issuer mints a JWT:

```json
{
  "sub": "did:dimo:fordcredit-svc…",
  "aud": ["dq"],
  "cnf": { "jkt": "…" },
  "exp": 1789600000,
  "grants": [
    {
      "subject": "did:dimo:veh7xk2m…",
      "abilities": ["telemetry:read", "location:precise"],
      "windows": [["2026-09-16T00:00:00Z", "2027-02-01T00:00:00Z"], ["2027-03-10T00:00:00Z", null]]
    }
  ],
  "coverageRef": null
}
```

When grants would cover more than 50 vehicles, the token carries `coverageRef: {delegation: at-uri, rev}` instead of listing them. dq resolves it against its local copy of the coverage index. **Deferred (2026-09-21):** v1 has no coverage index and no `coverageRef`; a request names one delegation and one vehicle (`{grant, vehicle, abilities}`, per decision 13), and the token lists one grant per window set for that vehicle. The as-built exchange is in the org host plan §5. A request with no grant asks as the vehicle's controller (decision 30).

**Lifetime:** at most 2 hours for historical abilities, 15 minutes for live abilities. Tokens are always DPoP-bound.

### 11.2 Coverage index

- **Source.** The org host emits every committed delegation, role, membership interval and tombstone to an internal NATS JetStream stream, `ORG_COVERAGE`, with subjects `coverage.<orgSuffix>.<collection>`, alongside `IDENTITY_OPS`.
- **Consumers.** The issuer and dq keep a materialized index: `(vehicle, delegation) → intervals`, `delegation → chain`, `subject org → members`.
- **Revocation lag.** At most stream lag plus the lifetime of tokens already issued. It's bounded by 15 minutes for live abilities and 2 hours for historical ones. Emergency kill: fleet-wide `revokeSince`, plus issuer denylisting of the affected `jkt` values.

### 11.3 Coverage proofs

`getCoverageProof(delegation, vehicle)` returns the chain records, their commits, membership records, the commitment opening and the era log. Anyone who holds it can re-verify coverage offline against the directory and the org's `#dimo_org` key history. This settles disputes like "did you have access to this car on 3/14?"

### 11.4 dq changes

| Where | Change |
|---|---|
| `dq/internal/auth/claim.go` | `DQClaim` is `tokenclaims.Token` with `Grants []Grant` (no `Asset`: no transition, §15; no `CoverageRef` in v1, §11.1) |
| `dq/internal/auth/directives.go` `NewVehicleTokenCheck` | Allow when `subject` ∈ grants, or `subject` is covered through `CoverageRef` in the local index. Otherwise deny, fail closed. |
| Resolvers and fetch RPCs | Clamp the requested time range to the subject's `windows`. Multi-interval results are returned as merged segments and never interpolated across gaps. |
| New | Fleet query taking a coverage reference (one token, many subjects, paged), so partners don't make one request per car |

`AllOfPrivilegeCheck` keeps working on the flattened ability names.

---

## 12. Renters and custody

A renter is not an org member and not a partner. They **bought a service**, and the purchase is what creates the access. So the record to model is the agreement, and grants are derived from its state:

```
booking → paid → picked up → returned → closed
   │        │         │           │
   │        │         │           └── live abilities end; the renter keeps their own window
   │        │         └── custody starts; the data window opens here
   │        └── duty satisfied: grants become mintable
   └── nothing is granted yet
```

Avis writes thousands of bookings a day, so nobody signs a delegation by hand. The booking service holds a **constrained role** and compiles each agreement into grants. This is where ODRL earns its place in the fixed choices: a rental is an ODRL Agreement whose **duties** (payment, return by date, retention) gate the permission.

### 12.1 What a booking compiles to

| Grant | Covers | Abilities | Validity | Data window |
|---|---|---|---|---|
| Custody | the assigned vehicle | `command:unlock`, `command:lock`, fuel or charge | booking window | the booking window until custody events sync, narrowing to custody afterwards (§12.3) |
| History | the same vehicle | `telemetry:read` | the retention term: a duty may state a term, a deadline or both, and when both are stated **the earlier ends it** | custody only, via `narrowToCustody` |
| Insurer (if a waiver was bought) | the same vehicle | `events:read` | the term carried on the purchased line item | the customer's custody window as a bound — **not** `narrowToCustody`, which follows the recipient's own custody, and the insurer never held the car |
| Roadside (while an incident is open) | the same vehicle | `location:precise` | the incident | the incident |

Custody and history are **separate grants on purpose**. Custody dies at return; the renter keeps the window they actually drove, and that history grant is separately revocable. It is the same `retainHistory` machinery the insurer uses after a defleet, pointed at an individual.

### 12.2 Custody suspends the operator's commands

During custody the renter holds `command:*` **exclusively**. The operator cannot lock or immobilise a car somebody else is driving; an operator immobilising a moving car is a safety event, not a permissions question. A `recovery` grant may still act, and the issuer logs every such use.

Two overlapping holds do not deadlock: the **newer one is in force**, so a stale hold from a device that never synced its return is superseded rather than locking the next renter out, while the operator stays blocked by both. A suspended grant answers `ErrExclusiveHold` naming the abilities, never "not covered" — the operator learns that somebody is driving their car, which is a different fact from never having been granted it. A caller asking for an ability the grant never carried still gets "not covered".

Exclusivity is permitted by the basis (`redelegate.exclusive`) and claimed by the time-bounded child, so a host permits it once at listing and only loses control for the booking window. It applies to the record being authorized, never to links inside its own chain. A child may set `redelegate.exclusive` only where its basis did, and a role must `allowExclusive` to issue it, so the permission never appears below where the controller granted it. A hold suspends others only once its own chain evaluates: a claim is not a hold.

### 12.3 Activation order

Grants activate on the **booking** window; the custody records **narrow** the data window afterwards, through `narrowToCustody` on the record and custody periods supplied by the resolver. The reverse is circular: the renter picks up the car by unlocking it, so waiting for a custody record written at pickup means nobody can open the door in a garage with no signal. The car's device signs custody events offline and syncs later.

### 12.4 Peer to peer

`host (consumer) → platform (operator) → renter (consumer)` is the same chain, with an allowlist at the listing bounding who the platform may book. No new concepts.

### 12.5 Operational rules the implementation settled

- **Unattended issuing needs its own policy profile.** No operator putting two admins behind every unlock grant can write thousands of bookings a day. The approval belongs one level up and happens once: a pair of admins signs the fleet delegation that permits exclusive redelegation, and everything compiled beneath it is bounded by that basis, by the booking role's constraints, and re-checked at evaluation. `agreement.CommitPolicy()` is that profile.
- **A booking cannot be unbounded.** With neither an end to the booking window nor a return duty, compilation fails rather than issuing a live grant with no end. This is what stops a stale exclusive hold — a device that never synced its return — from locking a renter out forever.
- **A device that never syncs cannot extend a window.** With no custody event and a returned booking, the fallback is the operator's own due-back time, never later.
- **Grant keys are stable** across recompilations, so a booking service upserts rather than accumulating a record per state change. The shape is `bookingID:serviceCode:offerName[:incidentID]`, each part drawn from `[A-Za-z0-9._-]`, so the key is a valid record key and the join is injective; an identifier outside that alphabet is refused (`ErrBadKey`) rather than escaped. The service code is part of it because two line items sharing an offer name would otherwise collide into one key.

### 12.5.1 Cancellation is a return, not an erasure

Cancelling **before pickup** compiles to nothing, history included: there is no custody to cover and no drive to keep.

Cancelling **mid-rental** ends custody at the cancellation — the commands stop, even if the device never syncs a return — and the customer keeps the history of the days they actually drove. That record is about them, and it is the evidence both sides reach for in the damage or billing dispute that usually follows.

### 12.6 What stays outside

Identity documents. KYC lives with the operator; the agreement references their verification. DIMO holds none of it.

## 13. Worked examples

### 13.1 Avis: 10,000 cars

```
Avis org (controller of record for 10k cars; commitments on each vehicle DID)
 ├─ role → alice        delegation:create + tag:write over fl-fleet
 ├─ role → avis-backend live abilities over all cars   (renter proxy, §12)
 ├─ tags: fl-fleet, ford-pro-enrolled, financed-fc      (membership intervals)
 ├─ delegation → Ford Credit   covers financed-fc, location+health, revocableBy: to, afterTransfer: drop
 ├─ delegation → Insurer       covers fl-fleet, telemetry+events, retainHistory
 ├─ delegation → Ford Pro      covers ford-pro-enrolled, telemetry + command:lock/unlock
 │     └─ Ford Pro → integrator  inherit, telemetry:read only   (redelegate attenuated, depth 1)
 └─ delegation → Franchisee org  covers tag tx-franchise, operator abilities
       └─ Franchisee roles → its staff
```

| Action | Work |
|---|---|
| Onboard 10k cars | One batch: set commitments (native) or register the holder address (NFT-era) |
| Grant three partners | 3 delegations |
| Add a car | 1–3 membership records |
| Car defleeted | 1 `transfer` op. Insurer keeps its Avis-era history, Ford Pro loses access, buyer starts clean. |
| Drop Ford Pro | Tombstone 1 delegation. The integrator's delegation below it dies with it. |
| Alice leaves | Tombstone 1 role. Her agreements survive. |

### 13.2 Dealer group

```
Owner (person) ──consent──▶ Dealer group org
                           abilities: telemetry:read, health:read, documents:read
                           redelegate: allowlist [Rooftop orgs, Ford warranty program]
  Dealer group ─▶ Rooftop org (inherit, redelegate none) ─▶ technician roles
  Dealer group ─▶ Ford warranty program (inherit, health:read only)
```

- The owner's app lists every party below the consent (§9.3).
- A marketing vendor can't be added because it isn't on the allowlist.
- The owner revokes once and every descendant loses access.

### 13.3 Consumer

Owner → insurance app, `covers: {vehicle}`. This is the same record type and the same issuer path as fleets.

---

## 14. Hole → fix traceability

| # | Hole | Fix |
|---|---|---|
| 1 | Member departure invalidates grants they signed | Validity rests on org commits (§6.2–6.3); `createdBy` is audit only |
| 2 | Tag removal erases rightful history, and joining exposes prior history | Membership intervals plus time-based coverage (§9.1) |
| 3 | Sale epoch bump erases pre-sale access | `transfer` era keeps own-era history; `revokeSince` for compromise (§8) |
| 4 | Public `controllers` list exposes the fleet | Control commitments, per-vehicle custody keys, staggered ops (§10) |
| 5 | Flat controllers conflate owner, operator and lienholder | Root of control plus typed child delegations; `revocableBy: to` for liens (§7) |
| 6 | Dealer shares beyond what the owner consented to | Consent as a basis, allowlist redelegation, owner-visible descendants (§9.3) |
| 7 | Editing a tag is an unchecked grant | Tag writes count only with authority ⊇ the delegation's abilities (§9.2) |
| 8 | Partners can't delegate to vendors | `redelegate` modes, org-member use of delegations, depth limit (§5, §5.2) |
| 9 | dq checks one car at a time | `coverageRef`, local coverage index, fleet query, multi-interval windows (§11) |
| 10 | Renter backend key could unlock any car | Renters outside protocol v1; per-booking policy keys later (§12) |
| 11 | Partners can't prove what they were granted | Coverage proofs from the signed repository (§11.3) |
| — | Org key compromise affects every car | Turnkey policy approval for large, live or irrevocable delegations; root keys don't sign routine writes (§7) |
| — | Vehicle key signs grants ("as the vehicle") | Vehicle DID has no grant-signing key; the controller signs as itself (§4) |

---

## 15. Migration and compatibility

**None** (decided 2026-09-22, §19). The did:erc721 world, on-chain SACDs, the holder registry, the dual v1/v2 privilege names, the 90-day SACD window and the `dimo.sacd.v3` document are all dropped. A single-car grant, consumer or fleet, is a delegation with `covers: {vehicle}` (§7), evaluated by the same issuer path. The developer license is a DIMO → org delegation with `abilities: [license:developer]`.

## 16. Decisions (2026-09-16)

| # | Question | Decision |
|---|---|---|
| 1 | Irrevocable liens | **Fleet only.** `revocableBy: "to"` is allowed only when the issuer is an attested operator (`Party.Operator`, §7), and needs policy approval. Consumer loans use `revocableBy: either`, and the org host notifies the lender on revocation. Enforced in `delegation.CheckCommit`; the operator rule is checked again at evaluation (`ErrLienNotAllowed`), the approval only at commit in v1 (decision 27). |
| 2 | Commitment vs. plain pointer | **Hash commitment** (§10), with per-vehicle custody keys. |
| 3 | Grantee countersignature | **Optional**, required only when `terms` is set. Enforced by the org host, not the evaluator. Not implemented yet. |
| 4 | Blast-radius threshold | **500 vehicles** by default (`delegation.DefaultApprovalThreshold`), overridable per org tier. Also applies when tag growth pushes an existing delegation past it (`CheckMembershipGrowth`). |
| 5 | Renters in protocol | **In**, as agreements that compile to grants (§12). |
| 7 | Policy keyed off entity type | **Replaced** by attested party attributes plus jurisdictional policy profiles. |
| 8 | Self-issued grants | **Refused** without a second approval from someone holding the same authority. |
| 9 | Operator commands during custody | **Suspended** by exclusivity, with a logged recovery path. The mechanism is built and opt-in per grant; whether Avis's contracts permit it is a legal question still open. |
| 10 | Where approval sits for unattended issuing | **Once, at the fleet level.** Two admins sign the fleet delegation that permits exclusive re-delegation; everything the booking service compiles below it is bounded by that basis and by its role constraints, and re-checked at evaluation. Per-grant approval for commands stays available as a policy profile for small fleets and pilots. |
| 11 | Cancellation after pickup | **Custody ends, history survives** for the days actually driven (§12.5.1). |
| 12 | Permissions format | **ODRL with the DIMO profile is the wire format** (§5); the record is its parsed form. |
| 13 | One person, two hats | **The caller names the capacity.** Authorization takes the grant being exercised, so the answer to "under what authority?" is the chain in the token, recorded at issue. The issuer does not infer a capacity the caller did not claim. |
| 14 | Device writes | **Live, checked at request time.** Approval and custody key off actuation instead. |
| 15 | Revocation on the SACD path | **Ends the era** (§8). A window cannot bind a timestamp the signer chooses. |
| 16 | Policy defaults | **Every permissive field is off by default** (`AllowUnapprovedActuation`, `AllowIrrevocableFromNonOperator`). A partial literal cannot switch a protection off by saying nothing. |
| 6 | Order vs. the Bluesky parity plan | **This first.** The parity plan is amended to carry `controlCommitment`, `effectiveAt` and `revokeSince` in place of `sacdEpoch`. |

## 17. Implementation status

**Done in `did-directory` (branch `feat/orgs-fleets-delegation`):**

| Area | Where |
|---|---|
| Commitments, openings, eras, revocation windows | `pkg/control` |
| `controlCommitment`, `dimo_transfer`, `dimo_revoke_since`; controlled DIDs can't have verification methods; ±5 min clock-skew bound; no ops after a tombstone | `internal/did/operation.go` (`ValidateTransition`, `ResolveControlState`) |
| `dimoControl` in the DID document; `GET /:did/control`; `sacdEpoch` removed | `internal/did/document.go`, `internal/handlers/resolve.go`, `internal/server/server.go`, `pkg/client.Control` |
| CLI: `create --controller` (custody key only), `transfer`, `revoke-since`; `revoke-all` removed | `cmd/dimocli` |
| Delegation records, narrowing rules, time-based coverage, roots of control with opening checks, tag-author authority, member-departure semantics, liens, allowlist/attenuated redelegation, client allowlists, org-member use, commit policy | `pkg/delegation` |
| Existing bug fixed: `MemoryStore` kept Fiber param strings that pointed into a reused request buffer, which corrupted stored DIDs | `internal/store/postgres.go` |

**Also built (2026-09-17, same branch):** party attributes in place of entity-type checks, policy profiles, the self-dealing rule, exclusivity with a recovery path, role constraints and custody narrowing — all in `pkg/delegation`. Plus `pkg/agreement`: the ODRL-shaped agreement record, a per-operator service catalog, and a pure compiler from an agreement and a time to the grants it produces, with duties gating the output.

**Reviewed 2026-09-17** at max effort, 15 findings; the nine correctness and security ones are fixed on the branch, with the rest triaged in the PR. The pattern worth remembering: authority kept being read from fields the signer controls — `createdBy`, `effectiveAt`, `grantee` — while the delegation path already had the right answer in the repository's witnessed `committedAt`. `internal/auth` and `internal/handlers` went from no tests to roughly 80%.

**Removed 2026-09-22 (§19):** `pkg/sacd`, `internal/auth`, `cmd/auth-service`, the `sacd-grant`, `sacd-verify` and `auth` CLI commands, and `scripts/demo.sh`. They were the single-car bearer-document path and the only runnable end-to-end flow; nothing exercises `pkg/delegation` end to end until the org host exists.

**Fixed 2026-09-22:** compiled grant keys were joined with `/`, which `ParseURI` cannot address. Keys are now `:`-joined from a restricted alphabet, and `delegation.ValidateRKey` enforces the atproto record-key rules for anyone minting a key.

**Built 2026-09-22 (org host plan §6, steps 1–8):** the org host (`cmd/org-host`: signed commit logs, write-time checks, two-person approval, `/authorize`, coverage proofs, descendants), the booking SDK, dauth's DID sign-in and `/exchange` (the evaluator runs in the host, decision 21), dq's grants, windows and DPoP, and `scripts/demo.sh` running all of it. Still not built: the `ORG_COVERAGE` stream and coverage index, `coverageRef` and the dq fleet query (deferred 2026-09-21), countersignatures and lender notification.

**Built 2026-09-24:** ODRL at the wire (§5, decision 28). Until then `pkg/odrl` existed but nothing called it, and records crossed the wire as `delegation.Record` JSON. The codec had also fallen behind the record — `maxDataReach` and `policy` in role constraints were dropped on the way through, and times were truncated to the second — so a test now fails when a record field has no place in the policy.

**Reviewed 2026-09-23** across the three repositories, with the fixes on the same branches: exclusive holds and custody from repositories that had no authority over the car; a `PUT` that replaced a record without the authority to revoke it; `redelegate.exclusive` passing down without the basis allowing it; roles, memberships and openings read at their current version rather than the one in force when authority was exercised; identity tokens accepted for any audience and client assertions that were bearer identity tokens; dq reads that returned data outside the token's windows; checks that did not hold under concurrent writes; and revocation windows that did not reach the controller's earlier eras. The pattern is the one of 2026-09-17 in a new place: authority read from state the reader had not established was the right state — another repository's claims, a caller's header, the record's current version, the time before a write lands.

## 18. Open, after the renter analysis

1. **Pairwise identifiers.** One global DID presented to every operator is a cross-company tracking key, and the directory is public. Portability and unlinkability both matter, so the likely answer is a root identity issuing per-relationship identifiers, with linkage proven selectively by the person when it benefits them. This changes §4 and is painful to retrofit once people hold DIDs, so it wants deciding early.
2. **Anti-sybil under pseudonymity.** If a renter can mint a fresh identifier per operator, a banned renter mints one too. A uniqueness attestation — one verified-person credential per operator, deterministic for that person, unlinkable across operators — is the standard answer. DIMO issues none of it.
3. ~~Capacity-scoped tokens~~ — **decided** (§16.13): the caller names the grant they are exercising, and the token records that chain. One request, one capacity, one audit answer.
4. **Data residency.** A German car, rented in France, operated from the US. The storage node's region is in the DID document and nothing checks it.
5. **Custody suspension in contract.** Rental agreements today assert the operator's right to immobilise. The engine can express either answer; legal picks.

## 19. Decisions (2026-09-22)

| # | Question | Decision |
|---|---|---|
| 17 | Backwards compatibility | **None.** §15 rewritten. Nothing in the new stack reads a SACD, an NFT holder or a v1 privilege number. |
| 18 | `dimo.sacd.v3` and the demo auth service | **Dropped.** A single-car grant is a delegation with `covers: {vehicle}`. The issuer is dauth `/exchange`; did-directory ships no token minting. |
| 19 | Ford Pro in the reference diagram | **Ford Pro is the data host**: the vehicle's `dimo_storage` service entry, set by the controller through a DID update. Reads of that data are still authorized by delegations; where the bytes sit grants nothing. |
| 20 | Org host location | A separate binary in this repo for now (`cmd/org-host`), with its own database. Confirmed 2026-09-21 as a separate service; repo placement is a convenience until a second consumer of `pkg/delegation` exists. |
| 21 | Who runs the evaluator | **The org host**, behind `POST /authorize`; dauth authenticates and mints. Openings never leave the host except inside a coverage proof. |
| 22 | Member authentication to the org host | **dauth identity token**, `sub` = member DID. |
| 23 | Commit signing in v1 | **Host-held org key** behind a `Signer` interface; Turnkey later. |
| 24 | Second approval | **A record fact** (`approvedBy`), collected in v1 by a second member approving a pending write. Not a vendor feature. |
| 25 | Party attributes | **DIMO-administered table** per DID for v1. |
| 26 | Agreement compilation | **Client side, in the booking service** (as §12 says). The host never learns what a booking is; `pkg/agreement` is an SDK. |
| 28 | ODRL at the wire (2026-09-24) | **Decision 12 stands and is built.** Delegations and roles cross the wire and sit in repositories as ODRL policies, normalized by the codec, with `uid` set to the record's at-uri. JSON, not JSON-LD: canonical JSON signing, no graph canonicalization, and `https://schema.dimo.zone/odrl/v1` need not resolve. The agreement a booking service holds stays its own format (decision 26); what it compiles to is ODRL. |
| 27 | Blast-radius approvals at evaluation (2026-09-23) | **Commit time only, for v1.** The host checks the second approval for large, actuating or irrevocable delegations when they are committed, under the authoring role's policy; the evaluator does not check it again. Rechecking would need the evaluator to know every role's commit policy. What this relies on is that nothing reaches a repository except through the host's write checks, which since 2026-09-23 include updates (a `PUT` must pass the tombstone check) and run under the org's write lock. |
| 29 | Scoped reads (2026-10-02) | **`org:read` reads within the role's own scope**, the same `covers` a write is held to; there is no separate read scope. Every member reads the records they wrote, `org:admin` reads everything, and only `org:admin` reads the control openings and the log. No other ability implies reading. A record out of the caller's reach answers 404. See `docs/2026-10-01-identity-explorer.md`, gap 2. |
| 30 | The implicit root at the token path (2026-10-05) | **An exchange with no grant asks as the vehicle's controller.** §7 made the controller's root implicit, but every token named a delegation, and a delegation cannot have `from == to`, so no controller or member could read its own cars. Now `/exchange` and `/authorize` take no grant/`uri` to mean "as controller": the host tries the caller and each org that gave it a role, proves control from that org's opening in each era (`Evaluator.AuthorizeController`, through the same `root` a written root uses), and requires a member's live role to cover the car with every ability asked for. History reaches every era the controller held, as `afterTransfer: retainHistory` would; live abilities only the current era, suspended by custody holds; admin abilities never. The token's chain is the opening's URI. |

**Open, added 2026-09-22.** `revokeSince` ends the era (§8) because a bearer SACD had no witnessed commit time. With SACDs gone every grant has one, so a compromise window alone could suffice. Ending the era still invalidates the old opening, which is a real property, so the mechanism stays until someone needs the simpler one.

